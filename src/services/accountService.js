"use strict";

const {
  hashPassword,
  hashToken,
  passwordNeedsRehash,
  randomId,
  randomToken,
  verifyPassword
} = require("../lib/crypto");
const { decodeJson, encodeJson } = require("../lib/lists");
const { appError, invalidRequest } = require("../lib/errors");

// Local accounts.
//
// This is what makes the issuer standalone: it owns registration, login,
// password reset, and email verification, so a deployment needs no upstream site
// to authenticate anyone. An external identity provider (see
// externalIdentityService) is an addition to this, never a prerequisite.
//
// Two rules run through the whole file:
//
//   * A response never reveals whether an email address is registered.
//     Registration, login, and password reset all behave identically for a known
//     and an unknown address, because an authorization server that answers that
//     question is an account-enumeration oracle.
//
//   * `user.id` is the OIDC `sub` claim. It is a random UUID, assigned once and
//     never reused, so it stays stable across an email or username change and
//     leaks nothing about the account. OIDC Core section 2 requires `sub` to be
//     locally unique and never reassigned.

const EMAIL_MAX_LENGTH = 254; // RFC 5321 section 4.5.3.1.3
const USERNAME_PATTERN = /^[a-zA-Z0-9](?:[a-zA-Z0-9._-]{1,30}[a-zA-Z0-9])$/;
const PASSWORD_MAX_LENGTH = 1024; // scrypt cost is linear in input; cap the work

const STATUS = { PENDING: "PENDING", ACTIVE: "ACTIVE", DISABLED: "DISABLED" };
const ROLE = { USER: "USER", ADMIN: "ADMIN" };

class AccountStateChanged extends Error {}
class PasswordChangedConcurrently extends Error {}
class ResetTokenChangedConcurrently extends Error {}

/**
 * Normalizes an email for storage and comparison.
 *
 * Only the case of the address is folded. The local part is technically
 * case-sensitive per RFC 5321, but every mail provider in practice treats it
 * case-insensitively, and treating `A@x.com` and `a@x.com` as two accounts is a
 * worse failure than the theoretical incompatibility. No other normalization is
 * applied: stripping dots or `+tag` suffixes, as some providers do internally,
 * would merge addresses their owners consider distinct.
 */
function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function assertValidEmail(value) {
  const email = normalizeEmail(value);
  if (!email) throw invalidRequest("An email address is required");
  if (email.length > EMAIL_MAX_LENGTH) throw invalidRequest("That email address is too long");
  // Deliberately permissive. A stricter regexp rejects valid addresses, and the
  // authoritative test of an address is whether mail to it arrives.
  if (!/^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/.test(email)) {
    throw invalidRequest("That does not look like an email address");
  }
  return email;
}

function assertValidUsername(value) {
  const username = String(value || "").trim();
  if (!username) return null;
  if (!USERNAME_PATTERN.test(username)) {
    throw invalidRequest(
      "A username must be 3 to 32 characters using letters, numbers, dot, underscore, or hyphen, and must start and end with a letter or number"
    );
  }
  return username;
}

/**
 * Password policy: a length floor and nothing else.
 *
 * Current NIST 800-63B guidance is to require length, drop composition rules,
 * and screen against known-breached values. Composition rules push users toward
 * predictable substitutions, so they are not implemented.
 */
function assertValidPassword(password, { minLength }) {
  const raw = String(password ?? "");
  if (raw.length < minLength) {
    throw invalidRequest(`A password must be at least ${minLength} characters`);
  }
  if (raw.length > PASSWORD_MAX_LENGTH) {
    throw invalidRequest("That password is too long");
  }
  return raw;
}

function createAccountService({ prisma, config, mailer, auditLog, now = () => new Date() } = {}) {
  const minPasswordLength = config?.accounts?.minPasswordLength ?? 12;
  const requireEmailVerification = Boolean(config?.accounts?.requireEmailVerification);
  const registrationEnabled = config?.accounts?.registrationEnabled !== false;
  const localLoginEnabled = config?.accounts?.localLoginEnabled !== false;
  const firstUserIsAdmin = config?.accounts?.firstUserIsAdmin !== false;

  // Prisma compiles `contains` to LIKE, and the two supported databases do not
  // agree on what that means: SQLite's LIKE folds case for ASCII, PostgreSQL's
  // does not. Left alone, an administrator searching "smith" finds "Alice Smith"
  // on SQLite and nothing on PostgreSQL — the same query, two answers, and only
  // the SQLite one is covered by the suite.
  //
  // `mode: "insensitive"` is how PostgreSQL is told to fold case, and it is added
  // only there: Prisma accepts the field on PostgreSQL alone and rejects it as an
  // unknown argument elsewhere, so sending it unconditionally would turn a wrong
  // result into a failed query. SQLite needs nothing, because its LIKE already
  // behaves the way this spreads to.
  const caseInsensitive =
    config?.database?.provider === "postgresql" ? { mode: "insensitive" } : {};

  /** Shape handed to the rest of the app. `attributes` is what custom scopes read. */
  function toAccount(record) {
    if (!record) return null;
    return {
      id: record.id,
      email: record.email,
      emailVerified: Boolean(record.emailVerifiedAt),
      emailVerifiedAt: record.emailVerifiedAt || null,
      username: record.username || null,
      name: record.name || null,
      picture: record.picture || null,
      role: record.role,
      status: record.status,
      hasPassword: Boolean(record.passwordHash),
      attributes: decodeJson(record.attributesJson, {}) || {},
      lastLoginAt: record.lastLoginAt || null,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt
    };
  }

  async function findById(id) {
    if (!id) return null;
    return toAccount(await prisma.user.findUnique({ where: { id: String(id) } }));
  }

  async function findByEmail(email) {
    const normalized = normalizeEmail(email);
    if (!normalized) return null;
    return toAccount(await prisma.user.findUnique({ where: { email: normalized } }));
  }

  /** Accepts an email address or a username, so a login form needs one field. */
  async function findByIdentifier(identifier) {
    const raw = String(identifier || "").trim();
    if (!raw) return null;
    if (raw.includes("@")) return findByEmail(raw);
    return toAccount(await prisma.user.findUnique({ where: { username: raw } }));
  }

  /**
   * Creates a local account.
   *
   * The first account becomes an administrator when configured, so a fresh
   * install has an admin without a seeding step or a default password. That is a
   * genuine race on a public deployment: two simultaneous first registrations
   * could both see an empty table. It is a one-time window on an install nobody
   * else knows about yet, and the alternative — shipping a default admin
   * credential — is worse.
   */
  async function register({ email, password, username, name, ipAddress, userAgent } = {}) {
    if (!registrationEnabled || !localLoginEnabled) {
      throw appError("Registration is closed on this server", 403);
    }
    const normalizedEmail = assertValidEmail(email);
    const normalizedUsername = assertValidUsername(username);
    const rawPassword = assertValidPassword(password, { minLength: minPasswordLength });

    const passwordHash = await hashPassword(rawPassword);
    const isFirstUser = firstUserIsAdmin && (await prisma.user.count()) === 0;
    const timestamp = now();

    let record;
    try {
      record = await prisma.user.create({
        data: {
          id: randomId(),
          email: normalizedEmail,
          username: normalizedUsername,
          passwordHash,
          name: String(name || "").trim() || null,
          role: isFirstUser ? ROLE.ADMIN : ROLE.USER,
          // The first user is active immediately even when verification is
          // required: locking the only administrator out of a fresh install
          // behind an email that may not be deliverable yet is a worse failure
          // than letting the installer in.
          status: requireEmailVerification && !isFirstUser ? STATUS.PENDING : STATUS.ACTIVE,
          emailVerifiedAt: isFirstUser && requireEmailVerification ? timestamp : null
        }
      });
    } catch (error) {
      // P2002 is Prisma's unique-constraint violation.
      if (error?.code === "P2002") {
        const target = String(error?.meta?.target || "");
        if (target.includes("username")) {
          throw invalidRequest("That username is taken");
        }
        // The address is already registered. Saying so would confirm an account
        // exists, so the caller is told to check their mail — the same thing a
        // successful registration says.
        await sendExistingAccountNotice(normalizedEmail);
        return { account: null, duplicateEmail: true, verificationRequired: requireEmailVerification };
      }
      throw error;
    }

    const account = toAccount(record);
    await auditLog?.record({
      action: "account.register",
      actorUserId: account.id,
      targetType: "user",
      targetId: account.id,
      metadata: { firstUser: isFirstUser, role: account.role },
      ipAddress,
      userAgent
    });

    // A message goes out on every registration, not only when verification is
    // mandatory.
    //
    // The answer to a new address and to one already taken is deliberately
    // identical, and the page it renders tells the caller to check their mail.
    // With verification optional — the default — a new account used to send
    // nothing at all, so "did anything actually arrive?" answered the question
    // that identical wording exists to close, and the page was simply false.
    // The link is worth sending either way: opening it records emailVerifiedAt.
    //
    // Skipped only for an account that is already verified, which on a fresh
    // install is the first user.
    try {
      if (!account.emailVerified) await issueEmailVerification(account);
    } catch {
      // Swallowed for the same reason the duplicate branch swallows its own
      // notice: a mail failure that changed the response would be the
      // enumeration oracle this is written to avoid. An account that never got
      // its link can ask for another one.
    }

    return {
      account,
      duplicateEmail: false,
      // Whether the user must confirm before the account is usable — not
      // whether a message was sent, which is now always.
      verificationRequired: requireEmailVerification && account.status === STATUS.PENDING
    };
  }

  /**
   * Told an address is already registered, we still send mail — to the existing
   * account holder, telling them someone tried to register their address. It
   * keeps the registration response identical either way and is useful to the
   * person who actually owns the address.
   */
  async function sendExistingAccountNotice(email) {
    if (!mailer) return;
    try {
      await mailer.sendExistingAccountNotice({ email });
    } catch {
      // A mail failure must not change the response, or the difference becomes
      // the enumeration oracle this was written to avoid.
    }
  }

  // --- Login ---------------------------------------------------------------

  /**
   * Verifies a credential.
   *
   * Every failure returns the same shape with a distinct `reason` for the audit
   * log, and the caller shows one message. An unknown identifier still runs a
   * scrypt verification against a dummy hash, so a request for a non-existent
   * account costs the same time as a wrong password; without it, response
   * latency alone reveals which addresses are registered.
   */
  async function authenticate({ identifier, password, ipAddress, userAgent } = {}) {
    if (!localLoginEnabled) {
      await auditLog?.record({
        action: "account.login.refused",
        targetType: "user",
        metadata: { reason: "local_login_disabled" },
        ipAddress,
        userAgent
      });
      return { ok: false, reason: "local_login_disabled", account: null };
    }

    const record = await findRecordByIdentifier(identifier);

    if (!record || !record.passwordHash) {
      await burnPasswordTime(password);
      await auditLog?.record({
        action: "account.login.failed",
        targetType: "user",
        targetId: record?.id || null,
        metadata: { reason: record ? "no_password" : "unknown_identifier" },
        ipAddress,
        userAgent
      });
      return { ok: false, reason: record ? "no_password" : "unknown_identifier", account: null };
    }

    const valid = await verifyPassword(password, record.passwordHash);
    if (!valid) {
      await auditLog?.record({
        action: "account.login.failed",
        targetUserId: record.id,
        targetType: "user",
        targetId: record.id,
        metadata: { reason: "bad_password" },
        ipAddress,
        userAgent
      });
      return { ok: false, reason: "bad_password", account: null };
    }

    if (record.status === STATUS.DISABLED) {
      return { ok: false, reason: "disabled", account: toAccount(record) };
    }
    if (record.status === STATUS.PENDING && requireEmailVerification) {
      return { ok: false, reason: "unverified", account: toAccount(record) };
    }

    // Upgrade the stored hash opportunistically: the plaintext is in hand
    // exactly once, at a successful login, so this is the only moment a
    // parameter change can be applied without asking the user to reset.
    const updates = { lastLoginAt: now() };
    if (passwordNeedsRehash(record.passwordHash)) {
      updates.passwordHash = await hashPassword(String(password));
    }
    if (record.status === STATUS.PENDING) updates.status = STATUS.ACTIVE;

    const updated = await prisma.user.update({ where: { id: record.id }, data: updates });
    await auditLog?.record({
      action: "account.login",
      actorUserId: record.id,
      targetType: "user",
      targetId: record.id,
      metadata: { rehashed: Boolean(updates.passwordHash) },
      ipAddress,
      userAgent
    });
    return { ok: true, reason: null, account: toAccount(updated) };
  }

  async function findRecordByIdentifier(identifier) {
    const raw = String(identifier || "").trim();
    if (!raw) return null;
    if (raw.includes("@")) {
      return prisma.user.findUnique({ where: { email: normalizeEmail(raw) } });
    }
    return prisma.user.findUnique({ where: { username: raw } });
  }

  // A fixed hash of a value nobody can supply. Verifying against it costs the
  // same as a real check, which is the point.
  let dummyHashPromise = null;
  async function burnPasswordTime(password) {
    if (!dummyHashPromise) {
      dummyHashPromise = hashPassword(`unused-${randomToken(16)}`).catch((error) => {
        // A full scrypt queue is temporary. Caching its rejected promise would
        // make every later unknown-account attempt skip the KDF permanently,
        // while real accounts resume paying the KDF cost, recreating the timing
        // oracle this dummy hash exists to close.
        dummyHashPromise = null;
        throw error;
      });
    }
    const hash = await dummyHashPromise;
    return verifyPassword(String(password ?? "x"), hash);
  }

  // --- Email verification --------------------------------------------------

  /**
   * Issues a verification link. Any outstanding token is invalidated first, so a
   * link forwarded or leaked earlier stops working as soon as a new one is asked
   * for.
   */
  async function issueEmailVerification(account, { ttlSeconds = 24 * 60 * 60 } = {}) {
    if (!account?.id) throw invalidRequest("An account is required");
    const token = randomToken();
    const expiresAt = new Date(now().getTime() + ttlSeconds * 1000);

    await prisma.emailVerificationToken.updateMany({
      where: { userId: account.id, usedAt: null },
      data: { usedAt: now() }
    });
    await prisma.emailVerificationToken.create({
      data: {
        id: randomId(),
        userId: account.id,
        tokenHash: hashToken(token),
        expiresAt
      }
    });

    await mailer?.sendEmailVerification({
      email: account.email,
      name: account.name,
      token,
      expiresAt
    });
    return { expiresAt };
  }

  /** Consumes a verification token. Single-use, and expiry is checked at use. */
  async function verifyEmail(token, { ipAddress, userAgent } = {}) {
    const raw = String(token || "").trim();
    if (!raw) return { ok: false, reason: "missing_token", account: null };

    const record = await prisma.emailVerificationToken.findUnique({
      where: { tokenHash: hashToken(raw) }
    });
    if (!record || record.usedAt) return { ok: false, reason: "invalid_token", account: null };
    if (record.expiresAt <= now()) return { ok: false, reason: "expired_token", account: null };

    // Same rule as resetPassword, and the window here is longer: a verification
    // link lives 24 hours, so "issued while active, opened after an
    // administrator disabled the account" is not a narrow race.
    const holder = await prisma.user.findUnique({ where: { id: record.userId } });
    if (!holder || holder.status === STATUS.DISABLED) {
      return { ok: false, reason: "disabled", account: null };
    }

    const timestamp = now();
    // Marking the token used is scoped to `usedAt: null` so two concurrent
    // requests cannot both consume it.
    const claimed = await prisma.emailVerificationToken.updateMany({
      where: { id: record.id, usedAt: null },
      data: { usedAt: timestamp }
    });
    if (!claimed.count) return { ok: false, reason: "invalid_token", account: null };

    const updated = await prisma.user.update({
      where: { id: record.userId },
      data: {
        emailVerifiedAt: timestamp,
        // Confirming an address promotes a PENDING account. It is not a reason
        // to move one out of any other state.
        status: holder.status === STATUS.PENDING ? STATUS.ACTIVE : holder.status
      }
    });
    await auditLog?.record({
      action: "account.email.verified",
      actorUserId: record.userId,
      targetType: "user",
      targetId: record.userId,
      ipAddress,
      userAgent
    });
    return { ok: true, reason: null, account: toAccount(updated) };
  }

  // --- Password reset ------------------------------------------------------

  /**
   * Starts a reset. Returns the same result whether or not the address is
   * registered; only a real account gets mail.
   */
  async function requestPasswordReset({ email, ttlSeconds = 60 * 60, ipAddress, userAgent } = {}) {
    if (!localLoginEnabled) return { sent: false };

    const normalized = normalizeEmail(email);
    const record = normalized ? await prisma.user.findUnique({ where: { email: normalized } }) : null;

    if (!record || record.status === STATUS.DISABLED) {
      return { sent: false };
    }

    const token = randomToken();
    const expiresAt = new Date(now().getTime() + ttlSeconds * 1000);
    await prisma.passwordResetToken.updateMany({
      where: { userId: record.id, usedAt: null },
      data: { usedAt: now() }
    });
    await prisma.passwordResetToken.create({
      data: {
        id: randomId(),
        userId: record.id,
        tokenHash: hashToken(token),
        expiresAt
      }
    });

    await mailer?.sendPasswordReset({
      email: record.email,
      name: record.name,
      token,
      expiresAt
    });
    await auditLog?.record({
      action: "account.password.reset_requested",
      targetUserId: record.id,
      targetType: "user",
      targetId: record.id,
      ipAddress,
      userAgent
    });
    return { sent: true };
  }

  /**
   * Completes a reset.
   *
   * A password change revokes every refresh token and every session for the
   * account. Someone resetting a password is often doing it because they believe
   * it was compromised, and leaving a stolen refresh token alive would make the
   * reset cosmetic. Returns the account so the caller can also drop the
   * requester's own session and force a fresh login.
   */
  async function resetPassword({ token, password, ipAddress, userAgent } = {}) {
    if (!localLoginEnabled) return { ok: false, reason: "local_login_disabled", account: null };

    const raw = String(token || "").trim();
    if (!raw) return { ok: false, reason: "missing_token", account: null };

    const record = await prisma.passwordResetToken.findUnique({
      where: { tokenHash: hashToken(raw) }
    });
    if (!record || record.usedAt) return { ok: false, reason: "invalid_token", account: null };
    if (record.expiresAt <= now()) return { ok: false, reason: "expired_token", account: null };

    // Checked before the token is spent, so a refusal does not also consume the
    // link. An administrator disabling an account has to outrank a reset that
    // was issued while it was still active: the write below used to set
    // `status: ACTIVE` unconditionally, so a disabled user could re-enable
    // themselves by opening a link from before — and submitResetPassword signs
    // them in immediately afterwards.
    const holder = await prisma.user.findUnique({ where: { id: record.userId } });
    if (!holder || holder.status === STATUS.DISABLED) {
      return { ok: false, reason: "disabled", account: null };
    }

    const newPassword = assertValidPassword(password, { minLength: minPasswordLength });
    const passwordHash = await hashPassword(newPassword);
    const timestamp = now();

    let updated;
    try {
      updated = await prisma.$transaction(async (transaction) => {
        // The status check must be part of the write. An administrator can
        // disable the account after the preflight read above; writing that old
        // ACTIVE value back would silently undo the administrative action. It
        // is also intentionally the first write in this transaction: account
        // disabling locks the user before revoking credentials, so using the
        // same order here avoids a user/reset-token lock inversion.
        const changed = await transaction.user.updateMany({
          where: { id: record.userId, status: { not: STATUS.DISABLED } },
          data: { passwordHash, emailVerifiedAt: timestamp }
        });
        if (!changed.count) throw new AccountStateChanged();
        await transaction.user.updateMany({
          where: { id: record.userId, status: STATUS.PENDING },
          data: { status: STATUS.ACTIVE }
        });

        // Keep the current reset token claim behind Session/refresh/code/OIDC
        // revocation. Every account-wide credential transition uses the same
        // lock order, while excluding this one row keeps it available for the
        // conditional single-use claim below.
        await revokeAllCredentialsWith(transaction, record.userId, "password_reset", timestamp, {
          preservePasswordResetTokenId: record.id
        });

        const claimed = await transaction.passwordResetToken.updateMany({
          where: { id: record.id, usedAt: null },
          data: { usedAt: timestamp }
        });
        // Throw rather than return: every write above must roll back when a
        // concurrent request consumed the link after the preflight read.
        if (!claimed.count) throw new ResetTokenChangedConcurrently();
        return transaction.user.findUnique({ where: { id: record.userId } });
      });
    } catch (error) {
      if (error instanceof AccountStateChanged) {
        return { ok: false, reason: "disabled", account: null };
      }
      if (error instanceof ResetTokenChangedConcurrently) {
        return { ok: false, reason: "invalid_token", account: null };
      }
      throw error;
    }

    await auditLog?.record({
      action: "account.password.reset",
      actorUserId: record.userId,
      targetType: "user",
      targetId: record.userId,
      ipAddress,
      userAgent
    });
    return { ok: true, reason: null, account: toAccount(updated) };
  }

  /** Changes a password for a signed-in user, which requires the current one. */
  async function changePassword({ userId, currentPassword, newPassword, ipAddress, userAgent } = {}) {
    if (!localLoginEnabled) return { ok: false, reason: "local_login_disabled" };

    const record = await prisma.user.findUnique({ where: { id: String(userId || "") } });
    if (!record) return { ok: false, reason: "unknown_account" };

    // An account with no password — external identity only — is setting one for
    // the first time, so there is no current password to prove.
    if (record.passwordHash) {
      const valid = await verifyPassword(currentPassword, record.passwordHash);
      if (!valid) {
        await auditLog?.record({
          action: "account.password.change_failed",
          actorUserId: record.id,
          targetType: "user",
          targetId: record.id,
          ipAddress,
          userAgent
        });
        return { ok: false, reason: "bad_password" };
      }
    }

    const validated = assertValidPassword(newPassword, { minLength: minPasswordLength });
    const passwordHash = await hashPassword(validated);
    const timestamp = now();
    try {
      await prisma.$transaction(async (transaction) => {
        const changed = await transaction.user.updateMany({
          where: { id: record.id, passwordHash: record.passwordHash },
          data: { passwordHash }
        });
        if (!changed.count) throw new PasswordChangedConcurrently();
        await revokeAllCredentialsWith(transaction, record.id, "password_change", timestamp);
      });
    } catch (error) {
      if (error instanceof PasswordChangedConcurrently) {
        return { ok: false, reason: "bad_password" };
      }
      throw error;
    }
    await auditLog?.record({
      action: "account.password.changed",
      actorUserId: record.id,
      targetType: "user",
      targetId: record.id,
      ipAddress,
      userAgent
    });
    return { ok: true, reason: null };
  }

  /**
   * Revokes every credential for an account: refresh tokens, unused
   * authorization codes, sessions, and per-client OIDC sessions. Grants are left
   * alone — the user's decision to trust a client is not withdrawn by a password
   * change, and revoking it would silently log them out of every application.
   */
  async function revokeAllCredentials(userId, reason) {
    const timestamp = now();
    await prisma.$transaction((transaction) =>
      revokeAllCredentialsWith(transaction, userId, reason, timestamp)
    );
  }

  async function lockCredentialOwnerWith(transaction, userId) {
    const id = String(userId || "");
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const owner = await transaction.user.findUnique({
        where: { id },
        select: { id: true, updatedAt: true }
      });
      if (!owner) return false;

      // A conditional no-op update obtains the User row lock without changing
      // profile or account state. Supplying updatedAt explicitly prevents
      // Prisma's @updatedAt behavior from making credential revocation look
      // like a profile change, while the CAS retries if another account update
      // committed after the read.
      const locked = await transaction.user.updateMany({
        where: { id: owner.id, updatedAt: owner.updatedAt },
        data: { updatedAt: owner.updatedAt }
      });
      if (locked.count) return true;
    }
    throw new Error("The account changed while its credentials were being revoked");
  }

  async function revokeAllCredentialsWith(
    transaction,
    userId,
    reason,
    timestamp,
    { preservePasswordResetTokenId = null } = {}
  ) {
    const id = String(userId || "");
    if (!(await lockCredentialOwnerWith(transaction, id))) return false;

    // Shared lock order with browser logout/revoke: Session always precedes
    // OIDC. Account-wide paths additionally start at User, then take every
    // credential class in one fixed order to avoid cross-flow deadlocks.
    await transaction.session.deleteMany({ where: { userId: id } });
    await transaction.refreshToken.updateMany({
      where: { userId: id, revokedAt: null },
      data: { revokedAt: timestamp }
    });
    await transaction.authorizationCode.updateMany({
      where: { userId: id, usedAt: null },
      data: { usedAt: timestamp }
    });
    await transaction.oidcSession.updateMany({
      where: { userId: id, revokedAt: null },
      data: { revokedAt: timestamp, revocationReason: reason }
    });

    // Outstanding reset and verification links are credentials too, and leaving
    // them alive let a reset survive the remedy for it.
    //
    // The sequence this closes: an attacker with brief access to the mailbox
    // requests a reset, takes the link, and deletes the mail. The user notices
    // and does the textbook thing — signs in and changes their password. That
    // killed every session and refresh token and left the attacker's link
    // untouched, still unused and valid for the rest of its hour, and using it
    // locks the user back out. A 24-hour verification link had the same
    // property.
    await transaction.passwordResetToken.updateMany({
      where: {
        userId: id,
        usedAt: null,
        ...(preservePasswordResetTokenId
          ? { id: { not: String(preservePasswordResetTokenId) } }
          : {})
      },
      data: { usedAt: timestamp }
    });
    await transaction.emailVerificationToken.updateMany({
      where: { userId: id, usedAt: null },
      data: { usedAt: timestamp }
    });
    return true;
  }

  // --- Profile and administration -----------------------------------------

  async function updateProfile({ userId, name, username, picture } = {}) {
    const data = {};
    if (name !== undefined) data.name = String(name || "").trim() || null;
    if (picture !== undefined) data.picture = String(picture || "").trim() || null;
    if (username !== undefined) data.username = assertValidUsername(username);
    if (!Object.keys(data).length) return findById(userId);

    try {
      return toAccount(await prisma.user.update({ where: { id: String(userId) }, data }));
    } catch (error) {
      if (error?.code === "P2002") throw invalidRequest("That username is taken");
      throw error;
    }
  }

  /**
   * Merges deployment-specific attributes. This is the write side of what
   * OAUTH_CUSTOM_SCOPES reads: an identity adapter or an operator's own script
   * populates it, and the core never interprets the contents.
   */
  async function setAttributes({ userId, attributes } = {}) {
    const record = await prisma.user.findUnique({ where: { id: String(userId || "") } });
    if (!record) throw invalidRequest("Unknown account");
    const merged = { ...(decodeJson(record.attributesJson, {}) || {}), ...(attributes || {}) };
    for (const [key, value] of Object.entries(merged)) {
      if (value === null || value === undefined) delete merged[key];
    }
    return toAccount(
      await prisma.user.update({
        where: { id: record.id },
        data: { attributesJson: encodeJson(Object.keys(merged).length ? merged : null) }
      })
    );
  }

  /** Disabling an account revokes its credentials; nobody stays signed in. */
  async function setStatus({ userId, status, reason, actorUserId } = {}) {
    if (!Object.values(STATUS).includes(status)) throw invalidRequest("Unknown account status");
    const timestamp = now();
    const record = await prisma.$transaction(async (transaction) => {
      const updated = await transaction.user.update({
        where: { id: String(userId) },
        data: {
          status,
          disabledAt: status === STATUS.DISABLED ? timestamp : null,
          disabledReason: status === STATUS.DISABLED ? String(reason || "").trim() || null : null
        }
      });
      if (status === STATUS.DISABLED) {
        await revokeAllCredentialsWith(transaction, updated.id, "account_disabled", timestamp);
      }
      return updated;
    });
    await auditLog?.record({
      action: "account.status.changed",
      actorUserId,
      targetUserId: record.id,
      targetType: "user",
      targetId: record.id,
      metadata: { status }
    });
    return toAccount(record);
  }

  async function setRole({ userId, role, actorUserId } = {}) {
    if (!Object.values(ROLE).includes(role)) throw invalidRequest("Unknown role");
    const record = await prisma.user.update({ where: { id: String(userId) }, data: { role } });
    await auditLog?.record({
      action: "account.role.changed",
      actorUserId,
      targetUserId: record.id,
      targetType: "user",
      targetId: record.id,
      metadata: { role }
    });
    return toAccount(record);
  }

  async function list({ take = 50, skip = 0, query = "" } = {}) {
    const search = String(query || "").trim();
    // The email term stays lowercased even with the flag above. Addresses are
    // stored normalized, so folding the term is what makes the match exact
    // rather than merely case-insensitive, and it keeps working if a row
    // predates normalizeEmail.
    const where = search
      ? {
          OR: [
            { email: { contains: search.toLowerCase(), ...caseInsensitive } },
            { username: { contains: search, ...caseInsensitive } },
            { name: { contains: search, ...caseInsensitive } }
          ]
        }
      : {};
    const [records, total] = await Promise.all([
      prisma.user.findMany({
        where,
        orderBy: { createdAt: "desc" },
        take: Math.min(Math.max(Number(take) || 50, 1), 200),
        skip: Math.max(Number(skip) || 0, 0)
      }),
      prisma.user.count({ where })
    ]);
    return { accounts: records.map(toAccount), total };
  }

  /** Cleans up spent and expired one-time tokens. Safe to call on a schedule. */
  async function pruneExpiredTokens() {
    const cutoff = now();
    const [verification, reset] = await Promise.all([
      prisma.emailVerificationToken.deleteMany({
        where: { OR: [{ expiresAt: { lt: cutoff } }, { usedAt: { not: null } }] }
      }),
      prisma.passwordResetToken.deleteMany({
        where: { OR: [{ expiresAt: { lt: cutoff } }, { usedAt: { not: null } }] }
      })
    ]);
    return { verificationTokens: verification.count, resetTokens: reset.count };
  }

  return {
    ROLE,
    STATUS,
    authenticate,
    changePassword,
    findByEmail,
    findById,
    findByIdentifier,
    issueEmailVerification,
    list,
    pruneExpiredTokens,
    register,
    requestPasswordReset,
    resetPassword,
    revokeAllCredentials,
    setAttributes,
    setRole,
    setStatus,
    toAccount,
    updateProfile,
    verifyEmail,
    get registrationEnabled() {
      return registrationEnabled;
    },
    get localLoginEnabled() {
      return localLoginEnabled;
    },
    get requireEmailVerification() {
      return requireEmailVerification;
    },
    // Read by the registration and password-reset pages, so the minimum a user
    // is told matches the one that will actually be enforced.
    get minPasswordLength() {
      return minPasswordLength;
    }
  };
}

module.exports = {
  ROLE,
  STATUS,
  assertValidEmail,
  assertValidPassword,
  assertValidUsername,
  createAccountService,
  normalizeEmail
};
