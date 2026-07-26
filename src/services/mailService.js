"use strict";

// Outbound mail for email verification and password reset.
//
// With SMTP disabled — the default — the link is written to the log instead of
// being sent. That is deliberate for a local install: silently dropping a
// verification mail would make a fresh deployment look broken with no way to
// find out why. `loadEnv` refuses to start in production with verification
// required and no SMTP configured, so the log fallback cannot become the
// production behaviour by accident.
//
// A mail body carries a single-use token. It is therefore never logged at
// anything other than the operator's own console, and never recorded in the
// audit log.

/** Minimal HTML escape for the values interpolated into a mail body. */
function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatMinutes(expiresAt, now) {
  const minutes = Math.max(1, Math.round((expiresAt.getTime() - now.getTime()) / 60000));
  if (minutes < 90) return `${minutes} minutes`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours} hours` : `${Math.round(hours / 24)} days`;
}

function createMailService({ config, logger = console, transport = null, now = () => new Date() } = {}) {
  const mail = config?.mail || {};
  const serviceName = config?.branding?.serviceName || "Knight OAuth";
  const baseUrl = config?.publicBaseUrl || "";
  const enabled = Boolean(mail.enabled);

  let cachedTransport = transport;

  /**
   * nodemailer is required lazily so the dependency is only loaded by a
   * deployment that actually sends mail.
   */
  function getTransport() {
    if (cachedTransport) return cachedTransport;
    // eslint-disable-next-line global-require
    const nodemailer = require("nodemailer");
    cachedTransport = nodemailer.createTransport({
      host: mail.host,
      port: mail.port,
      secure: Boolean(mail.secure),
      auth: mail.user ? { user: mail.user, pass: mail.password } : undefined
    });
    return cachedTransport;
  }

  async function deliver({ to, subject, text, html, kind, link }) {
    if (!enabled) {
      // The link is the whole point of the message, so it goes to the console
      // where the operator can act on it.
      logger.info?.(
        `[mail:disabled] ${kind} for ${to} — SMTP is off, open this link to continue:\n  ${link}`
      );
      return { delivered: false, reason: "smtp_disabled" };
    }

    try {
      await getTransport().sendMail({
        from: mail.from,
        to,
        subject,
        text,
        html
      });
      return { delivered: true, reason: null };
    } catch (error) {
      // A send failure is reported but never thrown: the caller's decision
      // (register, request a reset) already succeeded, and turning a transport
      // hiccup into a failed registration would be the wrong trade. The address
      // is logged; the token is not.
      logger.error?.(`[mail] failed to send ${kind} to ${to}: ${error.message}`);
      return { delivered: false, reason: "send_failed" };
    }
  }

  function link(path, token) {
    const url = new URL(path, `${baseUrl}/`);
    url.searchParams.set("token", token);
    return url.toString();
  }

  async function sendEmailVerification({ email, name, token, expiresAt }) {
    const url = link("/verify-email", token);
    const window = formatMinutes(expiresAt, now());
    const greeting = name ? `Hi ${name},` : "Hi,";
    return deliver({
      to: email,
      kind: "email verification",
      link: url,
      subject: `Confirm your email address for ${serviceName}`,
      text: `${greeting}\n\nConfirm your email address to finish setting up your ${serviceName} account:\n\n${url}\n\nThe link expires in ${window}. If you did not create this account, you can ignore this message.\n`,
      html: `<p>${escapeHtml(greeting)}</p>
<p>Confirm your email address to finish setting up your ${escapeHtml(serviceName)} account.</p>
<p><a href="${escapeHtml(url)}">Confirm my email address</a></p>
<p>The link expires in ${escapeHtml(window)}. If you did not create this account, you can ignore this message.</p>`
    });
  }

  async function sendPasswordReset({ email, name, token, expiresAt }) {
    const url = link("/reset-password", token);
    const window = formatMinutes(expiresAt, now());
    const greeting = name ? `Hi ${name},` : "Hi,";
    return deliver({
      to: email,
      kind: "password reset",
      link: url,
      subject: `Reset your ${serviceName} password`,
      text: `${greeting}\n\nSomeone asked to reset the password for your ${serviceName} account. If that was you, choose a new one here:\n\n${url}\n\nThe link expires in ${window} and can be used once. Resetting your password signs you out everywhere.\n\nIf it was not you, no action is needed — your password has not changed.\n`,
      html: `<p>${escapeHtml(greeting)}</p>
<p>Someone asked to reset the password for your ${escapeHtml(serviceName)} account. If that was you, choose a new one:</p>
<p><a href="${escapeHtml(url)}">Reset my password</a></p>
<p>The link expires in ${escapeHtml(window)} and can be used once. Resetting your password signs you out everywhere.</p>
<p>If it was not you, no action is needed — your password has not changed.</p>`
    });
  }

  /**
   * Sent when someone tries to register an address that already has an account.
   * The registration response is identical either way, so this message is what
   * tells the actual account holder that it happened.
   */
  async function sendExistingAccountNotice({ email }) {
    const url = new URL("/forgot-password", `${baseUrl}/`).toString();
    return deliver({
      to: email,
      kind: "existing account notice",
      link: url,
      subject: `Your ${serviceName} account already exists`,
      text: `Hi,\n\nSomeone tried to create a ${serviceName} account with this email address, but one already exists. No new account was created and nothing has changed.\n\nIf that was you and you have forgotten your password, you can reset it here:\n\n${url}\n`,
      html: `<p>Hi,</p>
<p>Someone tried to create a ${escapeHtml(serviceName)} account with this email address, but one already exists. No new account was created and nothing has changed.</p>
<p>If that was you and you have forgotten your password, you can <a href="${escapeHtml(url)}">reset it</a>.</p>`
    });
  }

  return {
    sendEmailVerification,
    sendExistingAccountNotice,
    sendPasswordReset,
    get enabled() {
      return enabled;
    }
  };
}

module.exports = { createMailService };
