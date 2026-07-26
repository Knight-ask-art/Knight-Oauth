# Knight OAuth production image.
#
# Two stages, so the Prisma CLI and the query engine it downloads at build time
# do not ship in the runtime image.

FROM node:22-bookworm-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./
# The full dependency set: `prisma generate` needs the CLI, which is a normal
# dependency here rather than a dev one so the same command works in a clone.
RUN npm ci --ignore-scripts --no-audit --no-fund

# The client is generated for whichever provider the image targets. SQLite is the
# default so the image runs with no configuration at all; build with
# `--build-arg DATABASE_PROVIDER=postgresql` for a Postgres deployment.
ARG DATABASE_PROVIDER=sqlite
ENV DATABASE_PROVIDER=${DATABASE_PROVIDER}

COPY prisma ./prisma
COPY scripts ./scripts
# --check rather than a regenerate: if the committed schema does not match the
# template, that is a repository to fix, not something a build should paper over.
RUN node scripts/build-schema.js --check \
    && node scripts/prisma.js generate

# Drop packages that are only needed for development. The Prisma CLI stays: it
# is listed under dependencies, and the entrypoint runs `migrate deploy` on
# start for SQLite. The generated client in node_modules/.prisma survives too.
RUN npm prune --omit=dev


FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production
WORKDIR /app

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/prisma ./prisma
COPY package.json ./
COPY scripts ./scripts
COPY src ./src

# The SQLite file is the only path written at runtime. Created here and owned by
# the runtime user, so a read-only root filesystem with a volume at /app/data
# works without the container needing to create the directory itself.
RUN mkdir -p /app/data && chown -R node:node /app/data

USER node
EXPOSE 3010

# The entrypoint applies pending migrations (SQLite by default) and then boots
# the server in the same process, so SIGTERM reaches the drain handler rather
# than a wrapper that would not forward it. Exec form: the process is PID 1.
CMD ["node", "scripts/docker-entrypoint.js"]
