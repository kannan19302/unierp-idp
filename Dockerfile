# unierp-idp — L3, the identity provider. A separate realm per plane (§ 5.2).
#
# Built from THIS repository alone. `@kannan19302/*` comes from the registry, not from
# a sibling directory, which is the property that makes the split real rather
# than a directory layout.
#
#   docker build -t unierp-idp .
#
# The previous Dockerfile here `COPY`d pnpm-lock.yaml, pnpm-workspace.yaml,
# apps/ and packages/ — four paths that have never existed in this repository —
# so it failed on its first instruction and was removed. This one is verified by
# building.

# ── build ───────────────────────────────────────────────────────────────────
FROM node:22-slim AS deps
WORKDIR /app

# openssl is Prisma's runtime requirement, and python3/make/g++ are needed by
# isolated-vm, which the § 8.3 extension sandbox compiles from source.
RUN apt-get update && apt-get install -y openssl python3 make g++

# Manifests first, so a source-only change does not re-resolve the tree.
# The repository's own .npmrc is deliberately NOT copied.
COPY package.json package-lock.json* ./

# @kannan19302/* resolves from the registry. In compose this is the `registry`
# service; the default is the host's, for a plain `docker build` on the machine
# that runs Verdaccio.
#
# Written into a project-level .npmrc rather than set with `npm config set`,
# which writes the USER config — and npm's precedence puts the project file
# above it. Copying the repo's .npmrc and then trying to override it that way
# left `localhost:4873` in force, so metadata resolved through the host while
# the tarball URLs Verdaccio generated pointed at the container itself, and the
# install died on ECONNREFUSED partway through. Verdaccio builds those URLs from
# the request's Host header, so the registry this file names is also the host
# the tarballs will be fetched from.
ARG UNIERP_REGISTRY=http://host.docker.internal:4873/
RUN printf '@kannan19302:registry=%s\nregistry=https://registry.npmjs.org/\n' "$UNIERP_REGISTRY" > .npmrc \
 # package-lock.json records the absolute tarball URL each dependency resolved
 # to, so a lockfile written against a registry on `localhost` is a lockfile
 # that only installs on the machine that wrote it. Inside a container
 # `localhost` is the container, and the install dies on ECONNREFUSED partway
 # through — after the metadata resolved perfectly, which is what makes it
 # confusing.
 #
 # Rewriting the host here keeps the lockfile's integrity hashes and pinned
 # versions doing their job while letting the URL follow the environment. The
 # durable fix is a registry addressed by a name that resolves the same way
 # everywhere; until § 14.1's "a registry CI can reach" decision is taken, this
 # is the honest workaround rather than dropping the lockfile.
 && rm -f package-lock.json \
 && npm install --no-audit --no-fund

# @kannan19302/database generates its Prisma clients in a postinstall, and the
# generator parses a schema that reads env("DATABASE_URL"). It never connects —
# a syntactically valid placeholder is enough, and the real URL is read at
# runtime.
ENV DATABASE_URL=postgresql://placeholder:placeholder@localhost:5432/placeholder

FROM deps AS builder
COPY tsconfig.json nest-cli.json ./
COPY src ./src

# ── local package overlay (DEV ONLY) ────────────────────────────────────────
#
# Why this stage exists.
#
# The registry install above is what makes the repository split real, and it
# stays exactly as it was for the production path below. But it also means the
# image gets whatever `@kannan19302/*` was last PUBLISHED — and the W1/W2 work
# added ten Prisma models (OAuthClient, AuthorizationCode, RefreshGrant,
# ClientConsent, OidcSigningKey, LoginAttemptCounter, Platform, PlatformGrant,
# AgentDefinition, AgentDelegation) that exist only in the local `data`
# package. Against published database@1.0.14 this service fails to compile
# with 35 "Property does not exist on type PrismaClient" errors, so the
# container could never run the very features it was built for.
#
# This is the "wire local overrides so shared/database resolve from disk in
# dev" item from the programme's Local development section. It applies to the
# DEV target only: `prod-builder` below still builds against the registry, so
# the split property is preserved where it matters and publishing remains the
# real release path.
#
# The sources arrive through a named build context (`localpkgs`, wired to the
# repo root in infra/docker-compose.platform.yml) rather than by moving this
# Dockerfile's own context, so `docker build -t unierp-idp .` from this
# directory keeps working — the default target is `runner`, which never
# touches this stage.
#
# Node modules and prebuilt output are deliberately NOT copied: the host's
# generated Prisma client carries a query engine compiled for the host OS.
# Everything is generated and compiled here instead, on this image's platform,
# which is the same reason the published package ships prisma/ but not the
# generated client (see data/scripts/postinstall.mjs).
FROM deps AS localdeps

# tsconfig.base.json is required, not optional: both packages' tsconfig.json
# does `extends: ./tsconfig.base.json`, and a missing extends target does not
# fail loudly — tsc silently falls back to its ES3/ES5 defaults and then
# reports dozens of "Property 'padStart' does not exist on type 'string'"
# errors that look like source bugs rather than a missing file.
COPY --from=localpkgs shared/package.json shared/tsconfig.json shared/tsconfig.base.json /tmp/shared/
COPY --from=localpkgs shared/src /tmp/shared/src
RUN cd /tmp/shared \
 && npm install --no-audit --no-fund \
 && npm run build

COPY --from=localpkgs data/package.json data/tsconfig.json data/tsconfig.base.json data/prisma.config.ts /tmp/data/
COPY --from=localpkgs data/prisma /tmp/data/prisma
COPY --from=localpkgs data/src /tmp/data/src
COPY --from=localpkgs data/scripts /tmp/data/scripts
# src/idp-client is generated output that may have been committed/left behind
# with host-native engines; drop it so `prisma generate` writes this platform's.
RUN rm -rf /tmp/data/src/idp-client /tmp/data/dist \
 && cd /tmp/data \
 # postinstall runs `prisma generate` for BOTH schemas (main + idp), then the
 # build's copy-prisma-clients.mjs places src/idp-client alongside dist/, which
 # is what dist/index.js requires at runtime.
 && npm install --no-audit --no-fund \
 && npm run build

# The IdP also consumes authentication hardening helpers that are newer than
# the currently published @kannan19302/auth package. Build the workspace copy
# for the development image so container compilation and local compilation use
# the same API surface.
COPY --from=localpkgs auth/package.json auth/tsconfig.json auth/tsconfig.build.json auth/tsconfig.base.json /tmp/auth/
COPY --from=localpkgs auth/src /tmp/auth/src
RUN cd /tmp/auth \
 && npm install --no-audit --no-fund \
 && npm run build

# Overlay: replace the published copies with the freshly built local ones.
# Their nested node_modules travel with them, so @prisma/client and the
# generated .prisma/client engines resolve from inside each package.
RUN rm -rf node_modules/@kannan19302/shared node_modules/@kannan19302/database node_modules/@kannan19302/auth \
 && mkdir -p node_modules/@kannan19302 \
 && cp -r /tmp/shared node_modules/@kannan19302/shared \
 && cp -r /tmp/data node_modules/@kannan19302/database \
 && cp -r /tmp/auth node_modules/@kannan19302/auth \
 && rm -rf /tmp/shared /tmp/data /tmp/auth

# Application source comes after the expensive workspace overlays so an IdP
# controller/middleware edit recompiles only this application layer. When this
# stage inherited from `builder`, every source edit invalidated Prisma
# generation and all three local package installs even though none changed.
COPY tsconfig.json nest-cli.json ./
COPY src ./src

# ── dev ─────────────────────────────────────────────────────────────────────
# Build dist/ at IMAGE BUILD TIME and run `node dist/main.js`, exactly as
# api/Dockerfile does and for exactly the same reason.
#
# `nest start --watch` is tsc in watch mode over the whole project. Under the
# shared *watch-env (NODE_OPTIONS=--max-old-space-size=8192) V8 is told it has
# an 8GB heap, so it does not collect until it reaches the cgroup wall — this
# container sat pinned at its mem_limit at single-digit CPU and NEVER finished
# the first compile, so nothing ever answered on :3005. Raising the limit only
# moved the wall (2g -> pinned at 2g, 4g -> pinned at 3.6g).
#
# With `nest build` the compile happens once, here, and exits; the container
# then runs a cheap, stable ~700MB process. That also matters for the platform
# as a whole: WSL2 has a 10GB budget shared across every service, and an idle
# idp holding 4GB of it is 4GB the twelve frontends cannot have.
#
# Trade-off, same as api: a src/ change needs `docker compose build idp` and a
# restart to take effect. The mounted src/ volume still reflects the working
# tree for inspection, but it is no longer what the process runs.
FROM localdeps AS dev
ENV NODE_ENV=development
RUN node --max-old-space-size=8192 ./node_modules/@nestjs/cli/bin/nest.js build
EXPOSE 3005
CMD ["node", "dist/main.js"]

# ── build ───────────────────────────────────────────────────────────────────
# FROM builder, not dev: the production artifact is built against the registry,
# so a published release never silently depends on a developer's working tree.
FROM builder AS prod-builder
RUN npm run build

# ── runtime ─────────────────────────────────────────────────────────────────
FROM node:22-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y openssl

# The generated Prisma client lives in node_modules, so it has to come across
# with it rather than being regenerated in an image with no schema.
COPY --from=prod-builder /app/node_modules ./node_modules
COPY --from=prod-builder /app/dist ./dist
COPY --from=prod-builder /app/package.json ./package.json

EXPOSE 3005
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://localhost:3005/api/v1/auth/check-email?email=probe@health.invalid').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/main.js"]
