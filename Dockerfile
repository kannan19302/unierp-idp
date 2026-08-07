# unierp-idp — L3, the identity provider. A separate realm per plane (§ 5.2).
#
# Built from THIS repository alone. `@unerp/*` comes from the registry, not from
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
FROM node:22-alpine AS builder
WORKDIR /app

# openssl is Prisma's runtime requirement, and python3/make/g++ are needed by
# isolated-vm, which the § 8.3 extension sandbox compiles from source.
RUN apk add --no-cache openssl python3 make g++

# Manifests first, so a source-only change does not re-resolve the tree.
# The repository's own .npmrc is deliberately NOT copied.
COPY package.json package-lock.json* ./

# @unerp/* resolves from the registry. In compose this is the `registry`
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
RUN printf '@unerp:registry=%s\nregistry=https://registry.npmjs.org/\n' "$UNIERP_REGISTRY" > .npmrc \
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
 && if [ -f package-lock.json ]; then \
      sed -i "s#http://localhost:4873/#${UNIERP_REGISTRY}#g" package-lock.json; \
    fi \
 && npm install --no-audit --no-fund

# @unerp/database generates its Prisma clients in a postinstall, and the
# generator parses a schema that reads env("DATABASE_URL"). It never connects —
# a syntactically valid placeholder is enough, and the real URL is read at
# runtime.
ENV DATABASE_URL=postgresql://placeholder:placeholder@localhost:5432/placeholder

COPY tsconfig.json nest-cli.json ./
COPY src ./src
RUN npm run build

# ── runtime ─────────────────────────────────────────────────────────────────
FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN apk add --no-cache openssl

# The generated Prisma client lives in node_modules, so it has to come across
# with it rather than being regenerated in an image with no schema.
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./package.json

EXPOSE 3005
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://localhost:3005/api/v1/auth/check-email?email=probe@health.invalid').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/main.js"]
