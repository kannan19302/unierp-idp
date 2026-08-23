// Tracing must initialise before any instrumented library is imported.
import "./tracing";
import * as fs from "fs";
import * as path from "path";

// Programmatically load environment variables from .env files
function loadEnv() {
  const rootEnv = path.resolve(__dirname, "../../../.env");
  const apiEnv = path.resolve(__dirname, "../.env");

  const loadFile = (filePath: string) => {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, "utf8");
      for (const line of content.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#")) {
          const index = trimmed.indexOf("=");
          if (index !== -1) {
            const key = trimmed.substring(0, index).trim();
            const value = trimmed
              .substring(index + 1)
              .trim()
              .replace(/^['"]|['"]$/g, "");
            if (key && process.env[key] === undefined) {
              process.env[key] = value;
            }
          }
        }
      }
    }
  };

  loadFile(rootEnv);
  loadFile(apiEnv);
}

loadEnv();

// Track G.6: refuse to boot on invalid/missing environment (fail-fast, one
// aggregated report). Must run after loadEnv() and before any module import
// that reads process.env at load time.
import { validateEnv } from "./common/config/env.schema";
import { deprecationMiddleware } from "./common/versioning/deprecation.middleware";

validateEnv();

import { NestFactory } from "@nestjs/core";
import { NestExpressApplication } from "@nestjs/platform-express";
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { json, urlencoded } from "express";
import * as Sentry from "@sentry/node";
import { AppModule } from "./app.module";
import { AppLogger } from "./common/services/logger.service";
import { AllExceptionsFilter } from "./common/filters/all-exceptions.filter";
import { entitlementMiddleware } from "./common/middleware/entitlement.middleware";
import { csrfMiddleware } from "./common/middleware/csrf.middleware";
import { requestLoggerMiddleware } from "./common/middleware/request-logger.middleware";
import { metricsMiddleware } from "./common/middleware/metrics.middleware";

if (process.env.SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV || "development",
    tracesSampleRate: process.env.NODE_ENV === "production" ? 0.1 : 1.0,
  });
}

async function bootstrap() {
  const logger = new AppLogger();
  logger.setContext("Bootstrap");

  const app = await NestFactory.create<NestExpressApplication>(AppModule, { logger });

  app.use(
    json({
      limit: "50mb",
      verify: (req: any, _res: any, buf: any) => {
        if (
          req.originalUrl &&
          (req.originalUrl.includes("/webhooks/stripe") ||
            req.originalUrl.includes("/billing-webhooks/stripe"))
        ) {
          req.rawBody = buf;
        }
      },
    }),
  );
  app.use(urlencoded({ limit: "50mb", extended: true }));

  // Observability — before all other middleware
  app.use(requestLoggerMiddleware);
  app.use(metricsMiddleware);

  // Every first-party platform origin (ports 4000-4010, per
  // infra/docker-compose.platform.yml's port map). Used by BOTH the CSP
  // form-action allowlist below and the CORS allowlist further down.
  const platformOrigins = Array.from({ length: 11 }, (_, i) => `http://localhost:${4000 + i}`);

  // Security
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "blob:"],
          fontSrc: ["'self'"],
          connectSrc: ["'self'", "ws:", "wss:"],
          frameAncestors: ["'none'"],
          // 'self' ALONE BREAKS SSO. Chrome enforces form-action against every
          // hop of the redirect chain a form submission triggers, not just the
          // form's immediate action. The hosted login form posts to
          // /oidc/login (same origin, fine), which 302s to /oidc/authorize
          // (same origin, fine), which 302s to the relying party's
          // redirect_uri — http://localhost:4000/auth/callback and friends,
          // a DIFFERENT origin. With 'self' alone the browser aborts that last
          // navigation and silently leaves the user sitting on the login page,
          // while the server log shows POST /oidc/login 302 and authorize 302
          // and looks perfectly healthy. Nothing in the UI says CSP.
          //
          // Same allowlist as CORS below, and the same caveat: the correct
          // source of truth is the redirect_uri origins registered on each
          // OAuthClient (data/prisma/seed-oidc-clients.ts), which W6 should
          // wire this up to read instead of a static port range.
          formAction: ["'self'", ...platformOrigins],
          baseUri: ["'none'"],
          upgradeInsecureRequests: [],
        },
      },
      crossOriginOpenerPolicy: { policy: "same-origin" },
      crossOriginEmbedderPolicy: false,
    }),
  );
  app.use(cookieParser());
  // idp is the OIDC provider for all ten platforms plus the wizard, not a
  // backend for one Next.js app — a single-origin CORS allowlist (the
  // original NEXTAUTH_URL/APP_URL pair) meant every platform except whichever
  // one happened to be configured got a browser-level CORS failure on
  // /oidc/token, /oidc/userinfo and /api/v1/auth/platforms, indistinguishable
  // from the network being down. The allowed set is every first-party
  // platform origin (ports 4000-4010, per infra/docker-compose.platform.yml's
  // port map) plus whatever NEXTAUTH_URL/APP_URL/CORS_ORIGINS add for
  // non-standard deployments.
  //
  // This is a dev-appropriate allowlist, not the long-term design: the
  // correct source of truth is the redirect_uri origins already registered on
  // each OAuthClient (data/prisma/seed-oidc-clients.ts), which W6 should wire
  // this up to read instead of a static port range.
  const allowedOrigins = [
    ...platformOrigins,
    process.env.NEXTAUTH_URL,
    process.env.APP_URL,
    ...(process.env.CORS_ORIGINS?.split(",").map((o) => o.trim()) ?? []),
  ].filter(Boolean) as string[];
  app.enableCors({
    origin: allowedOrigins,
    credentials: true,
  });

  // CSRF protection for state-changing requests
  app.use(csrfMiddleware);

  // Consistent error envelope for every thrown error
  app.useGlobalFilters(new AllExceptionsFilter());

  // Track G.1: RFC 9745/8594 Deprecation + Sunset headers for any surface in
  // the deprecation registry (docs/API_VERSIONING_POLICY.md).
  app.use(deprecationMiddleware());

  // Global prefix for all API routes (metrics and swagger excluded)
  // `.well-known/openid-configuration` and the JWKS must sit at the issuer
  // root: RFC 8414 has clients build that URL from the issuer themselves, so a
  // prefixed copy is one no standard client will ever look for.
  // The OIDC endpoints sit at the ISSUER ROOT, not under /api/v1.
  //
  // Discovery publishes absolute URLs built from the issuer
  // (`${issuer}/oidc/token` and so on), and clients use exactly those. Leaving
  // these under the API prefix makes the discovery document advertise paths
  // that 404 — the endpoints exist, just nowhere a conformant client looks.
  // Every route added to the OIDC module must be listed here.
  app.setGlobalPrefix("api/v1", {
    exclude: [
      "metrics",
      "swagger",
      "swagger-json",
      ".well-known/openid-configuration",
      "oidc/jwks.json",
      "oidc/authorize",
      "oidc/token",
      "oidc/userinfo",
      "oidc/revoke",
      "oidc/introspect",
      "oidc/end_session",
      "oidc/login",
      "oidc/login/mfa",
      "oidc/register",
      "oidc/forgot-password",
      "oidc/reset-password",
      "oidc/verify-email",
      "oidc/verify-email/resend",
      "oidc/consent",
    ],
  });

  // OpenAPI documentation
  const swaggerConfig = new DocumentBuilder()
    .setTitle("UniERP API")
    .setDescription("Universal Enterprise Resource Planning — REST API")
    .setVersion("1.0")
    .addBearerAuth()
    .addCookieAuth("auth_token")
    .build();
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup("swagger", app, document, {
    swaggerOptions: { persistAuthorization: true },
  });

  // Module entitlements: 404 gated business-module routes that the tenant has
  // uninstalled (kernel apps and unmapped routes pass through).
  app.use(entitlementMiddleware);

  // This service is the IdP, not the API. Defaulting to 3001 collided with
  // `api`, and env.schema.ts separately defaulted API_PORT to 4000, which
  // collided with the platform wizard — only compose happened to be right.
  // PORT is the service's own variable; API_PORT is kept as a fallback for
  // existing deployments that set it.
  const port = process.env.PORT ?? process.env.API_PORT ?? 3005;
  await app.listen(port, "0.0.0.0");

  logger.log(`UniERP IdP running on http://localhost:${port}/api/v1`);
  logger.log(
    `OIDC discovery at http://localhost:${port}/.well-known/openid-configuration`,
  );
  logger.log(`Swagger docs at http://localhost:${port}/swagger`);
}

bootstrap().catch((err) => {
  console.error("BOOTSTRAP ERROR:", err);
  process.exit(1);
});
