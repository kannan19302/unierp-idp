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

  const app = await NestFactory.create(AppModule, { logger });

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
          formAction: ["'self'"],
          baseUri: ["'none'"],
          upgradeInsecureRequests: [],
        },
      },
      crossOriginOpenerPolicy: { policy: "same-origin" },
      crossOriginEmbedderPolicy: false,
    }),
  );
  app.use(cookieParser());
  const allowedOrigins = [
    process.env.NEXTAUTH_URL ?? "http://localhost:3000",
    process.env.APP_URL,
  ].filter(Boolean) as string[];
  app.enableCors({
    origin: allowedOrigins.length === 1 ? allowedOrigins[0] : allowedOrigins,
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
  app.setGlobalPrefix("api/v1", {
    exclude: ["metrics", "swagger", "swagger-json"],
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

  const port = process.env.API_PORT ?? 3001;
  await app.listen(port, "0.0.0.0");

  logger.log(`UniERP API running on http://localhost:${port}/api/v1`);
  logger.log(`Swagger docs at http://localhost:${port}/swagger`);
}

bootstrap().catch((err) => {
  console.error("BOOTSTRAP ERROR:", err);
  process.exit(1);
});
