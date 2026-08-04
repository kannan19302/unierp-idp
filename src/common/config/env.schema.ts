/**
 * Boot-time environment validation (Foundation Roadmap Track G.6).
 *
 * Single source of truth for every environment variable the API reads.
 * `validateEnv()` runs in `main.ts` BEFORE Nest bootstraps: an invalid or
 * missing production variable aborts the process with one aggregated,
 * readable report instead of a runtime failure at first use.
 *
 * `.env.example` is GENERATED from this schema — edit the schema, then run
 * `node scripts/generate-env-example.mjs` (CI enforces sync via `--check`).
 *
 * Keep this module dependency-light: zod only, no Nest imports — it is
 * imported by the generator script via Node's TypeScript type-stripping.
 */
import { z } from "zod";

const booleanFlag = z
  .enum(["true", "false"])
  .optional()
  .describe('boolean flag — literal "true" or "false"');

const port = z.coerce.number().int().min(1).max(65535);

/** Required in production; defaulted or optional in development/test. */
export const envSchema = z.object({
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development")
    .describe("Runtime mode"),

  // ── Core infrastructure ────────────────────────────────────────────────
  DATABASE_URL: z
    .string()
    .url()
    .startsWith("postgresql://", "must be a postgresql:// URL")
    .describe(
      "PostgreSQL connection string (app runtime — unerp_api role, NOSUPERUSER NOBYPASSRLS)",
    ),
  DATABASE_OWNER_URL: z
    .string()
    .url()
    .startsWith("postgresql://", "must be a postgresql:// URL")
    .describe(
      "PostgreSQL connection string for migrations (owner/superuser role — not used at runtime)",
    ),
  REDIS_URL: z
    .string()
    .url()
    .startsWith("redis", "must be a redis:// or rediss:// URL")
    .default("redis://localhost:6379")
    .describe("Redis connection string (BullMQ queues, caching)"),
  API_PORT: port.default(4000).describe("Port the NestJS API listens on"),
  APP_URL: z
    .string()
    .url()
    .default("http://localhost:3000")
    .describe("Public web app origin (links in emails, redirects)"),

  // ── Secrets (strict length in production) ──────────────────────────────
  NEXTAUTH_SECRET: z
    .string()
    .min(1)
    .describe(
      "Session/JWT signing secret — generate: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"",
    ),
  NEXTAUTH_URL: z
    .string()
    .url()
    .default("http://localhost:3000")
    .describe("Auth callback base URL"),
  PII_ENCRYPTION_KEY: z
    .string()
    .min(1)
    .describe(
      "Field-level PII encryption key (hex) — same generator as NEXTAUTH_SECRET",
    ),
  MFA_ENCRYPTION_KEY: z
    .string()
    .optional()
    .describe(
      "MFA TOTP secret encryption key; falls back to PII_ENCRYPTION_KEY when unset",
    ),
  EXT_SERVICE_JWT_SECRET: z
    .string()
    .min(1)
    .default("change-me")
    .describe(
      "Extension-gateway service JWT secret (out-of-process industry apps)",
    ),
  VAPID_PUBLIC_KEY: z
    .string()
    .optional()
    .describe(
      "Web Push VAPID public key — generate: node -e \"console.log(require('web-push').generateVAPIDKeys())\"",
    ),
  VAPID_PRIVATE_KEY: z
    .string()
    .optional()
    .describe(
      "Web Push VAPID private key; MFA push-approval is disabled when unset",
    ),
  VAPID_SUBJECT: z
    .string()
    .default("mailto:admin@unerp.dev")
    .describe("Contact URI (mailto: or https:) sent with VAPID push requests"),

  // ── File storage (S3 / MinIO) ──────────────────────────────────────────
  S3_ENDPOINT: z
    .string()
    .url()
    .default("http://localhost:9000")
    .describe("S3-compatible endpoint"),
  S3_ACCESS_KEY: z.string().default("minioadmin").describe("S3 access key"),
  S3_SECRET_KEY: z.string().default("minioadmin").describe("S3 secret key"),
  S3_BUCKET: z
    .string()
    .default("unerp-uploads")
    .describe("S3 bucket for uploads"),

  // ── Email ──────────────────────────────────────────────────────────────
  SMTP_HOST: z
    .string()
    .optional()
    .describe("SMTP host (blank disables outbound email)"),
  SMTP_PORT: port.default(587).describe("SMTP port"),
  SMTP_USER: z.string().optional().describe("SMTP username"),
  SMTP_PASSWORD: z.string().optional().describe("SMTP password"),
  SMTP_FROM: z
    .string()
    .default("noreply@unerp.dev")
    .describe("From address for system email"),

  // ── OAuth integrations (optional feature unlocks) ──────────────────────
  GOOGLE_OAUTH_CLIENT_ID: z
    .string()
    .optional()
    .describe("CRM mailbox: Google OAuth client id"),
  GOOGLE_OAUTH_CLIENT_SECRET: z
    .string()
    .optional()
    .describe("CRM mailbox: Google OAuth client secret"),
  MICROSOFT_OAUTH_CLIENT_ID: z
    .string()
    .optional()
    .describe("CRM mailbox: Microsoft OAuth client id"),
  MICROSOFT_OAUTH_CLIENT_SECRET: z
    .string()
    .optional()
    .describe("CRM mailbox: Microsoft OAuth client secret"),

  // ── Payments ───────────────────────────────────────────────────────────
  STRIPE_SECRET_KEY: z
    .string()
    .optional()
    .describe("Stripe secret key (billing/e-commerce; blank disables)"),
  STRIPE_WEBHOOK_SECRET: z
    .string()
    .optional()
    .describe("Stripe webhook signing secret"),
  RAZORPAY_WEBHOOK_SECRET: z
    .string()
    .optional()
    .describe("Razorpay webhook signing secret (platform billing webhooks)"),

  // ── Observability ──────────────────────────────────────────────────────
  LOG_LEVEL: z
    .enum(["fatal", "error", "warn", "info", "debug", "trace"])
    .default("info")
    .describe("Pino log level"),
  SENTRY_DSN: z
    .string()
    .optional()
    .describe("Sentry DSN (blank disables error tracking)"),
  OTEL_EXPORTER_OTLP_ENDPOINT: z
    .string()
    .url()
    .optional()
    .describe("OpenTelemetry OTLP exporter endpoint"),

  // ── AI (self-hosted Ollama) ────────────────────────────────────────────
  OLLAMA_BASE_URL: z
    .string()
    .url()
    .default("http://localhost:11434")
    .describe("Ollama server URL"),
  OLLAMA_MODEL: z.string().default("llama3.2:3b").describe("Ollama model tag"),

  // ── Blockchain (QUARANTINED until roadmap Track E) ─────────────────────
  BLOCKCHAIN_ENABLED: booleanFlag.describe(
    "Blockchain layer flag — keep unset/false until Track E re-platforms it",
  ),
  FABRIC_USE_TEST_NETWORK: booleanFlag.describe(
    "Use the local Fabric test network",
  ),

  // ── Web app (read by apps/web next.config.mjs / client bundle) ─────────
  API_URL: z
    .string()
    .url()
    .default("http://localhost:4000")
    .describe("API origin used by the web app rewrite proxy"),
  NEXT_PUBLIC_API_URL: z
    .string()
    .url()
    .default("http://localhost:4000/api/v1")
    .describe("Browser-visible API base URL"),
  NEXT_PUBLIC_APP_URL: z
    .string()
    .url()
    .default("http://localhost:3000")
    .describe("Browser-visible app origin"),

  // ── Platform / extensions ──────────────────────────────────────────────
  CORE_VERSION: z
    .string()
    .optional()
    .describe("Reported platform core version (extension apiVersion window)"),
  APP_TENANT_ROOT: z
    .string()
    .optional()
    .describe("Filesystem root for per-tenant installed app bundles"),
  APP_BUNDLE_ROOT: z
    .string()
    .optional()
    .describe("Filesystem root for marketplace app bundles"),
  FIELD_SERVICE_SERVICE_URL: z
    .string()
    .url()
    .optional()
    .describe("Override URL for the field-service extension app"),
});

export type Env = z.infer<typeof envSchema>;

/** Secrets that must be long + non-placeholder in production. */
const productionStrictSecrets: Array<keyof Env> = [
  "NEXTAUTH_SECRET",
  "PII_ENCRYPTION_KEY",
  "EXT_SERVICE_JWT_SECRET",
  "S3_ACCESS_KEY",
  "S3_SECRET_KEY",
  "STRIPE_SECRET_KEY",
  "STRIPE_WEBHOOK_SECRET",
];

export interface ValidateEnvResult {
  env: Env | null;
  errors: string[];
}

/** Pure validation core — returns errors instead of exiting (unit-testable). */
export function checkEnv(
  source: Record<string, string | undefined>,
): ValidateEnvResult {
  const parsed = envSchema.safeParse(source);
  if (!parsed.success) {
    const errors = parsed.error.issues.map(
      (issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`,
    );
    return { env: null, errors };
  }

  const env = parsed.data;
  const errors: string[] = [];
  if (env.NODE_ENV === "production") {
    for (const key of productionStrictSecrets) {
      const value = String(env[key] ?? "");
      if (value.length < 32)
        errors.push(`${key}: must be at least 32 characters in production`);
      if (/^(change-?me|secret|password|test)$/i.test(value))
        errors.push(`${key}: placeholder value not allowed in production`);
    }
    if (String(source.DATABASE_URL ?? "").includes("localhost")) {
      errors.push("DATABASE_URL: localhost database not allowed in production");
    }
    if (String(source.DATABASE_OWNER_URL ?? "").includes("localhost")) {
      errors.push(
        "DATABASE_OWNER_URL: localhost database not allowed in production",
      );
    }
  }
  return errors.length > 0 ? { env: null, errors } : { env, errors: [] };
}

/** Boot entry: validate `process.env`, print one aggregated report, exit on failure. */
export function validateEnv(): Env {
  const { env, errors } = checkEnv(process.env);
  if (!env) {
    console.error(
      [
        "",
        "✖ Environment validation failed — refusing to start (Track G.6).",
        ...errors.map((error) => `  - ${error}`),
        "",
        "  Fix the variables above (see .env.example, generated from",
        "  apps/api/src/common/config/env.schema.ts) and restart.",
        "",
      ].join("\n"),
    );
    process.exit(1);
  }
  return env;
}
