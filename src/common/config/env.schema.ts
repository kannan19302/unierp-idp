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
  // 4000 is the platform wizard. This service listens on 3005 (see compose and
  // main.ts); a default that lands on another service is worse than no default.
  API_PORT: port.default(3005).describe("Port this IdP service listens on"),
  APP_URL: z
    .string()
    .url()
    .default("http://localhost:3000")
    .describe("Public web app origin (links in emails, redirects)"),
  PLATFORM_WIZARD_URL: z
    .string()
    .url()
    .default("http://localhost:4000")
    .describe("Public Platform Wizard origin used by hosted identity navigation"),
  TENANT_APP_URL: z
    .string()
    .url()
    .default("http://localhost:4003")
    .describe("Public tenant application origin used by Account Center destinations"),
  WEBAUTHN_RP_ID: z
    .string()
    .min(1)
    .default("localhost")
    .describe("WebAuthn relying-party domain without scheme or path"),
  WEBAUTHN_RP_NAME: z
    .string()
    .min(1)
    .default("UniERP")
    .describe("Human-readable relying-party name shown by authenticators"),
  WEBAUTHN_ORIGINS: z
    .string()
    .min(1)
    .default("http://localhost:3005")
    .describe("Comma-separated exact browser origins permitted for WebAuthn ceremonies"),

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
  SSO_CONFIG_ENCRYPTION_KEYS: z
    .string()
    .optional()
    .describe("JSON object mapping federation-secret key IDs to base64-encoded 32-byte AES keys"),
  SSO_CONFIG_ENCRYPTION_ACTIVE_KEY_ID: z
    .string()
    .regex(/^[A-Za-z0-9_-]{1,64}$/)
    .optional()
    .describe("Key ID used to decrypt and rotate federation client secrets"),
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
    .default("mailto:admin@kannan19302.dev")
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
  EMAIL_PROVIDER: z
    .enum(["auto", "resend", "brevo", "smtp"])
    .default("auto")
    .describe("Preferred transactional email provider; auto uses API providers before SMTP"),
  EMAIL_FROM: z
    .string()
    .default("UniERP <noreply@kannan19302.dev>")
    .describe("Verified sender identity used by transactional email providers"),
  RESEND_API_KEY: z
    .string()
    .optional()
    .describe("Resend transactional email API key (primary free-tier option)"),
  BREVO_API_KEY: z
    .string()
    .optional()
    .describe("Brevo transactional email API key (fallback free-tier option)"),
  RESEND_WEBHOOK_SECRET: z
    .string()
    .optional()
    .describe("Resend/Svix signing secret for authenticated delivery callbacks"),
  BREVO_WEBHOOK_SECRET: z
    .string()
    .optional()
    .describe("Password used by Brevo Basic-auth webhook callbacks"),
  EMAIL_RECIPIENT_HASH_KEY: z
    .string()
    .optional()
    .describe("HMAC key for privacy-minimised recipient delivery fingerprints"),
  EMAIL_DAILY_TENANT_QUOTA: z.coerce.number().int().min(1).default(1000)
    .describe("Maximum transactional email reservations per tenant per UTC day"),
  EMAIL_CANARY_RECIPIENT: z.string().email().optional()
    .describe("Dedicated inbox that receives the production email delivery canary"),
  EMAIL_CANARY_TENANT_ID: z.string().min(1).optional()
    .describe("Tenant charged for delivery-canary quota and ledger records"),
  EMAIL_CANARY_INTERVAL_MINUTES: z.coerce.number().int().min(15).default(360)
    .describe("Interval between real email delivery probes"),
  EMAIL_CANARY_GRACE_MINUTES: z.coerce.number().int().min(1).default(15)
    .describe("Maximum wait for a canary delivered callback"),
  EMAIL_CANARY_MAX_AGE_MINUTES: z.coerce.number().int().min(30).default(480)
    .describe("Maximum acceptable age of the latest email canary"),
  SMTP_HOST: z
    .string()
    .optional()
    .describe("SMTP host (blank disables outbound email)"),
  SMTP_PORT: port.default(587).describe("SMTP port"),
  SMTP_USER: z.string().optional().describe("SMTP username"),
  SMTP_PASSWORD: z.string().optional().describe("SMTP password"),
  SMTP_FROM: z
    .string()
    .default("noreply@kannan19302.dev")
    .describe("From address for system email"),

  // ── Registration legal documents ─────────────────────────────────────
  TERMS_OF_SERVICE_URL: z
    .string()
    .url()
    .default("http://localhost:4001/terms")
    .describe("Durable public URL for the Terms of Service accepted at registration"),
  TERMS_OF_SERVICE_VERSION: z
    .string()
    .min(1)
    .default("2026-07-development")
    .describe("Immutable Terms of Service document/version identifier"),
  TERMS_OF_SERVICE_EFFECTIVE_DATE: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, "must use YYYY-MM-DD")
    .default("2026-07-01")
    .describe("Terms of Service effective date"),
  PRIVACY_POLICY_URL: z
    .string()
    .url()
    .default("http://localhost:4001/privacy")
    .describe("Durable public URL for the Privacy Policy acknowledged at registration"),
  PRIVACY_POLICY_VERSION: z
    .string()
    .min(1)
    .default("2026-07-development")
    .describe("Immutable Privacy Policy document/version identifier"),
  PRIVACY_POLICY_EFFECTIVE_DATE: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, "must use YYYY-MM-DD")
    .default("2026-07-01")
    .describe("Privacy Policy effective date"),

  // ── OAuth integrations (optional feature unlocks) ──────────────────────
  GOOGLE_OAUTH_CLIENT_ID: z
    .string()
    .optional()
    .describe("CRM mailbox: Google OAuth client id"),
  GOOGLE_OAUTH_CLIENT_SECRET: z
    .string()
    .optional()
    .describe("CRM mailbox: Google OAuth client secret"),
  GOOGLE_OAUTH_ENABLED: z
    .enum(["true", "false"])
    .optional()
    .describe("Enable Google login/registration when credentials are configured"),
  MICROSOFT_OAUTH_CLIENT_ID: z
    .string()
    .optional()
    .describe("CRM mailbox: Microsoft OAuth client id"),
  MICROSOFT_OAUTH_CLIENT_SECRET: z
    .string()
    .optional()
    .describe("CRM mailbox: Microsoft OAuth client secret"),
  MICROSOFT_OAUTH_TENANT: z
    .string()
    .optional()
    .describe("Microsoft Entra tenant id or common/organizations/consumers"),
  MICROSOFT_OAUTH_ENABLED: z
    .enum(["true", "false"])
    .optional()
    .describe("Enable Microsoft login/registration when credentials are configured"),
  GITHUB_OAUTH_CLIENT_ID: z
    .string()
    .optional()
    .describe("GitHub OAuth app client id for login and registration"),
  GITHUB_OAUTH_CLIENT_SECRET: z
    .string()
    .optional()
    .describe("GitHub OAuth app client secret for login and registration"),
  GITHUB_OAUTH_ENABLED: z
    .enum(["true", "false"])
    .optional()
    .describe("Enable GitHub login/registration when credentials are configured"),

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
  "SSO_CONFIG_ENCRYPTION_KEYS",
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

function checkSsoEncryptionKeyring(env: Env, errors: string[]): void {
  if (!env.SSO_CONFIG_ENCRYPTION_ACTIVE_KEY_ID) {
    errors.push("SSO_CONFIG_ENCRYPTION_ACTIVE_KEY_ID: required in production");
    return;
  }
  try {
    const parsed = JSON.parse(env.SSO_CONFIG_ENCRYPTION_KEYS ?? "") as Record<string, unknown>;
    const value = parsed?.[env.SSO_CONFIG_ENCRYPTION_ACTIVE_KEY_ID];
    if (typeof value !== "string" || Buffer.from(value, "base64").length !== 32) {
      errors.push("SSO_CONFIG_ENCRYPTION_KEYS: active key must resolve to a base64-encoded 32-byte key");
    }
  } catch {
    errors.push("SSO_CONFIG_ENCRYPTION_KEYS: must be a valid JSON keyring in production");
  }
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
    checkSsoEncryptionKeyring(env, errors);
    if (String(source.DATABASE_URL ?? "").includes("localhost")) {
      errors.push("DATABASE_URL: localhost database not allowed in production");
    }
    if (String(source.DATABASE_OWNER_URL ?? "").includes("localhost")) {
      errors.push(
        "DATABASE_OWNER_URL: localhost database not allowed in production",
      );
    }
    for (const [key, value] of [
      ["TERMS_OF_SERVICE_URL", env.TERMS_OF_SERVICE_URL],
      ["PRIVACY_POLICY_URL", env.PRIVACY_POLICY_URL],
      ["PLATFORM_WIZARD_URL", env.PLATFORM_WIZARD_URL],
      ["TENANT_APP_URL", env.TENANT_APP_URL],
    ] as const) {
      if (/localhost|127\.0\.0\.1|\.local(?=\/|$)/i.test(value)) {
        errors.push(`${key}: development/local URL not allowed in production`);
      }
      if (!value.startsWith("https://")) {
        errors.push(`${key}: HTTPS is required in production`);
      }
    }
    const hasApiProvider = Boolean(env.RESEND_API_KEY || env.BREVO_API_KEY);
    const hasSmtp = Boolean(env.SMTP_HOST && env.SMTP_USER && env.SMTP_PASSWORD);
    if (!hasApiProvider && !hasSmtp) {
      errors.push("EMAIL_PROVIDER: configure Resend, Brevo, or authenticated SMTP in production");
    }
    if (env.RESEND_API_KEY && !env.RESEND_WEBHOOK_SECRET) {
      errors.push("RESEND_WEBHOOK_SECRET: required when Resend delivery is enabled");
    }
    if (env.BREVO_API_KEY && !env.BREVO_WEBHOOK_SECRET) {
      errors.push("BREVO_WEBHOOK_SECRET: required when Brevo delivery is enabled");
    }
    for (const key of ["EMAIL_RECIPIENT_HASH_KEY", "EMAIL_CANARY_RECIPIENT", "EMAIL_CANARY_TENANT_ID"] as const) {
      if (!env[key]) errors.push(`${key}: required for production email operations`);
    }
    if ((env.EMAIL_RECIPIENT_HASH_KEY?.length ?? 0) < 32) {
      errors.push("EMAIL_RECIPIENT_HASH_KEY: must be at least 32 characters in production");
    }
    if (/^(localhost|127\.0\.0\.1|\[::1\])$/i.test(env.WEBAUTHN_RP_ID)) {
      errors.push("WEBAUTHN_RP_ID: local relying-party id not allowed in production");
    }
    if (env.WEBAUTHN_RP_ID.includes("://") || env.WEBAUTHN_RP_ID.includes("/")) {
      errors.push("WEBAUTHN_RP_ID: must be a domain without scheme or path");
    }
    for (const rawOrigin of env.WEBAUTHN_ORIGINS.split(",")) {
      const value = rawOrigin.trim();
      try {
        const origin = new URL(value);
        if (origin.origin !== value || origin.protocol !== "https:") {
          errors.push(`WEBAUTHN_ORIGINS: exact HTTPS origin required (${value})`);
        }
        const hostname = origin.hostname.toLowerCase();
        const rpId = env.WEBAUTHN_RP_ID.toLowerCase();
        if (hostname !== rpId && !hostname.endsWith(`.${rpId}`)) {
          errors.push(`WEBAUTHN_ORIGINS: ${hostname} is not within RP ID ${rpId}`);
        }
      } catch {
        errors.push(`WEBAUTHN_ORIGINS: invalid origin (${value})`);
      }
    }
    for (const [key, value] of [
      ["TERMS_OF_SERVICE_VERSION", env.TERMS_OF_SERVICE_VERSION],
      ["PRIVACY_POLICY_VERSION", env.PRIVACY_POLICY_VERSION],
    ] as const) {
      if (/development|draft|placeholder/i.test(value)) {
        errors.push(`${key}: draft/development version not allowed in production`);
      }
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
