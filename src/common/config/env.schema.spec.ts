import { describe, expect, it } from "vitest";
import { checkEnv } from "./env.schema";

const validDev = {
  NODE_ENV: "development",
  DATABASE_URL: "postgresql://unerp:pw@localhost:5432/unerp_dev",
  DATABASE_OWNER_URL: "postgresql://unerp:pw@localhost:5432/unerp_dev_owner",
  NEXTAUTH_SECRET: "dev-secret",
  PII_ENCRYPTION_KEY: "dev-pii-key",
};

const validProd = {
  NODE_ENV: "production",
  DATABASE_URL: "postgresql://unerp:pw@db.internal:5432/unerp",
  DATABASE_OWNER_URL: "postgresql://unerp:pw@db.internal:5432/unerp_owner",
  REDIS_URL: "redis://cache.internal:6379",
  PLATFORM_WIZARD_URL: "https://wizard.unierp.example",
  TENANT_APP_URL: "https://app.unierp.example",
  WEBAUTHN_RP_ID: "unierp.example",
  WEBAUTHN_ORIGINS: "https://id.unierp.example,https://unierp.example",
  NEXTAUTH_SECRET: "a".repeat(64),
  PII_ENCRYPTION_KEY: "b".repeat(64),
  EXT_SERVICE_JWT_SECRET: "c".repeat(64),
  S3_ACCESS_KEY: "d".repeat(32),
  S3_SECRET_KEY: "e".repeat(32),
  STRIPE_SECRET_KEY: "f".repeat(32),
  STRIPE_WEBHOOK_SECRET: "g".repeat(32),
  SSO_CONFIG_ENCRYPTION_KEYS: JSON.stringify({
    "test-key-2026-08": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  }),
  SSO_CONFIG_ENCRYPTION_ACTIVE_KEY_ID: "test-key-2026-08",
  RESEND_API_KEY: "re_production",
  RESEND_WEBHOOK_SECRET: `whsec_${"h".repeat(44)}`,
  EMAIL_RECIPIENT_HASH_KEY: "i".repeat(64),
  EMAIL_CANARY_RECIPIENT: "delivery-canary@unierp.example",
  EMAIL_CANARY_TENANT_ID: "platform-operations",
  TERMS_OF_SERVICE_URL: "https://www.unierp.example/terms",
  TERMS_OF_SERVICE_VERSION: "2026-07",
  TERMS_OF_SERVICE_EFFECTIVE_DATE: "2026-07-01",
  PRIVACY_POLICY_URL: "https://www.unierp.example/privacy",
  PRIVACY_POLICY_VERSION: "2026-07",
  PRIVACY_POLICY_EFFECTIVE_DATE: "2026-07-01",
};

describe("checkEnv (Track G.6 boot validation)", () => {
  it("accepts a minimal development env and applies defaults", () => {
    const { env, errors } = checkEnv(validDev);
    expect(errors).toEqual([]);
    expect(env).not.toBeNull();
    // 3005, not 4000. This service is the IdP; 4000 is the platform wizard and
    // 3001 is the API, both of which this default previously collided with.
    expect(env?.API_PORT).toBe(3005);
    expect(env?.REDIS_URL).toBe("redis://localhost:6379");
    expect(env?.LOG_LEVEL).toBe("info");
  });

  it("coerces numeric ports from strings and rejects invalid ones", () => {
    expect(checkEnv({ ...validDev, API_PORT: "8080" }).env?.API_PORT).toBe(
      8080,
    );
    const { env, errors } = checkEnv({ ...validDev, API_PORT: "not-a-port" });
    expect(env).toBeNull();
    expect(errors.some((error) => error.startsWith("API_PORT"))).toBe(true);
  });

  it("rejects a non-postgres DATABASE_URL", () => {
    const { env, errors } = checkEnv({
      ...validDev,
      DATABASE_URL: "mysql://x",
    });
    expect(env).toBeNull();
    expect(errors.some((error) => error.startsWith("DATABASE_URL"))).toBe(true);
  });

  it("aggregates ALL failures into one report", () => {
    const { errors } = checkEnv({});
    expect(errors.length).toBeGreaterThanOrEqual(3); // DATABASE_URL, NEXTAUTH_SECRET, PII_ENCRYPTION_KEY
  });

  it("accepts a strict production env", () => {
    const { env, errors } = checkEnv(validProd);
    expect(errors).toEqual([]);
    expect(env?.NODE_ENV).toBe("production");
  });

  it("requires provider callbacks and canary controls in production", () => {
    const noWebhook = checkEnv({ ...validProd, RESEND_WEBHOOK_SECRET: undefined });
    expect(noWebhook.errors).toContain(
      "RESEND_WEBHOOK_SECRET: required when Resend delivery is enabled",
    );

    const noCanary = checkEnv({ ...validProd, EMAIL_CANARY_RECIPIENT: undefined });
    expect(noCanary.errors).toContain(
      "EMAIL_CANARY_RECIPIENT: required for production email operations",
    );
  });

  it("rejects short or placeholder secrets in production only", () => {
    const short = checkEnv({ ...validProd, NEXTAUTH_SECRET: "short" });
    expect(short.env).toBeNull();
    expect(
      short.errors.some((error) => error.includes("at least 32 characters")),
    ).toBe(true);

    const placeholder = checkEnv({
      ...validProd,
      EXT_SERVICE_JWT_SECRET: "change-me",
    });
    expect(placeholder.env).toBeNull();

    // same values are fine in development
    expect(checkEnv({ ...validDev, NEXTAUTH_SECRET: "short" }).errors).toEqual(
      [],
    );
  });

  it("rejects a localhost database in production", () => {
    const { env, errors } = checkEnv({
      ...validProd,
      DATABASE_URL: "postgresql://u:p@localhost:5432/d",
    });
    expect(env).toBeNull();
    expect(errors.some((error) => error.includes("localhost database"))).toBe(
      true,
    );
  });

  it("rejects local or draft legal documents in production", () => {
    const localTerms = checkEnv({
      ...validProd,
      TERMS_OF_SERVICE_URL: "http://localhost:4001/terms",
    });
    expect(localTerms.env).toBeNull();
    expect(
      localTerms.errors.some((error) => error.startsWith("TERMS_OF_SERVICE_URL")),
    ).toBe(true);

    const draftPrivacy = checkEnv({
      ...validProd,
      PRIVACY_POLICY_VERSION: "draft-3",
    });
    expect(draftPrivacy.env).toBeNull();
    expect(
      draftPrivacy.errors.some((error) => error.startsWith("PRIVACY_POLICY_VERSION")),
    ).toBe(true);
  });

  it("rejects local or insecure cross-platform navigation in production", () => {
    const localWizard = checkEnv({
      ...validProd,
      PLATFORM_WIZARD_URL: "http://localhost:4000",
    });
    expect(localWizard.env).toBeNull();
    expect(
      localWizard.errors.some((error) => error.startsWith("PLATFORM_WIZARD_URL")),
    ).toBe(true);

    const insecureApp = checkEnv({
      ...validProd,
      TENANT_APP_URL: "http://app.unierp.example",
    });
    expect(insecureApp.env).toBeNull();
    expect(
      insecureApp.errors.some((error) => error.includes("HTTPS is required")),
    ).toBe(true);
  });

  it("rejects local, insecure, or cross-domain WebAuthn configuration in production", () => {
    const local = checkEnv({
      ...validProd,
      WEBAUTHN_RP_ID: "localhost",
      WEBAUTHN_ORIGINS: "http://localhost:3005",
    });
    expect(local.env).toBeNull();
    expect(local.errors.some((error) => error.startsWith("WEBAUTHN_RP_ID"))).toBe(true);

    const unrelatedOrigin = checkEnv({
      ...validProd,
      WEBAUTHN_ORIGINS: "https://identity.example.net",
    });
    expect(unrelatedOrigin.env).toBeNull();
    expect(unrelatedOrigin.errors.some((error) => error.includes("not within RP ID"))).toBe(true);
  });

  it("rejects non-boolean feature flags", () => {
    expect(checkEnv({ ...validDev, BLOCKCHAIN_ENABLED: "yes" }).env).toBeNull();
    expect(
      checkEnv({ ...validDev, BLOCKCHAIN_ENABLED: "true" }).env,
    ).not.toBeNull();
  });
});
