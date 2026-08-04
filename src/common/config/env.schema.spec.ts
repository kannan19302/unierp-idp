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
  NEXTAUTH_SECRET: "a".repeat(64),
  PII_ENCRYPTION_KEY: "b".repeat(64),
  EXT_SERVICE_JWT_SECRET: "c".repeat(64),
  S3_ACCESS_KEY: "d".repeat(32),
  S3_SECRET_KEY: "e".repeat(32),
  STRIPE_SECRET_KEY: "f".repeat(32),
  STRIPE_WEBHOOK_SECRET: "g".repeat(32),
};

describe("checkEnv (Track G.6 boot validation)", () => {
  it("accepts a minimal development env and applies defaults", () => {
    const { env, errors } = checkEnv(validDev);
    expect(errors).toEqual([]);
    expect(env).not.toBeNull();
    expect(env?.API_PORT).toBe(4000);
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

  it("rejects non-boolean feature flags", () => {
    expect(checkEnv({ ...validDev, BLOCKCHAIN_ENABLED: "yes" }).env).toBeNull();
    expect(
      checkEnv({ ...validDev, BLOCKCHAIN_ENABLED: "true" }).env,
    ).not.toBeNull();
  });
});
