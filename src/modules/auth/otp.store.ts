import { Injectable, Logger, OnModuleDestroy } from "@nestjs/common";
import Redis from "ioredis";
import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Email OTP storage.
 *
 * Replaces an in-process `Map`. That worked only because the IdP happened to
 * run as a single process: with two replicas behind a load balancer, the code
 * is issued by one and verified by the other, so roughly half of all
 * verifications fail with "no verification code found" — an intermittent,
 * unreproducible-on-one-box failure that looks like an email delivery problem.
 * A restart lost every outstanding code for the same reason.
 *
 * Two further properties the Map version did not have:
 *
 *  * **Codes are stored hashed.** They are short-lived, but they are also a
 *    credential; whoever can read the store should not be able to complete
 *    someone else's verification.
 *  * **The attempt counter increments atomically.** `record.attempts += 1` on a
 *    shared object is a read-modify-write race: two concurrent guesses both
 *    read the same value, both write back the same increment, and the attempt
 *    limit can be walked past by simply guessing in parallel.
 *
 * Redis is used when REDIS_URL is set; otherwise an in-process fallback keeps
 * unit tests and Redis-less development working. The fallback carries the
 * single-process caveat, which is why it warns.
 */

const OTP_TTL_SECONDS = 5 * 60;
const RESEND_COOLDOWN_SECONDS = 60;
const MAX_ATTEMPTS = 5;

export interface OtpRecord {
  codeHash: string;
  attempts: number;
  issuedAtMs: number;
}

@Injectable()
export class OtpStore implements OnModuleDestroy {
  private readonly logger = new Logger(OtpStore.name);
  private readonly redis: Redis | null;
  private readonly memory = new Map<string, OtpRecord & { expiresAtMs: number }>();

  constructor() {
    const url = process.env.REDIS_URL;
    if (url) {
      this.redis = new Redis(url, { maxRetriesPerRequest: 2, lazyConnect: false });
      this.redis.on("error", (err) =>
        this.logger.error(`OTP store Redis error: ${err.message}`),
      );
    } else {
      this.redis = null;
      this.logger.warn(
        "REDIS_URL is not set — OTP codes are held in this process only. " +
          "Codes will not survive a restart and will not work across replicas.",
      );
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.redis?.quit().catch(() => undefined);
  }

  /**
   * Seconds the caller must wait before another code may be sent, or 0.
   * Rate-limiting resends matters because each one is an email we send on an
   * unauthenticated caller's say-so.
   */
  async secondsUntilResendAllowed(email: string): Promise<number> {
    const record = await this.read(key(email));
    if (!record) return 0;

    const elapsed = Math.floor((Date.now() - record.issuedAtMs) / 1000);
    const remaining = RESEND_COOLDOWN_SECONDS - elapsed;
    return remaining > 0 ? remaining : 0;
  }

  /** Stores a freshly issued code, replacing any previous one. */
  async issue(email: string, code: string): Promise<void> {
    const record: OtpRecord = {
      codeHash: hashCode(code),
      attempts: 0,
      issuedAtMs: Date.now(),
    };

    if (this.redis) {
      await this.redis.set(
        key(email),
        JSON.stringify(record),
        "EX",
        OTP_TTL_SECONDS,
      );
      return;
    }

    this.memory.set(key(email), {
      ...record,
      expiresAtMs: Date.now() + OTP_TTL_SECONDS * 1000,
    });
  }

  /**
   * Checks a submitted code and consumes it on success.
   *
   * The attempt counter is incremented BEFORE the comparison, so a guess costs
   * an attempt whether or not it is right — otherwise the limit would only
   * apply to attempts the attacker chose to let fail.
   */
  async verify(
    email: string,
    submitted: string,
  ): Promise<
    | { ok: true }
    | { ok: false; reason: "missing" | "expired" | "too-many-attempts" | "mismatch" }
  > {
    const k = key(email);
    const record = await this.read(k);
    if (!record) return { ok: false, reason: "missing" };

    const attempts = await this.incrementAttempts(k, record);
    if (attempts > MAX_ATTEMPTS) {
      await this.clear(email);
      return { ok: false, reason: "too-many-attempts" };
    }

    if (!constantTimeEquals(hashCode(submitted.trim()), record.codeHash)) {
      return { ok: false, reason: "mismatch" };
    }

    await this.clear(email);
    return { ok: true };
  }

  async clear(email: string): Promise<void> {
    const k = key(email);
    if (this.redis) {
      await this.redis.del(k);
      return;
    }
    this.memory.delete(k);
  }

  // ── internals ────────────────────────────────────────────────────────────

  private async read(k: string): Promise<OtpRecord | null> {
    if (this.redis) {
      const raw = await this.redis.get(k);
      if (!raw) return null;
      try {
        return JSON.parse(raw) as OtpRecord;
      } catch {
        // A corrupt entry is treated as absent rather than crashing the flow.
        await this.redis.del(k);
        return null;
      }
    }

    const record = this.memory.get(k);
    if (!record) return null;
    if (record.expiresAtMs < Date.now()) {
      this.memory.delete(k);
      return null;
    }
    return record;
  }

  /**
   * Increments the attempt counter atomically.
   *
   * On Redis this is a separate INCR key rather than a rewrite of the JSON
   * blob: rewriting would reintroduce exactly the read-modify-write race this
   * exists to remove, since two parallel guesses would each read `attempts: 1`
   * and each write back `2`.
   */
  private async incrementAttempts(
    k: string,
    record: OtpRecord,
  ): Promise<number> {
    if (this.redis) {
      const counterKey = `${k}:attempts`;
      const attempts = await this.redis.incr(counterKey);
      // Tie the counter's lifetime to the code's on first use.
      if (attempts === 1) await this.redis.expire(counterKey, OTP_TTL_SECONDS);
      return attempts;
    }

    const existing = this.memory.get(k);
    if (!existing) return record.attempts + 1;
    existing.attempts += 1;
    return existing.attempts;
  }
}

function key(email: string): string {
  return `otp:${email.toLowerCase().trim()}`;
}

/** Codes are stored hashed — short-lived, but still a credential. */
function hashCode(code: string): string {
  return createHash("sha256").update(code).digest("base64url");
}

/**
 * Constant-time comparison.
 *
 * A plain `!==` on a six-digit code leaks, through response timing, how many
 * leading characters were correct — which turns 10^6 guesses into roughly 60.
 */
function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export { OTP_TTL_SECONDS, RESEND_COOLDOWN_SECONDS, MAX_ATTEMPTS };
