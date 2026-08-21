import { Injectable, Logger } from "@nestjs/common";
import { createHash } from "node:crypto";
import { idpPrisma } from "@kannan19302/database";

/**
 * Per-ORIGIN login throttling.
 *
 * The existing per-account lockout (users.failed_login_attempts /
 * users.locked_until) bounds attempts against one account. It does nothing
 * about the attack that actually matters at scale: one origin trying the same
 * handful of common passwords across thousands of accounts. Each account sees
 * two or three failures — far below its own threshold — while the attacker
 * works through the entire user list unimpeded.
 *
 * The two bounds are complementary and neither replaces the other:
 *
 *   per-account  protects one user from being singled out;
 *   per-origin   protects every user from being swept.
 *
 * Backoff is exponential rather than a flat lockout so that a person mistyping
 * their password is delayed by seconds while an automated sweep is delayed by
 * hours, without an operator having to unlock anything.
 */

/** Failures tolerated before any delay is imposed. */
const FREE_ATTEMPTS = 10;

/** Base delay once the free allowance is spent; doubles per failure after that. */
const BASE_LOCKOUT_MS = 30_000;

/** Ceiling, so a lockout cannot become permanent through arithmetic. */
const MAX_LOCKOUT_MS = 60 * 60_000;

/** A quiet origin is forgotten entirely rather than accruing forever. */
const COUNTER_TTL_MS = 24 * 60 * 60_000;

export class LoginThrottledError extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super(
      `Too many sign-in attempts from this location. Try again in ${retryAfterSeconds}s.`,
    );
    this.name = "LoginThrottledError";
  }
}

@Injectable()
export class LoginThrottleService {
  private readonly logger = new Logger(LoginThrottleService.name);

  /**
   * Rejects the attempt when this origin is in backoff.
   *
   * Called BEFORE any credential check, so a throttled origin cannot use the
   * timing difference between "unknown user" and "wrong password" as an
   * enumeration oracle either.
   */
  async assertNotThrottled(ipAddress?: string | null): Promise<void> {
    if (!ipAddress) return;

    const counter = await idpPrisma.loginAttemptCounter.findUnique({
      where: { ipHash: hashIp(ipAddress) },
    });

    if (counter?.lockedUntil && counter.lockedUntil > new Date()) {
      const retryAfter = Math.ceil(
        (counter.lockedUntil.getTime() - Date.now()) / 1000,
      );
      throw new LoginThrottledError(retryAfter);
    }
  }

  /** Records a failure and extends the backoff once the allowance is spent. */
  async recordFailure(ipAddress?: string | null): Promise<void> {
    if (!ipAddress) return;

    const ipHash = hashIp(ipAddress);
    const now = new Date();

    const existing = await idpPrisma.loginAttemptCounter.findUnique({
      where: { ipHash },
    });

    // An origin that has been quiet for a day starts fresh: yesterday's typos
    // should not contribute to today's lockout.
    const stale =
      existing && now.getTime() - existing.lastSeenAt.getTime() > COUNTER_TTL_MS;

    const attempts = !existing || stale ? 1 : existing.attempts + 1;

    let lockedUntil: Date | null = null;
    if (attempts > FREE_ATTEMPTS) {
      const overage = attempts - FREE_ATTEMPTS;
      const delay = Math.min(
        BASE_LOCKOUT_MS * 2 ** (overage - 1),
        MAX_LOCKOUT_MS,
      );
      lockedUntil = new Date(now.getTime() + delay);
    }

    await idpPrisma.loginAttemptCounter.upsert({
      where: { ipHash },
      create: { ipHash, attempts, lockedUntil },
      update: { attempts, lockedUntil },
    });

    if (lockedUntil) {
      this.logger.warn(
        `Login throttled for an origin after ${attempts} failures; locked until ${lockedUntil.toISOString()}`,
      );
    }
  }

  /**
   * Clears the counter after a successful sign-in.
   *
   * Shared origins are the reason this exists: an office NAT or a university
   * network puts hundreds of legitimate users behind one address, and without
   * a reset their combined typos would eventually lock the building out.
   */
  async recordSuccess(ipAddress?: string | null): Promise<void> {
    if (!ipAddress) return;

    await idpPrisma.loginAttemptCounter
      .deleteMany({ where: { ipHash: hashIp(ipAddress) } })
      .catch(() => {
        // Clearing a counter is best-effort; a failure here must never turn a
        // successful sign-in into an error.
      });
  }

  /** Housekeeping: drop counters for origins that have gone quiet. */
  async purgeStale(): Promise<number> {
    const { count } = await idpPrisma.loginAttemptCounter.deleteMany({
      where: { lastSeenAt: { lt: new Date(Date.now() - COUNTER_TTL_MS) } },
    });
    return count;
  }
}

/**
 * Client addresses are hashed before storage.
 *
 * An IP address is personal data under GDPR, and this table is long-lived and
 * has no business reason to hold the raw value — every operation it supports is
 * an equality lookup, which a hash serves exactly as well.
 */
export function hashIp(ipAddress: string): string {
  return createHash("sha256").update(ipAddress.trim()).digest("base64url");
}

export { FREE_ATTEMPTS, BASE_LOCKOUT_MS, MAX_LOCKOUT_MS };
