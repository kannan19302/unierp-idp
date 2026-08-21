import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    loginAttemptCounter: {
      findUnique: vi.fn(),
      upsert: vi.fn(),
      deleteMany: vi.fn(),
    },
  },
  prisma: {},
  runWithTenantSession: vi.fn((_s: unknown, fn: () => unknown) => fn()),
}));

import { idpPrisma } from "@kannan19302/database";
import {
  LoginThrottleService,
  LoginThrottledError,
  hashIp,
  FREE_ATTEMPTS,
  MAX_LOCKOUT_MS,
} from "../login-throttle.service";

const IP = "203.0.113.7";

describe("LoginThrottleService", () => {
  let service: LoginThrottleService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new LoginThrottleService();
    vi.mocked(idpPrisma.loginAttemptCounter.deleteMany).mockResolvedValue({
      count: 0,
    } as never);
  });

  describe("privacy", () => {
    it("stores a hash, never the raw address", async () => {
      vi.mocked(idpPrisma.loginAttemptCounter.findUnique).mockResolvedValue(
        null as never,
      );

      await service.recordFailure(IP);

      const written = vi.mocked(idpPrisma.loginAttemptCounter.upsert).mock
        .calls[0][0] as { where: { ipHash: string } };

      expect(written.where.ipHash).toBe(hashIp(IP));
      expect(JSON.stringify(written)).not.toContain(IP);
    });
  });

  describe("assertNotThrottled", () => {
    it("allows an origin with no history", async () => {
      vi.mocked(idpPrisma.loginAttemptCounter.findUnique).mockResolvedValue(
        null as never,
      );
      await expect(service.assertNotThrottled(IP)).resolves.toBeUndefined();
    });

    it("allows an origin whose lockout has elapsed", async () => {
      vi.mocked(idpPrisma.loginAttemptCounter.findUnique).mockResolvedValue({
        attempts: 20,
        lockedUntil: new Date(Date.now() - 1000),
      } as never);
      await expect(service.assertNotThrottled(IP)).resolves.toBeUndefined();
    });

    it("rejects an origin still in backoff and says how long to wait", async () => {
      vi.mocked(idpPrisma.loginAttemptCounter.findUnique).mockResolvedValue({
        attempts: 20,
        lockedUntil: new Date(Date.now() + 45_000),
      } as never);

      const err = (await service
        .assertNotThrottled(IP)
        .catch((e) => e)) as LoginThrottledError;

      expect(err).toBeInstanceOf(LoginThrottledError);
      expect(err.retryAfterSeconds).toBeGreaterThan(40);
      expect(err.retryAfterSeconds).toBeLessThanOrEqual(45);
    });

    it("does nothing when the address is unknown", async () => {
      await expect(service.assertNotThrottled(undefined)).resolves.toBeUndefined();
      await expect(service.assertNotThrottled(null)).resolves.toBeUndefined();
      expect(idpPrisma.loginAttemptCounter.findUnique).not.toHaveBeenCalled();
    });
  });

  describe("backoff", () => {
    it("imposes no delay within the free allowance", async () => {
      // A person mistyping a password must not be locked out.
      vi.mocked(idpPrisma.loginAttemptCounter.findUnique).mockResolvedValue({
        attempts: FREE_ATTEMPTS - 2,
        lastSeenAt: new Date(),
      } as never);

      await service.recordFailure(IP);

      const written = vi.mocked(idpPrisma.loginAttemptCounter.upsert).mock
        .calls[0][0] as { update: { lockedUntil: Date | null } };
      expect(written.update.lockedUntil).toBeNull();
    });

    it("starts locking once the allowance is spent", async () => {
      vi.mocked(idpPrisma.loginAttemptCounter.findUnique).mockResolvedValue({
        attempts: FREE_ATTEMPTS,
        lastSeenAt: new Date(),
      } as never);

      await service.recordFailure(IP);

      const written = vi.mocked(idpPrisma.loginAttemptCounter.upsert).mock
        .calls[0][0] as { update: { lockedUntil: Date | null } };
      expect(written.update.lockedUntil).toBeInstanceOf(Date);
    });

    it("doubles the delay with each further failure", async () => {
      const delays: number[] = [];
      for (const attempts of [FREE_ATTEMPTS, FREE_ATTEMPTS + 1, FREE_ATTEMPTS + 2]) {
        vi.mocked(idpPrisma.loginAttemptCounter.findUnique).mockResolvedValue({
          attempts,
          lastSeenAt: new Date(),
        } as never);
        const before = Date.now();
        await service.recordFailure(IP);
        const call = vi.mocked(idpPrisma.loginAttemptCounter.upsert).mock
          .calls.at(-1)![0] as { update: { lockedUntil: Date } };
        delays.push(call.update.lockedUntil.getTime() - before);
      }

      expect(delays[1]).toBeGreaterThan(delays[0] * 1.8);
      expect(delays[2]).toBeGreaterThan(delays[1] * 1.8);
    });

    it("caps the delay so a lockout cannot become permanent", async () => {
      // 2**n grows fast; without a ceiling a determined sweep would lock an
      // origin out for centuries, including whoever legitimately shares it.
      vi.mocked(idpPrisma.loginAttemptCounter.findUnique).mockResolvedValue({
        attempts: FREE_ATTEMPTS + 40,
        lastSeenAt: new Date(),
      } as never);

      const before = Date.now();
      await service.recordFailure(IP);

      const call = vi.mocked(idpPrisma.loginAttemptCounter.upsert).mock
        .calls[0][0] as { update: { lockedUntil: Date } };
      expect(call.update.lockedUntil.getTime() - before).toBeLessThanOrEqual(
        MAX_LOCKOUT_MS + 1000,
      );
    });

    it("forgets an origin that has been quiet for a day", async () => {
      vi.mocked(idpPrisma.loginAttemptCounter.findUnique).mockResolvedValue({
        attempts: 50,
        lastSeenAt: new Date(Date.now() - 25 * 60 * 60_000),
      } as never);

      await service.recordFailure(IP);

      const written = vi.mocked(idpPrisma.loginAttemptCounter.upsert).mock
        .calls[0][0] as { update: { attempts: number; lockedUntil: Date | null } };
      expect(written.update.attempts).toBe(1);
      expect(written.update.lockedUntil).toBeNull();
    });
  });

  describe("recordSuccess", () => {
    it("clears the counter so a shared office address is not locked out", async () => {
      await service.recordSuccess(IP);
      expect(idpPrisma.loginAttemptCounter.deleteMany).toHaveBeenCalledWith({
        where: { ipHash: hashIp(IP) },
      });
    });

    it("never turns a successful sign-in into an error", async () => {
      vi.mocked(idpPrisma.loginAttemptCounter.deleteMany).mockRejectedValue(
        new Error("database unavailable"),
      );
      await expect(service.recordSuccess(IP)).resolves.toBeUndefined();
    });
  });
});
