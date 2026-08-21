import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createHash } from "node:crypto";
import { OtpStore, MAX_ATTEMPTS } from "../otp.store";

/**
 * Exercises the in-process fallback path (no REDIS_URL). The Redis path shares
 * every branch except storage, and is covered end-to-end when the service runs
 * against the compose stack.
 */
describe("OtpStore (in-process fallback)", () => {
  let store: OtpStore;
  const EMAIL = "Ada@Example.test";

  beforeEach(() => {
    delete process.env.REDIS_URL;
    store = new OtpStore();
  });

  afterEach(async () => {
    await store.onModuleDestroy();
  });

  it("accepts the issued code", async () => {
    await store.issue(EMAIL, "123456");
    await expect(store.verify(EMAIL, "123456")).resolves.toEqual({ ok: true });
  });

  it("normalises the email, so case and padding do not lose the code", async () => {
    await store.issue(EMAIL, "123456");
    await expect(store.verify("  ada@example.test ", "123456")).resolves.toEqual({
      ok: true,
    });
  });

  it("consumes the code, so it cannot be replayed", async () => {
    await store.issue(EMAIL, "123456");
    await store.verify(EMAIL, "123456");
    await expect(store.verify(EMAIL, "123456")).resolves.toEqual({
      ok: false,
      reason: "missing",
    });
  });

  it("reports a missing code rather than throwing", async () => {
    await expect(store.verify("nobody@example.test", "000000")).resolves.toEqual({
      ok: false,
      reason: "missing",
    });
  });

  it("rejects a wrong code", async () => {
    await store.issue(EMAIL, "123456");
    await expect(store.verify(EMAIL, "999999")).resolves.toEqual({
      ok: false,
      reason: "mismatch",
    });
  });

  it("stores the code hashed, not in clear text", async () => {
    // The store is short-lived but it still holds a credential; whoever can
    // read it should not be able to complete someone else's verification.
    await store.issue(EMAIL, "123456");
    const serialised = JSON.stringify([
      ...(store as unknown as { memory: Map<string, unknown> }).memory,
    ]);

    expect(serialised).not.toContain("123456");
    expect(serialised).toContain(
      createHash("sha256").update("123456").digest("base64url"),
    );
  });

  it("counts a failed guess against the attempt limit", async () => {
    // Incrementing only on success would mean the limit never applied to the
    // guesses an attacker actually makes.
    await store.issue(EMAIL, "123456");

    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      await store.verify(EMAIL, "000000");
    }

    await expect(store.verify(EMAIL, "123456")).resolves.toEqual({
      ok: false,
      reason: "too-many-attempts",
    });
  });

  it("discards the code once the attempt limit is passed", async () => {
    await store.issue(EMAIL, "123456");
    for (let i = 0; i <= MAX_ATTEMPTS; i++) {
      await store.verify(EMAIL, "000000");
    }
    await expect(store.verify(EMAIL, "123456")).resolves.toEqual({
      ok: false,
      reason: "missing",
    });
  });

  it("expires a code after its lifetime", async () => {
    vi.useFakeTimers();
    try {
      await store.issue(EMAIL, "123456");
      vi.advanceTimersByTime(6 * 60 * 1000);
      await expect(store.verify(EMAIL, "123456")).resolves.toEqual({
        ok: false,
        reason: "missing",
      });
    } finally {
      vi.useRealTimers();
    }
  });

  describe("resend cooldown", () => {
    it("blocks an immediate resend", async () => {
      // Each resend sends an email on an unauthenticated caller's say-so.
      await store.issue(EMAIL, "123456");
      await expect(store.secondsUntilResendAllowed(EMAIL)).resolves.toBeGreaterThan(
        0,
      );
    });

    it("allows a resend once the cooldown elapses", async () => {
      vi.useFakeTimers();
      try {
        await store.issue(EMAIL, "123456");
        vi.advanceTimersByTime(61_000);
        await expect(store.secondsUntilResendAllowed(EMAIL)).resolves.toBe(0);
      } finally {
        vi.useRealTimers();
      }
    });

    it("allows a first send when nothing is outstanding", async () => {
      await expect(
        store.secondsUntilResendAllowed("fresh@example.test"),
      ).resolves.toBe(0);
    });
  });

  it("clears a code on demand", async () => {
    await store.issue(EMAIL, "123456");
    await store.clear(EMAIL);
    await expect(store.verify(EMAIL, "123456")).resolves.toEqual({
      ok: false,
      reason: "missing",
    });
  });
});
