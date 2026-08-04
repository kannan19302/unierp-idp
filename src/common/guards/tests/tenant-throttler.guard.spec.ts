import { describe, it, expect } from "vitest";
import {
  TENANT_PLAN_LIMITS,
  TenantThrottlerGuard,
} from "../tenant-throttler.guard";
import { InMemoryThrottlerStorage } from "../tenant-throttler-storage";

describe("TENANT_PLAN_LIMITS", () => {
  it("free tier has lowest limits", () => {
    expect(TENANT_PLAN_LIMITS.free.short).toBeLessThan(
      TENANT_PLAN_LIMITS.starter.short,
    );
    expect(TENANT_PLAN_LIMITS.free.medium).toBeLessThan(
      TENANT_PLAN_LIMITS.starter.medium,
    );
  });

  it("enterprise tier has highest limits", () => {
    expect(TENANT_PLAN_LIMITS.enterprise.short).toBeGreaterThan(
      TENANT_PLAN_LIMITS.business.short,
    );
    expect(TENANT_PLAN_LIMITS.enterprise.medium).toBeGreaterThan(
      TENANT_PLAN_LIMITS.business.medium,
    );
  });

  it("every tier defines both short and medium buckets", () => {
    for (const [tier, limits] of Object.entries(TENANT_PLAN_LIMITS)) {
      expect(limits.short).toBeTypeOf("number");
      expect(limits.medium).toBeTypeOf("number");
    }
  });
});

describe("TenantThrottlerGuard", () => {
  describe("getTracker", () => {
    it("uses tenant: prefix for authenticated users", async () => {
      const guard = new (class extends TenantThrottlerGuard {
        constructor() {
          super({ throttlers: [] }, {} as any, {} as any);
        }
      })();
      const req = { user: { tenantId: "tenant-123" } };
      const tracker = await guard.getTracker(req);
      expect(tracker).toBe("tenant:tenant-123");
    });

    it("uses apikey: prefix for API key requests", async () => {
      const guard = new (class extends TenantThrottlerGuard {
        constructor() {
          super({ throttlers: [] }, {} as any, {} as any);
        }
      })();
      const req = {
        user: { tenantId: "tenant-123", userId: "apikey:key-456" },
      };
      const tracker = await guard.getTracker(req);
      expect(tracker).toBe("apikey:tenant-123:apikey:key-456");
    });

    it("uses ip: prefix for unauthenticated requests", async () => {
      const guard = new (class extends TenantThrottlerGuard {
        constructor() {
          super({ throttlers: [] }, {} as any, {} as any);
        }
      })();
      const req = { ip: "192.168.1.1" };
      const tracker = await guard.getTracker(req);
      expect(tracker).toBe("ip:192.168.1.1");
    });
  });
});

describe("InMemoryThrottlerStorage", () => {
  it("returns 1 hit on first increment", async () => {
    const storage = new InMemoryThrottlerStorage();
    const result = await storage.increment("test:key", 1000, 10, 1000, "short");
    expect(result.totalHits).toBe(1);
    expect(result.isBlocked).toBe(false);
  });

  it("blocks when limit exceeded", async () => {
    const storage = new InMemoryThrottlerStorage();
    await storage.increment("test:block", 1000, 2, 1000, "short");
    await storage.increment("test:block", 1000, 2, 1000, "short");
    const result = await storage.increment(
      "test:block",
      1000,
      2,
      1000,
      "short",
    );
    expect(result.totalHits).toBe(3);
    expect(result.isBlocked).toBe(true);
  });

  it("expires after ttl and resets", async () => {
    const storage = new InMemoryThrottlerStorage();
    await storage.increment("test:expire", 100, 2, 1000, "short");
    await new Promise((r) => setTimeout(r, 110));

    const result = await storage.increment(
      "test:expire",
      100,
      2,
      1000,
      "short",
    );
    expect(result.totalHits).toBe(1);
    expect(result.isBlocked).toBe(false);
  });

  it("keys are isolated", async () => {
    const storage = new InMemoryThrottlerStorage();
    await storage.increment("tenant-a", 1000, 2, 1000, "short");
    await storage.increment("tenant-a", 1000, 2, 1000, "short");

    const resultA = await storage.increment("tenant-a", 1000, 2, 1000, "short");
    expect(resultA.isBlocked).toBe(true);

    const resultB = await storage.increment("tenant-b", 1000, 2, 1000, "short");
    expect(resultB.totalHits).toBe(1);
    expect(resultB.isBlocked).toBe(false);
  });
});
