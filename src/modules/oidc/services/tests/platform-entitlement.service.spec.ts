import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    platform: { findUnique: vi.fn(), findMany: vi.fn() },
    platformGrant: { findFirst: vi.fn() },
  },
  prisma: {
    tenantSubscription: { findUnique: vi.fn() },
  },
  runWithTenantSession: vi.fn((_s: unknown, fn: () => unknown) => fn()),
}));

import { idpPrisma, prisma } from "@kannan19302/database";
import { PlatformEntitlementService } from "../platform-entitlement.service";
import { OAuthError } from "../authorization.service";

const tenantUser = {
  platformCode: "P2",
  realm: "tenant" as const,
  roles: ["tenant-admin"],
  permissions: ["saas.read", "finance.invoice.read"],
  tenantId: "t1",
};

function internalPlatform() {
  return { audience: "INTERNAL" };
}
function publicPlatform() {
  return { audience: "PUBLIC" };
}

describe("PlatformEntitlementService", () => {
  let service: PlatformEntitlementService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new PlatformEntitlementService();
  });

  // ── The control-plane boundary — unchanged from W1, now data-driven ──────
  describe("internal platforms are never opened by a grant", () => {
    beforeEach(() => {
      vi.mocked(idpPrisma.platform.findUnique).mockResolvedValue(
        internalPlatform() as never,
      );
    });

    it("refuses an ordinary tenant user", async () => {
      await expect(service.assertMayAccess(tenantUser)).rejects.toThrow(
        OAuthError,
      );
      // The boundary must be checked before any grant lookup — a grant table
      // existing must never become a second way to reach the control plane.
      expect(idpPrisma.platformGrant.findFirst).not.toHaveBeenCalled();
    });

    it("refuses a tenant super-admin holding the wildcard permission", async () => {
      await expect(
        service.assertMayAccess({
          ...tenantUser,
          permissions: ["*"],
          realm: "tenant",
        }),
      ).rejects.toThrow(/not permitted/);
    });

    it("refuses a wildcard even under a forged provider realm claim", async () => {
      await expect(
        service.assertMayAccess({
          ...tenantUser,
          permissions: ["*"],
          realm: "provider",
        }),
      ).rejects.toThrow(OAuthError);
    });

    it("admits provider staff holding a system.* permission", async () => {
      await expect(
        service.assertMayAccess({
          ...tenantUser,
          permissions: ["system.tenant.read"],
          realm: "provider",
        }),
      ).resolves.toBeUndefined();
    });

    it("admits provider staff holding a platform.* permission", async () => {
      await expect(
        service.assertMayAccess({
          ...tenantUser,
          permissions: ["platform.sre.read"],
          realm: "provider",
        }),
      ).resolves.toBeUndefined();
    });

    it("is not fooled by a namespace-name prefix that is not actually the namespace", async () => {
      await expect(
        service.assertMayAccess({
          ...tenantUser,
          permissions: ["systemic.read", "platformx.read"],
          realm: "provider",
        }),
      ).rejects.toThrow(OAuthError);
    });
  });

  // ── PUBLIC platforms — grant-based, the new W2 behaviour ──────────────────
  describe("PUBLIC platforms resolve grants", () => {
    beforeEach(() => {
      vi.mocked(idpPrisma.platform.findUnique).mockResolvedValue(
        publicPlatform() as never,
      );
    });

    it("admits when a ROLE grant matches one of the user's roles", async () => {
      vi.mocked(idpPrisma.platformGrant.findFirst).mockResolvedValue({
        id: "g1",
      } as never);

      await expect(
        service.assertMayAccess({ ...tenantUser, platformCode: "P3" }),
      ).resolves.toBeUndefined();

      expect(idpPrisma.platformGrant.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            platformCode: "P3",
            subjectType: "ROLE",
            subjectId: { in: ["*", "tenant-admin"] },
          }),
        }),
      );
    });

    it("admits via the wildcard ROLE grant used for baseline platforms", async () => {
      // seed-platform-entitlement.ts grants subjectId "*" for the platforms
      // every tenant user reaches without a plan upgrade.
      vi.mocked(idpPrisma.platformGrant.findFirst).mockImplementation(
        (async (args: { where: { subjectId: { in: string[] } } }) =>
          args.where.subjectId.in.includes("*") ? { id: "wildcard" } : null) as never,
      );

      await expect(
        service.assertMayAccess({ ...tenantUser, platformCode: "P7" }),
      ).resolves.toBeUndefined();
    });

    it("falls through to the tenant's plan when no ROLE grant matches", async () => {
      vi.mocked(idpPrisma.platformGrant.findFirst)
        .mockResolvedValueOnce(null as never) // ROLE lookup
        .mockResolvedValueOnce({ id: "plan-grant" } as never); // PLAN lookup
      vi.mocked(prisma.tenantSubscription.findUnique).mockResolvedValue({
        planId: "plan-business",
        status: "ACTIVE",
      } as never);

      await expect(
        service.assertMayAccess({ ...tenantUser, platformCode: "P5" }),
      ).resolves.toBeUndefined();

      expect(idpPrisma.platformGrant.findFirst).toHaveBeenLastCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            platformCode: "P5",
            subjectType: "PLAN",
            subjectId: "plan-business",
          }),
        }),
      );
    });

    it("refuses when no ROLE or PLAN grant covers the platform", async () => {
      vi.mocked(idpPrisma.platformGrant.findFirst).mockResolvedValue(
        null as never,
      );
      vi.mocked(prisma.tenantSubscription.findUnique).mockResolvedValue(
        null as never,
      );

      await expect(
        service.assertMayAccess({ ...tenantUser, platformCode: "P5" }),
      ).rejects.toThrow(OAuthError);
    });

    it("does not consult a CANCELED subscription's plan grants", async () => {
      // A lapsed plan must not keep unlocking what it once did.
      vi.mocked(idpPrisma.platformGrant.findFirst).mockResolvedValueOnce(
        null as never,
      );
      vi.mocked(prisma.tenantSubscription.findUnique).mockResolvedValue({
        planId: "plan-business",
        status: "CANCELED",
      } as never);

      await expect(
        service.assertMayAccess({ ...tenantUser, platformCode: "P5" }),
      ).rejects.toThrow(OAuthError);
      // Never even asked whether that plan has a grant.
      expect(idpPrisma.platformGrant.findFirst).toHaveBeenCalledTimes(1);
    });

    it("honours a TRIAL subscription the same as ACTIVE", async () => {
      vi.mocked(idpPrisma.platformGrant.findFirst)
        .mockResolvedValueOnce(null as never)
        .mockResolvedValueOnce({ id: "g" } as never);
      vi.mocked(prisma.tenantSubscription.findUnique).mockResolvedValue({
        planId: "plan-business",
        status: "TRIAL",
      } as never);

      await expect(
        service.assertMayAccess({ ...tenantUser, platformCode: "P5" }),
      ).resolves.toBeUndefined();
    });
  });

  describe("clients with no platform binding", () => {
    it("passes third-party clients through untouched — bounded by scope/consent instead", async () => {
      await expect(
        service.assertMayAccess({ ...tenantUser, platformCode: null }),
      ).resolves.toBeUndefined();
      expect(idpPrisma.platform.findUnique).not.toHaveBeenCalled();
    });
  });

  describe("listEntitledPlatforms", () => {
    it("returns only the platforms the caller is actually entitled to", async () => {
      vi.mocked(idpPrisma.platform.findMany).mockResolvedValue([
        { code: "P2", name: "Provider Admin OS", port: 4002, baseUrl: "http://localhost:4002", icon: null, audience: "INTERNAL" },
        { code: "P3", name: "Tenant Applications", port: 4003, baseUrl: "http://localhost:4003", icon: null, audience: "PUBLIC" },
        { code: "P5", name: "Web Studio", port: 4005, baseUrl: "http://localhost:4005", icon: null, audience: "PUBLIC" },
      ] as never);
      vi.mocked(idpPrisma.platform.findUnique).mockImplementation(
        (async ({ where }: { where: { code: string } }) =>
          where.code === "P2" ? internalPlatform() : publicPlatform()) as never,
      );
      // P3 has a ROLE grant; P5 has neither ROLE nor an active plan grant.
      vi.mocked(idpPrisma.platformGrant.findFirst).mockImplementation(
        (async (args: { where: { platformCode: string } }) =>
          args.where.platformCode === "P3" ? { id: "g" } : null) as never,
      );
      vi.mocked(prisma.tenantSubscription.findUnique).mockResolvedValue(
        null as never,
      );

      const result = await service.listEntitledPlatforms({
        realm: "tenant",
        roles: ["tenant-admin"],
        permissions: [],
        tenantId: "t1",
      });

      expect(result.map((p) => p.code)).toEqual(["P3"]);
    });

    it("includes the control plane for provider staff, alongside public platforms", async () => {
      vi.mocked(idpPrisma.platform.findMany).mockResolvedValue([
        { code: "P2", name: "Provider Admin OS", port: 4002, baseUrl: "x", icon: null, audience: "INTERNAL" },
        { code: "P3", name: "Tenant Applications", port: 4003, baseUrl: "x", icon: null, audience: "PUBLIC" },
      ] as never);
      vi.mocked(idpPrisma.platform.findUnique).mockImplementation(
        (async ({ where }: { where: { code: string } }) =>
          where.code === "P2" ? internalPlatform() : publicPlatform()) as never,
      );
      vi.mocked(idpPrisma.platformGrant.findFirst).mockResolvedValue({
        id: "g",
      } as never);

      const result = await service.listEntitledPlatforms({
        realm: "provider",
        roles: [],
        permissions: ["system.tenant.read"],
        tenantId: "t1",
      });

      expect(result.map((p) => p.code).sort()).toEqual(["P2", "P3"]);
    });
  });
});
