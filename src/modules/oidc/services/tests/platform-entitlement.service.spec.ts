import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    platform: { findUnique: vi.fn(), findMany: vi.fn() },
    platformGrant: { findMany: vi.fn() },
    userGroupMember: { findMany: vi.fn() },
  },
  prisma: { tenantSubscription: { findUnique: vi.fn() } },
  runWithTenantSession: vi.fn((_session: unknown, operation: () => unknown) =>
    operation(),
  ),
}));
vi.mock("../../../../common/audit/emit-auth-audit", () => ({
  emitAuthAudit: vi.fn(),
}));

import { idpPrisma, prisma } from "@kannan19302/database";
import { OAuthError } from "../authorization.service";
import { PlatformEntitlementService } from "../platform-entitlement.service";

const tenantPrincipal = {
  realm: "tenant" as const,
  roles: ["tenant-admin"],
  permissions: ["finance.invoice.read"],
  tenantId: "t1",
};

function platform(overrides: Record<string, unknown> = {}) {
  return {
    code: "P3",
    name: "Tenant Applications",
    port: 4003,
    baseUrl: "http://localhost:4003",
    icon: null,
    audience: "PUBLIC",
    requiresTenant: true,
    lifecycle: "ACTIVE",
    surfaceType: "USER_UI",
    isUserFacing: true,
    discoverability: "ENTITLED",
    category: "WORK",
    sortWeight: 30,
    minimumAssurance: null,
    ...overrides,
  };
}

function grant(overrides: Record<string, unknown> = {}) {
  return {
    platformCode: "P3",
    subjectType: "ROLE",
    subjectId: "tenant-admin",
    tenantId: null,
    effect: "ALLOW",
    validFrom: null,
    validUntil: null,
    conditions: {},
    ...overrides,
  };
}

describe("PlatformEntitlementService", () => {
  let service: PlatformEntitlementService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new PlatformEntitlementService();
    vi.mocked(idpPrisma.platformGrant.findMany).mockResolvedValue([] as never);
    vi.mocked(idpPrisma.userGroupMember.findMany).mockResolvedValue([] as never);
    vi.mocked(prisma.tenantSubscription.findUnique).mockResolvedValue(null as never);
  });

  it("keeps the provider control plane closed to tenant wildcard roles", async () => {
    vi.mocked(idpPrisma.platform.findUnique).mockResolvedValue(
      platform({ code: "P2", audience: "INTERNAL", discoverability: "INTERNAL" }) as never,
    );
    vi.mocked(idpPrisma.platformGrant.findMany).mockResolvedValue([
      grant({ platformCode: "P2", subjectId: "*" }),
    ] as never);

    await expect(service.assertMayAccess({
      ...tenantPrincipal,
      roles: ["*"],
      permissions: ["*"],
      platformCode: "P2",
    })).rejects.toThrow(OAuthError);
  });

  it("admits provider staff with concrete control-plane authority", async () => {
    vi.mocked(idpPrisma.platform.findUnique).mockResolvedValue(
      platform({ code: "P2", audience: "INTERNAL", discoverability: "INTERNAL" }) as never,
    );

    await expect(service.assertMayAccess({
      ...tenantPrincipal,
      realm: "provider",
      permissions: ["system.tenant.read"],
      platformCode: "P2",
    })).resolves.toBeUndefined();
  });

  it("admits provider staff with canonical PCC-only authority", async () => {
    vi.mocked(idpPrisma.platform.findUnique).mockResolvedValue(
      platform({ code: "P2", audience: "INTERNAL", discoverability: "INTERNAL" }) as never,
    );

    await expect(service.assertMayAccess({
      ...tenantPrincipal,
      realm: "provider",
      permissions: ["pcc.identity-governance.access"],
      platformCode: "P2",
    })).resolves.toBeUndefined();
  });

  it("honours a tenant-scoped USER grant", async () => {
    vi.mocked(idpPrisma.platform.findUnique).mockResolvedValue(platform() as never);
    vi.mocked(idpPrisma.platformGrant.findMany).mockResolvedValue([
      grant({ subjectType: "USER", subjectId: "u1", tenantId: "t1" }),
    ] as never);

    await expect(service.assertMayAccess({
      ...tenantPrincipal,
      userId: "u1",
      roles: [],
      platformCode: "P3",
    })).resolves.toBeUndefined();
  });

  it("gives a matching DENY precedence over ROLE and PLAN allows", async () => {
    vi.mocked(idpPrisma.platform.findUnique).mockResolvedValue(platform() as never);
    vi.mocked(prisma.tenantSubscription.findUnique).mockResolvedValue({
      planId: "business",
      status: "ACTIVE",
    } as never);
    vi.mocked(idpPrisma.platformGrant.findMany).mockResolvedValue([
      grant(),
      grant({ subjectType: "PLAN", subjectId: "business" }),
      grant({ effect: "DENY", subjectType: "USER", subjectId: "u1", tenantId: "t1" }),
    ] as never);

    await expect(service.assertMayAccess({
      ...tenantPrincipal,
      userId: "u1",
      platformCode: "P3",
    })).rejects.toThrow(OAuthError);
  });

  it("ignores grants outside their validity window", async () => {
    vi.mocked(idpPrisma.platform.findUnique).mockResolvedValue(platform() as never);
    vi.mocked(idpPrisma.platformGrant.findMany).mockResolvedValue([
      grant({ validUntil: new Date("2020-01-01T00:00:00Z") }),
    ] as never);

    await expect(service.assertMayAccess({
      ...tenantPrincipal,
      platformCode: "P3",
    })).rejects.toThrow(OAuthError);
  });

  it("resolves GROUP grants from authoritative membership", async () => {
    vi.mocked(idpPrisma.platform.findUnique).mockResolvedValue(platform() as never);
    vi.mocked(idpPrisma.userGroupMember.findMany).mockResolvedValue([
      { groupId: "g-finance", group: { name: "Finance" } },
    ] as never);
    vi.mocked(idpPrisma.platformGrant.findMany).mockResolvedValue([
      grant({ subjectType: "GROUP", subjectId: "g-finance" }),
    ] as never);

    await expect(service.assertMayAccess({
      ...tenantPrincipal,
      userId: "u1",
      roles: [],
      platformCode: "P3",
    })).resolves.toBeUndefined();
  });

  it("never launches a retired platform even when a grant survives", async () => {
    vi.mocked(idpPrisma.platform.findUnique).mockResolvedValue(
      platform({ code: "P5", lifecycle: "RETIRED", isUserFacing: false }) as never,
    );
    vi.mocked(idpPrisma.platformGrant.findMany).mockResolvedValue([
      grant({ platformCode: "P5" }),
    ] as never);

    await expect(service.assertMayAccess({
      ...tenantPrincipal,
      platformCode: "P5",
    })).rejects.toThrow(OAuthError);
  });

  it("builds the Wizard response with batched catalog, grant and plan reads", async () => {
    vi.mocked(idpPrisma.platform.findMany).mockResolvedValue([
      platform({ code: "P1", name: "Marketing", requiresTenant: false, discoverability: "PUBLIC", sortWeight: 10 }),
      platform(),
      platform({ code: "P8", name: "Developer Platform", sortWeight: 80 }),
    ] as never);
    vi.mocked(idpPrisma.platformGrant.findMany).mockResolvedValue([grant()] as never);

    const result = await service.listEntitledPlatforms(tenantPrincipal);

    expect(result.map((entry) => entry.code)).toEqual(["P1", "P3"]);
    expect(result.every((entry) => entry.launchAllowed)).toBe(true);
    expect(idpPrisma.platform.findMany).toHaveBeenCalledTimes(1);
    expect(idpPrisma.platformGrant.findMany).toHaveBeenCalledTimes(1);
    expect(prisma.tenantSubscription.findUnique).toHaveBeenCalledTimes(1);
  });

  it("returns a public maintenance surface as visible but disabled", async () => {
    vi.mocked(idpPrisma.platform.findMany).mockResolvedValue([
      platform({ code: "P1", requiresTenant: false, discoverability: "PUBLIC", lifecycle: "MAINTENANCE" }),
    ] as never);

    const [result] = await service.listEntitledPlatforms(tenantPrincipal);

    expect(result).toMatchObject({
      code: "P1",
      visibility: "VISIBLE_DISABLED",
      launchAllowed: false,
      reasonCodes: ["PLATFORM_MAINTENANCE"],
    });
  });
});
