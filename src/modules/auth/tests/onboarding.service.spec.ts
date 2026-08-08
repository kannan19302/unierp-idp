import { describe, it, expect, vi, beforeEach } from "vitest";
import { OnboardingService } from "../onboarding.service";
import { NotFoundException, BadRequestException } from "@nestjs/common";

// Mock the database client
vi.mock("@kannan19302/database", () => {
  const mockTenantUpdate = vi.fn();
  const mockTenantFindUnique = vi.fn();
  const mockOrgFindFirst = vi.fn();
  const mockCustomerCreate = vi.fn();
  const mockVendorCreate = vi.fn();
  const mockProductCreate = vi.fn();
  const mockUserFindFirst = vi.fn();
  const mockUserCount = vi.fn();
  const mockInstalledAppCount = vi.fn();
  const mockSubscriptionFindUnique = vi.fn();

  // Identity models (user, role, userSession, ...) are read through
  // `idpPrisma`, not `prisma` — this spec predates that split and stubs
  // them under `prisma`. Exporting the same stub object under both names
  // keeps every `vi.mocked(prisma.user.*)` setup pointing at exactly the
  // function the service calls.
  const mocked = {
    prisma: {
      tenant: {
        findUnique: mockTenantFindUnique,
        update: mockTenantUpdate,
      },
      user: {
        findFirst: mockUserFindFirst,
        count: mockUserCount,
      },
      installedApp: {
        count: mockInstalledAppCount,
      },
      tenantSubscription: {
        findUnique: mockSubscriptionFindUnique,
      },
      organization: {
        findFirst: mockOrgFindFirst,
      },
      customer: {
        create: mockCustomerCreate,
      },
      vendor: {
        create: mockVendorCreate,
      },
      product: {
        create: mockProductCreate,
      },
      $transaction: vi.fn(async (cb) => {
        const tx = {
          $executeRaw: vi.fn().mockResolvedValue(1),
          customer: {
            create: mockCustomerCreate,
          },
          vendor: {
            create: mockVendorCreate,
          },
          product: {
            create: mockProductCreate,
          },
          tenant: {
            update: mockTenantUpdate,
          },
        };
        return cb(tx);
      }),
    },
  };
  return { ...mocked, idpPrisma: mocked.prisma };
});

// Helper to access mock functions
import { idpPrisma, prisma } from "@kannan19302/database";
const tenantMocks = prisma.tenant as any;
const orgMocks = prisma.organization as any;
const userMocks = prisma.user as any;
const installedAppMocks = prisma.installedApp as any;
const subscriptionMocks = prisma.tenantSubscription as any;

function mockRealStateDefaults() {
  userMocks.findFirst.mockResolvedValue({ avatar: null });
  userMocks.count.mockResolvedValue(0);
  installedAppMocks.count.mockResolvedValue(0);
  subscriptionMocks.findUnique.mockResolvedValue(null);
}

describe("OnboardingService", () => {
  let service: OnboardingService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new OnboardingService();
  });

  describe("getOnboardingState", () => {
    beforeEach(() => {
      mockRealStateDefaults();
    });

    it("should throw NotFoundException if tenant does not exist", async () => {
      tenantMocks.findUnique.mockResolvedValue(null);
      await expect(service.getOnboardingState("t-none", "u1")).rejects.toThrow(
        NotFoundException,
      );
    });

    it("should derive all steps as false with no real backend state", async () => {
      tenantMocks.findUnique.mockResolvedValue({ id: "t1", settings: {} });

      const res = await service.getOnboardingState("t1", "u1");
      expect(res.profile).toBe(false);
      expect(res.logo).toBe(false);
      expect(res.invite).toBe(false);
      expect(res.app).toBe(false);
      expect(res.plan).toBe(false);
      expect(res.dashboard).toBe(false);
      // No more implicit tenant.settings writes just to read state.
      expect(tenantMocks.update).not.toHaveBeenCalled();
    });

    it("profile: true iff the requesting user has an avatar", async () => {
      tenantMocks.findUnique.mockResolvedValue({ id: "t1", settings: {} });
      userMocks.findFirst.mockResolvedValue({ avatar: "https://x/a.png" });

      const res = await service.getOnboardingState("t1", "u1");
      expect(res.profile).toBe(true);
      expect(userMocks.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: "u1", tenantId: "t1" } }),
      );
    });

    it("logo: true iff tenant.settings.logoUrl is a non-empty string", async () => {
      tenantMocks.findUnique.mockResolvedValue({
        id: "t1",
        settings: { logoUrl: "https://cdn/logo.png" },
      });

      const res = await service.getOnboardingState("t1", "u1");
      expect(res.logo).toBe(true);
    });

    it("logo: false when logoUrl is empty string", async () => {
      tenantMocks.findUnique.mockResolvedValue({
        id: "t1",
        settings: { logoUrl: "" },
      });

      const res = await service.getOnboardingState("t1", "u1");
      expect(res.logo).toBe(false);
    });

    it("invite: true iff another INVITED or ACTIVE user exists in the tenant", async () => {
      tenantMocks.findUnique.mockResolvedValue({ id: "t1", settings: {} });
      userMocks.count.mockResolvedValue(1);

      const res = await service.getOnboardingState("t1", "u1");
      expect(res.invite).toBe(true);
      expect(userMocks.count).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tenantId: "t1",
            id: { not: "u1" },
            status: { in: ["INVITED", "ACTIVE"] },
          }),
        }),
      );
    });

    it("app: false when only CATALOG apps are installed (query filters to MARKETPLACE only)", async () => {
      tenantMocks.findUnique.mockResolvedValue({ id: "t1", settings: {} });
      // installedApp.count is scoped to source: "MARKETPLACE" in the query,
      // so a tenant with only CATALOG installs resolves to 0 here.
      installedAppMocks.count.mockResolvedValue(0);

      const res = await service.getOnboardingState("t1", "u1");
      expect(res.app).toBe(false);
      expect(installedAppMocks.count).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { tenantId: "t1", source: "MARKETPLACE" },
        }),
      );
    });

    it("app: true when a MARKETPLACE app is installed", async () => {
      tenantMocks.findUnique.mockResolvedValue({ id: "t1", settings: {} });
      installedAppMocks.count.mockResolvedValue(1);

      const res = await service.getOnboardingState("t1", "u1");
      expect(res.app).toBe(true);
    });

    it("plan: false on the free plan", async () => {
      tenantMocks.findUnique.mockResolvedValue({ id: "t1", settings: {} });
      subscriptionMocks.findUnique.mockResolvedValue({
        id: "sub1",
        plan: { name: "Free" },
      });

      const res = await service.getOnboardingState("t1", "u1");
      expect(res.plan).toBe(false);
    });

    it("plan: true on a paid plan", async () => {
      tenantMocks.findUnique.mockResolvedValue({ id: "t1", settings: {} });
      subscriptionMocks.findUnique.mockResolvedValue({
        id: "sub1",
        plan: { name: "Pro" },
      });

      const res = await service.getOnboardingState("t1", "u1");
      expect(res.plan).toBe(true);
    });

    it("dashboard: reflects the persisted flag from tenant.settings", async () => {
      tenantMocks.findUnique.mockResolvedValue({
        id: "t1",
        settings: { onboardingChecklist: { dashboard: true } },
      });

      const res = await service.getOnboardingState("t1", "u1");
      expect(res.dashboard).toBe(true);
    });
  });

  describe("completeStep", () => {
    beforeEach(() => {
      mockRealStateDefaults();
    });

    it("should throw BadRequestException if step key is invalid", async () => {
      await expect(
        service.completeStep("t1", "u1", "invalid-key"),
      ).rejects.toThrow(BadRequestException);
    });

    it("should throw BadRequestException for derived keys (profile, logo, invite, app, plan)", async () => {
      for (const key of ["profile", "logo", "invite", "app", "plan"]) {
        await expect(service.completeStep("t1", "u1", key)).rejects.toThrow(
          BadRequestException,
        );
      }
      expect(tenantMocks.findUnique).not.toHaveBeenCalled();
    });

    it("should mark dashboard as true and persist it", async () => {
      tenantMocks.findUnique
        .mockResolvedValueOnce({ id: "t1", settings: {} }) // completeStep lookup
        .mockResolvedValueOnce({ id: "t1", settings: {} }); // getOnboardingState refetch
      tenantMocks.update.mockResolvedValue({});

      await service.completeStep("t1", "u1", "dashboard");
      expect(tenantMocks.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: "t1" },
          data: {
            settings: expect.objectContaining({
              onboardingChecklist: expect.objectContaining({
                dashboard: true,
              }),
            }),
          },
        }),
      );
    });
  });
});
