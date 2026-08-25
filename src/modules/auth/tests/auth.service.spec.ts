import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuthService } from "../auth.service";
import { idpPrisma } from "@kannan19302/database";

// Mock the database client
vi.mock("@kannan19302/database", () => {
  // Identity models (user, role, userSession, ...) are read through
  // `idpPrisma`, not `prisma` â€” this spec predates that split and stubs
  // them under `prisma`. Exporting the same stub object under both names
  // keeps every `vi.mocked(prisma.user.*)` setup pointing at exactly the
  // function the service calls.
  const mocked = {
    prisma: {
      tenant: {
        findUnique: vi.fn(),
        create: vi.fn(),
        deleteMany: vi.fn().mockResolvedValue({ count: 1 }),
      },
      user: {
        findFirst: vi.fn(),
        findMany: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
      },
      role: {
        create: vi.fn(),
      },
      userRole: {
        create: vi.fn(),
        findMany: vi.fn(),
      },
      organization: {
        create: vi.fn(),
      },
      department: {
        create: vi.fn(),
      },
      emailVerificationToken: {
        create: vi.fn(),
        updateMany: vi.fn(),
      },
      // register() opens an idpPrisma transaction but writes main-schema models
      // (tenant, organization, department, plan, subscription) through the
      // OUTER `prisma` client, since the IdP client has no delegate for them.
      // They therefore have to be stubbed here, not only on the `tx` object.
      saaSPlan: {
        upsert: vi.fn(),
      },
      tenantSubscription: {
        create: vi.fn(),
      },
      // getRecommendedInstallSlugs() seeds InstalledApp rows for the
      // registering tenant's recommended module set — also written through
      // the OUTER `prisma` client, same reasoning as saaSPlan/tenantSubscription
      // above.
      installedApp: {
        create: vi.fn().mockResolvedValue({}),
      },
      $transaction: vi.fn((cb) =>
        cb({
          $executeRaw: vi.fn().mockResolvedValue(1),
          tenant: {
            create: vi.fn().mockResolvedValue({
              id: "tenant-123",
              name: "Acme",
              slug: "acme",
            }),
          },
          role: {
            create: vi.fn().mockResolvedValue({ id: "role-123" }),
          },
          user: {
            create: vi.fn().mockResolvedValue({
              id: "user-123",
              email: "admin@uni-erp.com",
              firstName: "Super",
              lastName: "Admin",
            }),
          },
          userRole: {
            create: vi.fn().mockResolvedValue({ id: "ur-123" }),
          },
          userIdentity: {
            create: vi.fn().mockResolvedValue({ id: "identity-123" }),
          },
          organization: {
            create: vi.fn().mockResolvedValue({ id: "org-123" }),
          },
          department: {
            create: vi.fn().mockResolvedValue({ id: "dept-123" }),
          },
          emailVerificationToken: {
            create: vi.fn().mockResolvedValue({ id: "evt-123" }),
          },
          saaSPlan: {
            upsert: vi.fn().mockResolvedValue({
              id: "plan-free-trial",
              name: "Free Trial",
            }),
          },
          tenantSubscription: {
            create: vi.fn().mockResolvedValue({ id: "sub-123" }),
          },
        }),
      ),
      $queryRaw: vi.fn().mockResolvedValue([]),
    },
    runWithTenantSession: vi.fn((_session: unknown, fn: () => unknown) => fn()),
  };
  return { ...mocked, idpPrisma: mocked.prisma };
});

// Mock the auth utilities
vi.mock("@kannan19302/auth", () => {
  return {
    hashPassword: vi.fn().mockResolvedValue("hashed_pass_123"),
    comparePassword: vi.fn().mockResolvedValue(true),
    comparePasswordWithRehash: vi.fn().mockResolvedValue({ valid: true, needsRehash: false }),
    checkPasswordBreach: vi.fn().mockResolvedValue(0),
    signToken: vi.fn().mockReturnValue("jwt_token_abc"),
    signSessionToken: vi.fn().mockReturnValue("jwt_session_abc"),
    signTypedToken: vi.fn().mockReturnValue("typed_token_abc"),
    verifyTypedToken: vi.fn().mockReturnValue({ userId: "user-123" }),
    TOKEN_TYPE: {
      SESSION: "session",
      PASSWORD_RESET: "password-reset",
      MFA_CHALLENGE: "mfa-challenge",
    },
  };
});

describe("AuthService", () => {
  let authService: AuthService;

  beforeEach(() => {
    authService = new AuthService();
    vi.clearAllMocks();
  });

  describe("generateOtp", () => {
    it("should generate OTP without using Math.random for cryptographic security", () => {
      const mathRandomSpy = vi.spyOn(Math, "random").mockReturnValue(0.5);

      const otp = (authService as any).generateOtp();

      expect(mathRandomSpy).not.toHaveBeenCalled();
      expect(otp).toMatch(/^[0-9]{6}$/);

      mathRandomSpy.mockRestore();
    });
  });

  describe("register", () => {
    it("should register a tenant and return registration credentials", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.tenant.findUnique).mockResolvedValue(null);
      // NOTE: register() opens `idpPrisma.$transaction` but creates the tenant
      // through the OUTER `prisma` client, because Tenant lives in the main
      // schema and the IdP client's `tx` has no `tenant` delegate. That insert
      // therefore does not participate in the transaction — a failure later in
      // registration leaves an orphan tenant row behind. This stub is on the
      // outer client to match what the code actually calls; the atomicity gap
      // is a consequence of the two-client split and is tracked separately.
      vi.mocked(prisma.tenant.create).mockResolvedValue({
        id: "tenant-123",
        name: "Acme",
        slug: "acme",
      } as never);
      // Same reason: Organization is a main-schema model, so it is created on
      // the outer client too and its id is needed for the department inserts.
      vi.mocked(prisma.organization.create).mockResolvedValue({
        id: "org-123",
      } as never);
      // Registration also starts the 30-day trial: it upserts the shared
      // free-trial plan and creates the tenant's subscription row.
      vi.mocked(prisma.saaSPlan.upsert).mockResolvedValue({
        id: "plan-free",
      } as never);
      vi.mocked(prisma.tenantSubscription.create).mockResolvedValue(
        {} as never,
      );

      const result = await authService.register({
        email: "admin@uni-erp.com",
        password: "AdminPass123!",
        confirmPassword: "AdminPass123!",
        firstName: "Super",
        lastName: "Admin",
        organizationName: "Acme",
        termsAccepted: true,
      });

      expect(result).toBeDefined();
      expect(result.user.email).toBe("admin@uni-erp.com");
      expect(result.tenant.name).toBe("Acme");
      expect(prisma.tenant.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            settings: expect.objectContaining({
              termsAcceptedAt: expect.any(String),
              legalConsent: expect.objectContaining({
                mechanism: "registration_checkbox",
                terms: expect.objectContaining({
                  url: "http://localhost:4001/terms",
                  version: "2026-07-development",
                }),
                privacy: expect.objectContaining({
                  url: "http://localhost:4001/privacy",
                  version: "2026-07-development",
                }),
              }),
            }),
          }),
        }),
      );
      // Non-production: register surfaces the verification link for dev ergonomics.
      expect(
        (result as { developerVerificationLink?: string })
          .developerVerificationLink,
      ).toContain("/verify-email?token=");
    });

    it("registers a verified passwordless tenant owner from an external identity", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.tenant.findUnique).mockResolvedValue(null);
      vi.mocked(prisma.tenant.create).mockResolvedValue({
        id: "tenant-123",
        name: "Acme",
        slug: "acme",
      } as never);
      vi.mocked(prisma.organization.create).mockResolvedValue({
        id: "org-123",
      } as never);
      vi.mocked(prisma.saaSPlan.upsert).mockResolvedValue({
        id: "plan-free",
      } as never);
      vi.mocked(prisma.tenantSubscription.create).mockResolvedValue({} as never);

      const result = await authService.register({
        email: "owner@example.com",
        firstName: "External",
        lastName: "Owner",
        organizationName: "Acme",
        termsAccepted: true,
        externalIdentity: {
          provider: "google",
          subject: "google-subject-123",
        },
      });

      expect(result.user.id).toBe("user-123");
      expect(
        (result as { developerVerificationLink?: string })
          .developerVerificationLink,
      ).toBeUndefined();
    });

    it("compensates a newly-created tenant when identity provisioning fails", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.tenant.findUnique).mockResolvedValue(null);
      vi.mocked(prisma.tenant.create).mockResolvedValue({
        id: "tenant-compensate",
        name: "Partial Tenant",
        slug: "partial-tenant",
      } as never);
      vi.mocked(idpPrisma.$transaction).mockImplementationOnce(
        (async (operation: (tx: unknown) => unknown) =>
          operation({
            $executeRaw: vi.fn().mockRejectedValue(new Error("identity failure")),
          })) as never,
      );

      await expect(
        authService.register({
          email: "partial@example.com",
          password: "AdminPass123!",
          confirmPassword: "AdminPass123!",
          firstName: "Partial",
          lastName: "Owner",
          organizationName: "Partial Tenant",
          termsAccepted: true,
        }),
      ).rejects.toThrow("identity failure");

      expect(prisma.tenant.deleteMany).toHaveBeenCalledWith({
        where: { id: "tenant-compensate" },
      });
    });
  });

  describe("verifyEmail", () => {
    it("rejects an unknown or expired token", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.$queryRaw).mockResolvedValue([]);

      await expect(
        authService.verifyEmail({ token: "0".repeat(64) }),
      ).rejects.toThrow("Invalid or expired verification link");
    });

    it("marks the user verified and burns tokens for a valid token", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.$queryRaw).mockResolvedValue([
        {
          id: "evt-1",
          user_id: "user-123",
          tenant_id: "tenant-123",
          expires_at: new Date(Date.now() + 60_000),
          used_at: null,
        },
      ] as never);
      vi.mocked(idpPrisma.$transaction).mockResolvedValue([] as never);

      const result = await authService.verifyEmail({ token: "0".repeat(64) });
      expect(result.message).toMatch(/verified/i);
    });
  });

  describe("refreshSession", () => {
    it("rejects an unknown refresh token", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.$queryRaw).mockResolvedValue([]);

      await expect(authService.refreshSession("0".repeat(64))).rejects.toThrow(
        "Invalid or expired refresh token",
      );
    });

    it("rejects an expired or inactive session", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.$queryRaw).mockResolvedValue([
        {
          id: "sess-1",
          user_id: "user-123",
          tenant_id: "tenant-123",
          refresh_expires_at: new Date(Date.now() - 1000),
          is_active: true,
          remember_me: false,
        },
      ] as never);

      await expect(authService.refreshSession("0".repeat(64))).rejects.toThrow(
        "Invalid or expired refresh token",
      );
    });

    it("rotates the refresh token and issues a new access token", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.$queryRaw).mockResolvedValue([
        {
          id: "sess-1",
          user_id: "user-123",
          tenant_id: "tenant-123",
          refresh_expires_at: new Date(Date.now() + 60_000),
          is_active: true,
          remember_me: false,
        },
      ] as never);
      // No `tenant` property: the IdP schema's User has no tenant relation, it
      // carries a bare tenantId. The old fixture asserted a relation that does
      // not exist, which is why the service could read `user.tenant.id` in
      // production and throw while this test passed.
      vi.mocked(idpPrisma.user.findFirst).mockResolvedValue({
        id: "user-123",
        tenantId: "tenant-123",
        email: "admin@uni-erp.com",
        firstName: "Super",
        lastName: "Admin",
        avatar: null,
      } as never);
      // The tenant comes from the main database — § 5.2 keeps identity and
      // business data apart.
      vi.mocked(prisma.tenant.findUnique).mockResolvedValue({
        id: "tenant-123",
        name: "Acme",
        slug: "acme",
      } as never);
      vi.mocked(idpPrisma.userRole.findMany).mockResolvedValue([] as never);
      const sessionUpdate = vi.fn().mockResolvedValue({});
      (
        prisma as unknown as {
          userSession: { update: typeof sessionUpdate };
        }
      ).userSession = { update: sessionUpdate };

      const result = await authService.refreshSession("0".repeat(64));

      expect(result.token).toBe("jwt_session_abc");
      expect(result.refreshToken).toHaveLength(64);
      // Rotation must swap the stored hash.
      expect(sessionUpdate).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: "sess-1" },
          data: expect.objectContaining({
            refreshTokenHash: expect.any(String),
          }),
        }),
      );
    });
  });

  describe("resendVerification", () => {
    it("returns the generic message for unknown emails", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.$queryRaw).mockResolvedValue([]);

      const result = await authService.resendVerification({
        email: "ghost@example.com",
      });
      expect(result.message).toMatch(/If an unverified account exists/);
      expect(
        (result as { developerVerificationLink?: string })
          .developerVerificationLink,
      ).toBeUndefined();
    });
  });

  describe("providerLogin", () => {
    it("selects only the explicitly authorized principal in the provider realm", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.tenant.findUnique).mockResolvedValue({
        id: "tnt-provider",
        slug: "provider",
      } as never);
      vi.mocked(prisma.$queryRaw).mockResolvedValue([
        { id: "user-123", tenant_id: "tenant-123" },
        { id: "provider-user", tenant_id: "tnt-provider" },
      ] as never);
      vi.spyOn(authService, "resolveRolesAndPermissions").mockResolvedValue({
        roles: ["platform.admin"],
        permissions: ["system.superadmin.access"],
      });
      const authenticate = vi
        .spyOn(authService as any, "authenticateInternal")
        .mockResolvedValue({ token: "provider-token" });

      await expect(
        authService.providerLogin({
          email: "kannan19302@gmail.com",
          password: "not-inspected-by-selection",
        }),
      ).resolves.toEqual({ token: "provider-token" });
      expect(authenticate).toHaveBeenCalledWith(
        "tnt-provider",
        expect.objectContaining({ email: "kannan19302@gmail.com" }),
        undefined,
        "provider",
      );
      expect(authService.resolveRolesAndPermissions).toHaveBeenCalledWith(
        "provider-user",
        "tnt-provider",
      );
    });

    it("rejects a provider role attached to a customer identity row", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.tenant.findUnique).mockResolvedValue({
        id: "tnt-provider",
        slug: "provider",
      } as never);
      vi.mocked(prisma.$queryRaw).mockResolvedValue([
        { id: "customer-user", tenant_id: "tenant-123" },
      ] as never);
      const resolve = vi
        .spyOn(authService, "resolveRolesAndPermissions")
        .mockResolvedValue({
          roles: ["platform.admin"],
          permissions: ["pcc.identity-governance.access"],
        });

      await expect(
        authService.providerLogin({
          email: "kannan19302@gmail.com",
          password: "irrelevant",
        }),
      ).rejects.toThrow("Invalid credentials");
      expect(resolve).not.toHaveBeenCalled();
    });

    it("rejects an ordinary tenant role even when the email exists", async () => {
      const { prisma } = await import("@kannan19302/database");
      vi.mocked(prisma.tenant.findUnique).mockResolvedValue({
        id: "tnt-provider",
        slug: "provider",
      } as never);
      vi.mocked(prisma.$queryRaw).mockResolvedValue([
        { id: "user-123", tenant_id: "tenant-123" },
      ] as never);
      vi.spyOn(authService, "resolveRolesAndPermissions").mockResolvedValue({
        roles: ["SUPER_ADMIN"],
        permissions: ["*"],
      });

      await expect(
        authService.providerLogin({
          email: "kannan19302@gmail.com",
          password: "irrelevant",
        }),
      ).rejects.toThrow("Invalid credentials");
    });
  });
});
