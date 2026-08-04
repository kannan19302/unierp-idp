import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuthService } from "../auth.service";

// Mock the database client
vi.mock("@unerp/database", () => {
  return {
    prisma: {
      tenant: {
        findUnique: vi.fn(),
        create: vi.fn(),
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
});

// Mock the auth utilities
vi.mock("@unerp/auth", () => {
  return {
    hashPassword: vi.fn().mockResolvedValue("hashed_pass_123"),
    comparePassword: vi.fn().mockResolvedValue(true),
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
      const { prisma } = await import("@unerp/database");
      vi.mocked(prisma.tenant.findUnique).mockResolvedValue(null);

      const result = await authService.register({
        email: "admin@uni-erp.com",
        password: "AdminPass123!",
        confirmPassword: "AdminPass123!",
        firstName: "Super",
        lastName: "Admin",
        organizationName: "Acme",
      });

      expect(result).toBeDefined();
      expect(result.user.email).toBe("admin@uni-erp.com");
      expect(result.tenant.name).toBe("Acme");
      // Non-production: register surfaces the verification link for dev ergonomics.
      expect(
        (result as { developerVerificationLink?: string })
          .developerVerificationLink,
      ).toContain("/verify-email?token=");
    });
  });

  describe("verifyEmail", () => {
    it("rejects an unknown or expired token", async () => {
      const { prisma } = await import("@unerp/database");
      vi.mocked(prisma.$queryRaw).mockResolvedValue([]);

      await expect(
        authService.verifyEmail({ token: "0".repeat(64) }),
      ).rejects.toThrow("Invalid or expired verification link");
    });

    it("marks the user verified and burns tokens for a valid token", async () => {
      const { prisma } = await import("@unerp/database");
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
      const { prisma } = await import("@unerp/database");
      vi.mocked(prisma.$queryRaw).mockResolvedValue([]);

      await expect(authService.refreshSession("0".repeat(64))).rejects.toThrow(
        "Invalid or expired refresh token",
      );
    });

    it("rejects an expired or inactive session", async () => {
      const { prisma } = await import("@unerp/database");
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
      const { prisma } = await import("@unerp/database");
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
      vi.mocked(idpPrisma.user.findFirst).mockResolvedValue({
        id: "user-123",
        tenantId: "tenant-123",
        email: "admin@uni-erp.com",
        firstName: "Super",
        lastName: "Admin",
        avatar: null,
        tenant: { id: "tenant-123", name: "Acme", slug: "acme" },
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
      const { prisma } = await import("@unerp/database");
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
});
