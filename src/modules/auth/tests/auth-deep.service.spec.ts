import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuthDeepService } from "../auth-deep.service";

vi.mock("@unerp/database", () => ({
  prisma: {
    authApiToken: {
      findMany: vi.fn(),
      create: vi.fn(),
      findFirst: vi.fn(),
      delete: vi.fn(),
    },
    loginHistory: { findMany: vi.fn(), count: vi.fn() },
    userSession: { findMany: vi.fn(), findFirst: vi.fn(), update: vi.fn() },
    setting: { findUnique: vi.fn(), upsert: vi.fn() },
    ipRestriction: {
      findMany: vi.fn(),
      findUnique: vi.fn(),
      create: vi.fn(),
      findFirst: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
    },
  },
  runWithTenantSession: vi.fn((_ctx, cb) => cb()),
}));

const mockDate = new Date("2026-07-27");
vi.setSystemTime(mockDate);

describe("AuthDeepService", () => {
  let service: AuthDeepService;

  beforeEach(() => {
    service = new AuthDeepService();
    vi.clearAllMocks();
  });

  describe("api tokens", () => {
    it("should list api tokens", async () => {
      const mockTokens = [
        {
          id: "1",
          name: "Test",
          scopes: ["*"],
          expiresAt: null,
          lastUsedAt: null,
          createdAt: mockDate,
        },
      ];
      const { prisma } = require("@unerp/database");
      idpPrisma.authApiToken.findMany.mockResolvedValue(mockTokens);
      const result = await service.listApiTokens("tenant-1", "user-1");
      expect(result).toEqual(mockTokens);
      expect(idpPrisma.authApiToken.findMany).toHaveBeenCalledWith({
        where: { tenantId: "tenant-1", userId: "user-1" },
        orderBy: { createdAt: "desc" },
        select: expect.any(Object),
      });
    });

    it("should create an api token", async () => {
      const { prisma } = require("@unerp/database");
      idpPrisma.authApiToken.create.mockResolvedValue({
        id: "1",
        name: "My Token",
        tokenHash: "hash",
        scopes: ["read"],
        expiresAt: null,
      });
      const result = await service.createApiToken("tenant-1", "user-1", {
        name: "My Token",
        scopes: ["read"],
      });
      expect(result.name).toBe("My Token");
      expect(result.token).toBeDefined();
      expect(result.token.length).toBe(64);
    });

    it("should delete an api token", async () => {
      const { prisma } = require("@unerp/database");
      idpPrisma.authApiToken.findFirst.mockResolvedValue({
        id: "1",
        tenantId: "tenant-1",
        userId: "user-1",
      });
      const result = await service.deleteApiToken("tenant-1", "user-1", "1");
      expect(result).toEqual({ message: "Token revoked" });
    });
  });

  describe("login history", () => {
    it("should list login history with pagination", async () => {
      const { prisma } = require("@unerp/database");
      prisma.loginHistory.findMany.mockResolvedValue([]);
      prisma.loginHistory.count.mockResolvedValue(0);
      const result = await service.listLoginHistory("t-1", "u-1", {
        page: 1,
        limit: 50,
      });
      expect(result.page).toBe(1);
      expect(result.total).toBe(0);
    });
  });

  describe("sessions", () => {
    it("should list sessions", async () => {
      const { prisma } = require("@unerp/database");
      idpPrisma.userSession.findMany.mockResolvedValue([]);
      const result = await service.listSessions("t-1", "u-1");
      expect(result).toEqual([]);
    });
  });

  describe("password policy", () => {
    it("should return defaults when no policy set", async () => {
      const { prisma } = require("@unerp/database");
      prisma.setting.findUnique.mockResolvedValue(null);
      const result = await service.getPasswordPolicy("t-1");
      expect(result.minLength).toBe(8);
      expect(result.expiryDays).toBe(90);
    });
  });

  describe("ip allowlist", () => {
    it("should list entries", async () => {
      const { prisma } = require("@unerp/database");
      prisma.ipRestriction.findMany.mockResolvedValue([]);
      const result = await service.listIpAllowlist("t-1");
      expect(result).toEqual([]);
    });
  });
});
