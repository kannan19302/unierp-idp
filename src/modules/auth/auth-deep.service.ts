import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
  ForbiddenException,
} from "@nestjs/common";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { randomBytes, createHash } from "node:crypto";

const hashToken = (token: string) =>
  createHash("sha256").update(token).digest("hex");
const generateApiToken = () => randomBytes(32).toString("hex");

@Injectable()
export class AuthDeepService {
  private readonly logger = new Logger(AuthDeepService.name);

  /* ──────────────── API Token Management ──────────────── */

  async listApiTokens(tenantId: string, userId: string) {
    return runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.authApiToken.findMany({
        where: { tenantId, userId },
        orderBy: { createdAt: "desc" },
        select: {
          id: true,
          name: true,
          scopes: true,
          expiresAt: true,
          lastUsedAt: true,
          createdAt: true,
        },
      }),
    );
  }

  async createApiToken(
    tenantId: string,
    userId: string,
    data: { name: string; scopes?: string[]; expiresAt?: string },
  ) {
    const plainToken = generateApiToken();
    const tokenHash = hashToken(plainToken);
    const record = await runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.authApiToken.create({
        data: {
          tenantId,
          userId,
          name: data.name,
          tokenHash,
          scopes: data.scopes ?? ["*"],
          expiresAt: data.expiresAt ? new Date(data.expiresAt) : null,
        },
      }),
    );
    return {
      id: record.id,
      name: record.name,
      token: plainToken,
      scopes: record.scopes,
      expiresAt: record.expiresAt,
    };
  }

  async deleteApiToken(tenantId: string, userId: string, tokenId: string) {
    const token = await runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.authApiToken.findFirst({
        where: { id: tokenId, tenantId, userId },
      }),
    );
    if (!token) throw new NotFoundException("API token not found");
    await idpPrisma.authApiToken.delete({ where: { id: tokenId } });
    return { message: "Token revoked" };
  }

  /* ──────────────── Login History Viewer ──────────────── */

  async listLoginHistory(
    tenantId: string,
    userId: string,
    query: {
      page?: number;
      limit?: number;
      from?: string;
      to?: string;
      status?: string;
    },
  ) {
    const page = query.page ?? 1;
    const limit = Math.min(query.limit ?? 50, 100);
    const where: any = { tenantId };
    if (userId) where.userId = userId;
    if (query.status) where.status = query.status;
    if (query.from || query.to) {
      where.createdAt = {};
      if (query.from) where.createdAt.gte = new Date(query.from);
      if (query.to) where.createdAt.lte = new Date(query.to);
    }
    return runWithTenantSession({ tenantId, userId }, async () => {
      const [items, total] = await Promise.all([
        prisma.loginHistory.findMany({
          where,
          orderBy: { createdAt: "desc" },
          skip: (page - 1) * limit,
          take: limit,
        }),
        prisma.loginHistory.count({ where }),
      ]);
      return {
        items,
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      };
    });
  }

  /* ──────────────── Session Management ──────────────── */

  async listSessions(tenantId: string, userId: string, currentSid?: string) {
    const sessions = await idpPrisma.userSession.findMany({
      where: { tenantId, userId, isActive: true },
      orderBy: { lastActivityAt: "desc" },
    });
    return sessions.map((s) => ({
      id: s.id,
      device: s.device,
      browser: s.browser,
      ipAddress: s.ipAddress,
      location: s.location,
      startedAt: s.startedAt,
      lastActivityAt: s.lastActivityAt,
      isCurrent: s.id === currentSid,
      expiresAt: s.expiresAt,
    }));
  }

  async revokeSessionById(tenantId: string, userId: string, sessionId: string) {
    const session = await idpPrisma.userSession.findFirst({
      where: { id: sessionId, tenantId, userId, isActive: true },
    });
    if (!session) throw new NotFoundException("Session not found");
    await idpPrisma.userSession.update({
      where: { id: sessionId },
      data: { isActive: false, refreshTokenHash: null },
    });
    return { message: "Session revoked" };
  }

  /* ──────────────── Password Policy ──────────────── */

  async getPasswordPolicy(tenantId: string) {
    const setting = await prisma.setting.findUnique({
      where: { tenantId_key: { tenantId, key: "password_policy" } },
    });
    const defaults = {
      minLength: 8,
      requireUppercase: true,
      requireLowercase: true,
      requireNumber: true,
      requireSpecial: true,
      expiryDays: 90,
      historyCount: 5,
    };
    if (!setting) return defaults;
    return { ...defaults, ...(setting.value as object) };
  }

  async updatePasswordPolicy(
    tenantId: string,
    data: Partial<{
      minLength: number;
      requireUppercase: boolean;
      requireLowercase: boolean;
      requireNumber: boolean;
      requireSpecial: boolean;
      expiryDays: number;
      historyCount: number;
    }>,
  ) {
    const current = await this.getPasswordPolicy(tenantId);
    const merged = { ...current, ...data };
    await prisma.setting.upsert({
      where: { tenantId_key: { tenantId, key: "password_policy" } },
      create: {
        tenantId,
        key: "password_policy",
        value: merged as any,
        category: "security",
      },
      update: { value: merged as any },
    });
    return merged;
  }

  /* ──────────────── IP Allowlisting ──────────────── */

  async listIpAllowlist(tenantId: string) {
    return prisma.ipRestriction.findMany({
      where: { tenantId, ruleType: "ALLOW", isActive: true },
      orderBy: { createdAt: "desc" },
    });
  }

  async createIpAllowlistEntry(
    tenantId: string,
    data: { ipRange: string; description?: string },
  ) {
    const existing = await prisma.ipRestriction.findUnique({
      where: { tenantId_ipRange: { tenantId, ipRange: data.ipRange } },
    });
    if (existing) throw new BadRequestException("IP range already exists");
    return prisma.ipRestriction.create({
      data: {
        tenantId,
        ipRange: data.ipRange,
        description: data.description,
        ruleType: "ALLOW",
      },
    });
  }

  async updateIpAllowlistEntry(
    tenantId: string,
    id: string,
    data: { ipRange?: string; description?: string; isActive?: boolean },
  ) {
    const entry = await prisma.ipRestriction.findFirst({
      where: { id, tenantId },
    });
    if (!entry) throw new NotFoundException("IP allowlist entry not found");
    return prisma.ipRestriction.update({ where: { id }, data });
  }

  async deleteIpAllowlistEntry(tenantId: string, id: string) {
    const entry = await prisma.ipRestriction.findFirst({
      where: { id, tenantId },
    });
    if (!entry) throw new NotFoundException("IP allowlist entry not found");
    await prisma.ipRestriction.delete({ where: { id } });
    return { message: "IP allowlist entry removed" };
  }
}
