import {
  Controller,
  Get,
  Post,
  Delete,
  Put,
  Body,
  Param,
  Query,
  Req,
  HttpCode,
  HttpStatus,
  UseGuards,
} from "@nestjs/common";
import { ApiTags, ApiOperation, ApiBearerAuth } from "@nestjs/swagger";
import { z } from "zod";
import { ZodBody } from "../../common/decorators/zod-body.decorator";
import { Request } from "express";
import { JwtAuthGuard } from "../../common/guards/jwt-auth.guard";
import { RbacGuard } from "../../common/guards/rbac.guard";
import { Permissions } from "../../common/decorators/permissions.decorator";
import { AuthDeepService } from "./auth-deep.service";

interface AuthenticatedRequest extends Request {
  user: {
    sid?: string;
    userId: string;
    tenantId: string;
    email: string;
    roles: string[];
  };
}

@ApiTags("auth")
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RbacGuard)
@Controller("auth")
export class AuthDeepController {
  constructor(private readonly authDeepService: AuthDeepService) {}

  /* ─── API Token Management ─── */

  @ApiOperation({ summary: "List API tokens" })
  @Get("api-tokens")
  @Permissions("auth.api-token.read")
  async listApiTokens(@Req() req: AuthenticatedRequest) {
    return this.authDeepService.listApiTokens(
      req.user.tenantId,
      req.user.userId,
    );
  }

  @ApiOperation({ summary: "Create API token" })
  @Post("api-tokens")
  @HttpCode(HttpStatus.CREATED)
  @Permissions("auth.api-token.create")
  async createApiToken(
    @Req() req: AuthenticatedRequest,
    @ZodBody(
      z.object({
        name: z.string().min(1).max(100),
        scopes: z.array(z.string()).optional(),
        expiresAt: z.string().optional(),
      }),
    )
    body: { name: string; scopes?: string[]; expiresAt?: string },
  ) {
    return this.authDeepService.createApiToken(
      req.user.tenantId,
      req.user.userId,
      body,
    );
  }

  @ApiOperation({ summary: "Delete API token" })
  @Delete("api-tokens/:id")
  @HttpCode(HttpStatus.OK)
  @Permissions("auth.api-token.delete")
  async deleteApiToken(
    @Req() req: AuthenticatedRequest,
    @Param("id") id: string,
  ) {
    return this.authDeepService.deleteApiToken(
      req.user.tenantId,
      req.user.userId,
      id,
    );
  }

  /* ─── Login History Viewer ─── */

  @ApiOperation({ summary: "List login history with pagination and filters" })
  @Get("login-history")
  @Permissions("auth.login-history.read")
  async listLoginHistory(
    @Req() req: AuthenticatedRequest,
    @Query("page") page?: string,
    @Query("limit") limit?: string,
    @Query("from") from?: string,
    @Query("to") to?: string,
    @Query("status") status?: string,
  ) {
    return this.authDeepService.listLoginHistory(
      req.user.tenantId,
      req.user.userId,
      {
        page: page ? parseInt(page) : 1,
        limit: limit ? parseInt(limit) : 50,
        from,
        to,
        status,
      },
    );
  }

  /* ─── Session Management ─── */

  @ApiOperation({ summary: "List active sessions" })
  @Get("sessions")
  @Permissions("auth.session.read")
  async listSessions(@Req() req: AuthenticatedRequest) {
    return this.authDeepService.listSessions(
      req.user.tenantId,
      req.user.userId,
      req.user.sid,
    );
  }

  @ApiOperation({ summary: "Revoke a specific session" })
  @Delete("sessions/:id")
  @HttpCode(HttpStatus.OK)
  @Permissions("auth.session.revoke")
  async revokeSession(
    @Req() req: AuthenticatedRequest,
    @Param("id") id: string,
  ) {
    return this.authDeepService.revokeSessionById(
      req.user.tenantId,
      req.user.userId,
      id,
    );
  }

  /* ─── Password Policy ─── */

  @ApiOperation({ summary: "Get password policy" })
  @Get("password-policy")
  @Permissions("auth.password-policy.read")
  async getPasswordPolicy(@Req() req: AuthenticatedRequest) {
    return this.authDeepService.getPasswordPolicy(req.user.tenantId);
  }

  @ApiOperation({ summary: "Update password policy" })
  @Put("password-policy")
  @HttpCode(HttpStatus.OK)
  @Permissions("auth.password-policy.update")
  async updatePasswordPolicy(
    @Req() req: AuthenticatedRequest,
    @ZodBody(
      z.object({
        minLength: z.number().int().min(4).max(128).optional(),
        requireUppercase: z.boolean().optional(),
        requireLowercase: z.boolean().optional(),
        requireNumber: z.boolean().optional(),
        requireSpecial: z.boolean().optional(),
        expiryDays: z.number().int().min(0).max(365).optional(),
        historyCount: z.number().int().min(0).max(50).optional(),
      }),
    )
    body: Partial<{
      minLength: number;
      requireUppercase: boolean;
      requireLowercase: boolean;
      requireNumber: boolean;
      requireSpecial: boolean;
      expiryDays: number;
      historyCount: number;
    }>,
  ) {
    return this.authDeepService.updatePasswordPolicy(req.user.tenantId, body);
  }

  /* ─── IP Allowlisting ─── */

  @ApiOperation({ summary: "List IP allowlist entries" })
  @Get("ip-allowlist")
  @Permissions("auth.ip-allowlist.read")
  async listIpAllowlist(@Req() req: AuthenticatedRequest) {
    return this.authDeepService.listIpAllowlist(req.user.tenantId);
  }

  @ApiOperation({ summary: "Create IP allowlist entry" })
  @Post("ip-allowlist")
  @HttpCode(HttpStatus.CREATED)
  @Permissions("auth.ip-allowlist.create")
  async createIpAllowlist(
    @Req() req: AuthenticatedRequest,
    @ZodBody(
      z.object({
        ipRange: z.string().min(1),
        description: z.string().optional(),
      }),
    )
    body: { ipRange: string; description?: string },
  ) {
    return this.authDeepService.createIpAllowlistEntry(req.user.tenantId, body);
  }

  @ApiOperation({ summary: "Update IP allowlist entry" })
  @Put("ip-allowlist/:id")
  @HttpCode(HttpStatus.OK)
  @Permissions("auth.ip-allowlist.update")
  async updateIpAllowlist(
    @Req() req: AuthenticatedRequest,
    @Param("id") id: string,
    @ZodBody(
      z.object({
        ipRange: z.string().optional(),
        description: z.string().optional(),
        isActive: z.boolean().optional(),
      }),
    )
    body: { ipRange?: string; description?: string; isActive?: boolean },
  ) {
    return this.authDeepService.updateIpAllowlistEntry(
      req.user.tenantId,
      id,
      body,
    );
  }

  @ApiOperation({ summary: "Delete IP allowlist entry" })
  @Delete("ip-allowlist/:id")
  @HttpCode(HttpStatus.OK)
  @Permissions("auth.ip-allowlist.delete")
  async deleteIpAllowlist(
    @Req() req: AuthenticatedRequest,
    @Param("id") id: string,
  ) {
    return this.authDeepService.deleteIpAllowlistEntry(req.user.tenantId, id);
  }
}
