import {
  Body,
  Controller,
  ForbiddenException,
  Header,
  Post,
  Req,
  Res,
  UseGuards,
} from "@nestjs/common";
import { ApiExcludeController } from "@nestjs/swagger";
import { Throttle } from "@nestjs/throttler";
import type { Request, Response } from "express";
import { JwtAuthGuard } from "../../../common/guards/jwt-auth.guard";
import { AccountGovernanceService } from "../../auth/account-governance.service";
import { setSessionCookies, verifyCsrf } from "./login.controller";

type AccountRequest = Request & {
  user?: { userId?: string; tenantId?: string; sid?: string };
};

@ApiExcludeController()
@Controller("oidc/account/governance")
@UseGuards(JwtAuthGuard)
export class AccountGovernanceController {
  constructor(private readonly governance: AccountGovernanceService) {}

  @Post("organization/switch")
  @Header("Cache-Control", "no-store")
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  async switchOrganization(
    @Body() body: Record<string, unknown>,
    @Req() req: AccountRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    this.assertCsrf(req, body._csrf);
    const result = await this.governance.switchOrganization({
      userId: req.user?.userId || "",
      tenantId: req.user?.tenantId || "",
      sid: req.user?.sid || "",
      targetTenantId: typeof body.targetTenantId === "string" ? body.targetTenantId : "",
      context: {
        ipAddress: req.ip || req.socket.remoteAddress,
        userAgent: req.headers["user-agent"],
      },
    });
    setSessionCookies(res, result as unknown as Record<string, unknown>);
    return { switched: true, returnTo: "/oidc/account" };
  }

  @Post("organization/leave")
  @Header("Cache-Control", "no-store")
  @Throttle({ default: { limit: 5, ttl: 60 * 60_000 } })
  async leaveOrganization(
    @Body() body: Record<string, unknown>,
    @Req() req: AccountRequest,
  ) {
    this.assertCsrf(req, body._csrf);
    return this.governance.leaveOrganization({
      userId: req.user?.userId || "",
      tenantId: req.user?.tenantId || "",
      sid: req.user?.sid || "",
      targetTenantId: typeof body.targetTenantId === "string" ? body.targetTenantId : "",
    });
  }

  @Post("privacy/export")
  @Header("Cache-Control", "no-store")
  @Throttle({ default: { limit: 3, ttl: 60 * 60_000 } })
  async createExport(
    @Body() body: Record<string, unknown>,
    @Req() req: AccountRequest,
  ) {
    this.assertCsrf(req, body._csrf);
    return this.governance.createSubjectExport({
      userId: req.user?.userId || "",
      tenantId: req.user?.tenantId || "",
      sid: req.user?.sid || "",
    });
  }

  @Post("privacy/deletion/request")
  @Header("Cache-Control", "no-store")
  @Throttle({ default: { limit: 3, ttl: 60 * 60_000 } })
  async requestDeletion(
    @Body() body: Record<string, unknown>,
    @Req() req: AccountRequest,
  ) {
    this.assertCsrf(req, body._csrf);
    return this.governance.requestAccountDeletion({
      userId: req.user?.userId || "",
      tenantId: req.user?.tenantId || "",
      sid: req.user?.sid || "",
      reason: typeof body.reason === "string" ? body.reason : undefined,
    });
  }

  @Post("privacy/deletion/cancel")
  @Header("Cache-Control", "no-store")
  @Throttle({ default: { limit: 5, ttl: 60 * 60_000 } })
  async cancelDeletion(
    @Body() body: Record<string, unknown>,
    @Req() req: AccountRequest,
  ) {
    this.assertCsrf(req, body._csrf);
    return this.governance.cancelAccountDeletion({
      userId: req.user?.userId || "",
      tenantId: req.user?.tenantId || "",
      sid: req.user?.sid || "",
      requestId: typeof body.requestId === "string" ? body.requestId : "",
    });
  }

  private assertCsrf(req: Request, value: unknown): void {
    if (!verifyCsrf(req, typeof value === "string" ? value : undefined)) {
      throw new ForbiddenException("Invalid or expired security token.");
    }
  }
}
