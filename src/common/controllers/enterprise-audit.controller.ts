import {
  Controller,
  Get,
  Post,
  Param,
  Query,
  Res,
  Req,
  UseGuards,
} from "@nestjs/common";
import { Response } from "express";
import { TenantGuard } from "../guards/tenant.guard";
import { RbacGuard } from "../guards/rbac.guard";
import { Permissions } from "../decorators/permissions.decorator";
import { EnterpriseAuditService } from "../services/enterprise-audit.service";

interface AuthenticatedRequest {
  user: { tenantId: string; userId: string };
  tenantId?: string;
}

@Controller("audit")
@UseGuards(TenantGuard, RbacGuard)
export class EnterpriseAuditController {
  constructor(
    private readonly enterpriseAuditService: EnterpriseAuditService,
  ) {}

  @Get(":entityType/:entityId")
  @Permissions("audit.view")
  async getAuditTrail(
    @Param("entityType") entityType: string,
    @Param("entityId") entityId: string,
    @Req() req: AuthenticatedRequest,
    @Query("page") page?: string,
    @Query("limit") limit?: string,
    @Query("sort") sort?: string,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.enterpriseAuditService.getAuditTrail(
      tenantId,
      entityType,
      entityId,
      {
        page: page ? parseInt(page, 10) : 1,
        limit: limit ? parseInt(limit, 10) : 25,
        sort,
      },
    );
  }

  @Get("user/:userId")
  @Permissions("audit.view")
  async getUserActivity(
    @Param("userId") userId: string,
    @Req() req: AuthenticatedRequest,
    @Query("page") page?: string,
    @Query("limit") limit?: string,
    @Query("startDate") startDate?: string,
    @Query("endDate") endDate?: string,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.enterpriseAuditService.getUserActivity(
      tenantId,
      userId,
      {
        startDate: startDate ? new Date(startDate) : undefined,
        endDate: endDate ? new Date(endDate) : undefined,
      },
      {
        page: page ? parseInt(page, 10) : 1,
        limit: limit ? parseInt(limit, 10) : 25,
      },
    );
  }

  @Get("security")
  @Permissions("audit.security")
  async getSecurityAudit(
    @Req() req: AuthenticatedRequest,
    @Query("page") page?: string,
    @Query("limit") limit?: string,
    @Query("startDate") startDate?: string,
    @Query("endDate") endDate?: string,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.enterpriseAuditService.getSecurityAudit(
      tenantId,
      {
        startDate: startDate ? new Date(startDate) : undefined,
        endDate: endDate ? new Date(endDate) : undefined,
      },
      {
        page: page ? parseInt(page, 10) : 1,
        limit: limit ? parseInt(limit, 10) : 25,
      },
    );
  }

  @Get("export")
  @Permissions("audit.export")
  async exportAuditLog(
    @Req() req: AuthenticatedRequest,
    @Res() res: Response,
    @Query("format") format?: string,
    @Query("startDate") startDate?: string,
    @Query("endDate") endDate?: string,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    const exportFormat = format === "xlsx" || format === "pdf" ? format : "csv";
    await this.enterpriseAuditService.exportAuditLog(
      tenantId,
      exportFormat as any,
      {
        startDate: startDate ? new Date(startDate) : undefined,
        endDate: endDate ? new Date(endDate) : undefined,
      },
      res,
    );
  }

  @Get("compliance-report")
  @Permissions("audit.compliance")
  async getComplianceReport(
    @Req() req: AuthenticatedRequest,
    @Query("startDate") startDate: string,
    @Query("endDate") endDate: string,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.enterpriseAuditService.getComplianceReport(
      tenantId,
      new Date(startDate),
      new Date(endDate),
    );
  }
}
