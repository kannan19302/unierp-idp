import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  Query,
  Res,
  Req,
  UseGuards,
} from "@nestjs/common";
import { Response } from "express";
import { TenantGuard } from "../guards/tenant.guard";
import { RbacGuard } from "../guards/rbac.guard";
import { Permissions } from "../decorators/permissions.decorator";
import { ExportV2Service } from "../services/export-v2.service";

interface AuthenticatedRequest {
  user: { tenantId: string; userId: string };
  tenantId?: string;
}

@Controller("export/v2")
@UseGuards(TenantGuard, RbacGuard)
export class ExportV2Controller {
  constructor(private readonly exportV2Service: ExportV2Service) {}

  @Post(":modelName")
  @Permissions("export-v2.create")
  async exportWithTemplate(
    @Param("modelName") modelName: string,
    @Body()
    body: {
      fields: { header: string; key: string; width?: number }[];
      rows: Record<string, any>[];
      template?: string;
      format?: "csv" | "xlsx" | "pdf";
    },
    @Res() res: Response,
    @Req() req: AuthenticatedRequest,
  ) {
    await this.exportV2Service.exportWithTemplates(
      res,
      modelName,
      body.fields,
      body.rows,
      body.template,
      body.format || "xlsx",
    );
  }

  @Post("schedule")
  @Permissions("export-v2.schedule")
  async scheduleExport(
    @Body()
    body: {
      modelName: string;
      format: "csv" | "xlsx" | "pdf";
      template?: string;
      cronExpression: string;
      recipients: string[];
      filters?: Record<string, any>;
    },
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    const userId = req.user?.userId;
    return this.exportV2Service.scheduleExport(tenantId, userId, body);
  }

  @Get("history")
  @Permissions("export-v2.view")
  async getExportHistory(
    @Req() req: AuthenticatedRequest,
    @Query("page") page?: string,
    @Query("limit") limit?: string,
    @Query("sort") sort?: string,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.exportV2Service.getExportHistory(tenantId, {
      page: page ? parseInt(page, 10) : 1,
      limit: limit ? parseInt(limit, 10) : 25,
      sort,
    });
  }

  @Post("bulk/:modelName")
  @Permissions("export-v2.bulk")
  async bulkExport(
    @Param("modelName") modelName: string,
    @Body() body: { ids: string[]; format?: "csv" | "xlsx" | "pdf" },
    @Res() res: Response,
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    await this.exportV2Service.bulkExport(
      tenantId,
      modelName,
      body.ids,
      body.format || "csv",
      res,
    );
  }
}
