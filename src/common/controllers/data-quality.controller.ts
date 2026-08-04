import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
  Req,
} from "@nestjs/common";
import { TenantGuard } from "../guards/tenant.guard";
import { RbacGuard } from "../guards/rbac.guard";
import { Permissions } from "../decorators/permissions.decorator";
import { DataQualityService } from "../services/data-quality.service";

interface AuthenticatedRequest {
  user: { tenantId: string; userId: string };
  tenantId?: string;
}

@Controller("data-quality")
@UseGuards(TenantGuard, RbacGuard)
export class DataQualityController {
  constructor(private readonly dataQualityService: DataQualityService) {}

  @Post(":modelName/deduplicate")
  @Permissions("data-quality.deduplicate")
  async deduplicate(
    @Param("modelName") modelName: string,
    @Body() body: { fields: string[] },
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.dataQualityService.deduplicate(
      tenantId,
      modelName,
      body.fields,
    );
  }

  @Post(":modelName/merge")
  @Permissions("data-quality.merge")
  async mergeDuplicates(
    @Param("modelName") modelName: string,
    @Body()
    body: { primaryId: string; duplicateIds: string[]; mergeStrategy?: any[] },
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.dataQualityService.mergeDuplicates(
      tenantId,
      modelName,
      body.primaryId,
      body.duplicateIds,
      body.mergeStrategy,
    );
  }

  @Get(":modelName/validate")
  @Permissions("data-quality.validate")
  async validateDataQuality(
    @Param("modelName") modelName: string,
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.dataQualityService.validateDataQuality(tenantId, modelName);
  }

  @Post("normalize/address")
  @Permissions("data-quality.normalize")
  async normalizeAddress(
    @Body() body: { address: any },
    @Req() req: AuthenticatedRequest,
  ) {
    return this.dataQualityService.standardizeAddress(body.address);
  }

  @Post("normalize/phone")
  @Permissions("data-quality.normalize")
  async normalizePhone(
    @Body() body: { phone: string; country?: string },
    @Req() req: AuthenticatedRequest,
  ) {
    return this.dataQualityService.normalizePhone(body.phone, body.country);
  }
}
