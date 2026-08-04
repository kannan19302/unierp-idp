import {
  Controller,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  Req,
} from "@nestjs/common";
import { TenantGuard } from "../guards/tenant.guard";
import { RbacGuard } from "../guards/rbac.guard";
import { Permissions } from "../decorators/permissions.decorator";
import { BulkOperationsService } from "../services/bulk-operations.service";

interface AuthenticatedRequest {
  user: { tenantId: string; userId: string };
  tenantId?: string;
}

@Controller("bulk")
@UseGuards(TenantGuard, RbacGuard)
export class BulkOperationsController {
  constructor(private readonly bulkOperationsService: BulkOperationsService) {}

  @Post(":modelName/create")
  @Permissions("bulk-ops.create")
  async bulkCreate(
    @Param("modelName") modelName: string,
    @Body() body: { records: any[] },
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.bulkOperationsService.bulkCreate(
      tenantId,
      modelName,
      body.records,
    );
  }

  @Patch(":modelName/update")
  @Permissions("bulk-ops.update")
  async bulkUpdate(
    @Param("modelName") modelName: string,
    @Body() body: { ids: string[]; updates: Record<string, any> },
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.bulkOperationsService.bulkUpdate(
      tenantId,
      modelName,
      body.ids,
      body.updates,
    );
  }

  @Delete(":modelName/delete")
  @Permissions("bulk-ops.delete")
  async bulkDelete(
    @Param("modelName") modelName: string,
    @Body() body: { ids: string[] },
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.bulkOperationsService.bulkDelete(tenantId, modelName, body.ids);
  }

  @Post(":modelName/restore")
  @Permissions("bulk-ops.restore")
  async bulkRestore(
    @Param("modelName") modelName: string,
    @Body() body: { ids: string[] },
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.bulkOperationsService.bulkRestore(
      tenantId,
      modelName,
      body.ids,
    );
  }

  @Patch(":modelName/status")
  @Permissions("bulk-ops.status")
  async bulkStatusChange(
    @Param("modelName") modelName: string,
    @Body() body: { ids: string[]; status: string },
    @Req() req: AuthenticatedRequest,
  ) {
    const tenantId = req.tenantId || req.user?.tenantId;
    return this.bulkOperationsService.bulkStatusChange(
      tenantId,
      modelName,
      body.ids,
      body.status,
    );
  }
}
