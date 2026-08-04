import {
  Controller,
  Get,
  Query,
  Param,
  UseGuards,
  UseInterceptors,
  Req,
} from "@nestjs/common";
import { JwtAuthGuard } from "../guards/jwt-auth.guard";
import { TenantInterceptor } from "../guards/tenant.interceptor";
import { ChangeHistoryService } from "../services/change-history.service";

interface AuthenticatedRequest {
  user: { tenantId: string; userId: string };
}

@Controller("change-history")
@UseGuards(JwtAuthGuard)
@UseInterceptors(TenantInterceptor)
export class ChangeHistoryController {
  constructor(private readonly changeHistoryService: ChangeHistoryService) {}

  @Get(":entityType/:entityId")
  async getHistory(
    @Req() req: AuthenticatedRequest,
    @Param("entityType") entityType: string,
    @Param("entityId") entityId: string,
    @Query("page") page?: string,
    @Query("limit") limit?: string,
  ) {
    return this.changeHistoryService.getHistory(
      req.user.tenantId,
      entityType,
      entityId,
      page ? parseInt(page, 10) : 1,
      limit ? parseInt(limit, 10) : 20,
    );
  }
}
