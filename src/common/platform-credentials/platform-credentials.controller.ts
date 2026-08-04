import { Controller, Get, Param, Put, Req, UseGuards } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { z } from "zod";
import { JwtAuthGuard } from "../guards/jwt-auth.guard";
import { RbacGuard } from "../guards/rbac.guard";
import { Permissions } from "../decorators/permissions.decorator";
import { ZodBody } from "../decorators/zod-body.decorator";
import { PlatformCredentialsService } from "./platform-credentials.service";

const setCredentialsSchema = z.object({
  values: z.record(z.string(), z.string()),
});

@ApiTags("platform-credentials")
@UseGuards(JwtAuthGuard, RbacGuard)
@Controller("admin/platform-credentials")
export class PlatformCredentialsController {
  constructor(private readonly service: PlatformCredentialsService) {}

  @ApiOperation({ summary: "List all platform credential providers (masked)" })
  @Permissions("admin.setting.read")
  @Get()
  async list() {
    return this.service.getAllMasked();
  }

  @ApiOperation({ summary: "Update a platform credential provider's values" })
  @Permissions("admin.setting.update")
  @Put(":provider")
  async update(
    @Param("provider") provider: string,
    @ZodBody(setCredentialsSchema) dto: z.infer<typeof setCredentialsSchema>,
    @Req() req: any,
  ) {
    await this.service.set(provider, dto.values, req.user.userId);
    return this.service.getMasked(provider);
  }
}
