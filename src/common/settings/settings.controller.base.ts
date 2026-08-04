import {
  Get,
  Patch,
  Delete,
  Param,
  Body,
  Query,
  UseGuards,
} from "@nestjs/common";
import { ApiOperation, ApiParam, ApiQuery } from "@nestjs/swagger";
import { RbacGuard } from "../guards/rbac.guard";
import { TrackChanges } from "../decorators/track-changes.decorator";
import { CurrentTenant } from "../decorators/current-tenant.decorator";
import { AppSettingsService } from "./settings.service";
import {
  ModuleSettingsSchema,
  AppSettingResponse,
  SettingsSchemaResponse,
  SetSettingInput,
  GetSettingsQuery,
} from "./settings.interface";

export abstract class SettingsControllerBase {
  constructor(protected readonly settingsService: AppSettingsService) {}

  protected readonly moduleSlug!: string;
  protected readonly settingsSchema!: ModuleSettingsSchema;

  @ApiOperation({ summary: "Get all settings for this module" })
  @ApiQuery({
    name: "scope",
    required: false,
    enum: ["TENANT", "USER", "ROLE"],
  })
  @ApiQuery({ name: "roleId", required: false })
  @Get()
  @UseGuards(RbacGuard)
  async getAllSettings(
    @CurrentTenant() tenantId: string,
    @Query() query: GetSettingsQuery,
  ): Promise<AppSettingResponse[]> {
    return this.settingsService.getSettings(tenantId, this.moduleSlug, query);
  }

  @ApiOperation({ summary: "Get settings schema for this module" })
  @Get("schema")
  @UseGuards(RbacGuard)
  async getSchema(): Promise<SettingsSchemaResponse> {
    return this.settingsService.getSchema(this.moduleSlug, this.settingsSchema);
  }

  @ApiOperation({ summary: "Get a specific setting by key" })
  @ApiParam({ name: "key", description: "Setting key" })
  @ApiQuery({
    name: "scope",
    required: false,
    enum: ["TENANT", "USER", "ROLE"],
  })
  @ApiQuery({ name: "roleId", required: false })
  @Get(":key")
  @UseGuards(RbacGuard)
  async getSetting(
    @CurrentTenant() tenantId: string,
    @Param("key") key: string,
    @Query() query: GetSettingsQuery,
  ): Promise<AppSettingResponse> {
    return this.settingsService.getSetting(
      tenantId,
      this.moduleSlug,
      key,
      query,
    );
  }

  @ApiOperation({ summary: "Set a setting value" })
  @ApiParam({ name: "key", description: "Setting key" })
  @Patch(":key")
  @UseGuards(RbacGuard)
  @TrackChanges("AppSettings")
  async setSetting(
    @CurrentTenant() tenantId: string,
    @Param("key") key: string,
    @Body() body: SetSettingInput,
  ): Promise<AppSettingResponse> {
    return this.settingsService.setSetting(
      tenantId,
      this.moduleSlug,
      key,
      body,
      this.settingsSchema,
    );
  }

  @ApiOperation({ summary: "Delete a setting" })
  @ApiParam({ name: "key", description: "Setting key" })
  @ApiQuery({
    name: "scope",
    required: false,
    enum: ["TENANT", "USER", "ROLE"],
  })
  @ApiQuery({ name: "roleId", required: false })
  @Delete(":key")
  @UseGuards(RbacGuard)
  async deleteSetting(
    @CurrentTenant() tenantId: string,
    @Param("key") key: string,
    @Query() query: GetSettingsQuery,
  ): Promise<void> {
    return this.settingsService.deleteSetting(
      tenantId,
      this.moduleSlug,
      key,
      query,
    );
  }
}
