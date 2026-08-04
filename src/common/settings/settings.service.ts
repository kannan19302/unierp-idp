import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from "@nestjs/common";
import { idpPrisma, prisma } from "@unerp/database";
import {
  ModuleSettingsSchema,
  AppSettingResponse,
  SettingsSchemaResponse,
  SetSettingInput,
  GetSettingsQuery,
  SettingScope,
} from "./settings.interface";

// The "app_settings" column is a plain string (no DB enum) — narrow it back
// to the app-level union at the API boundary.
const asScope = (scope: string): SettingScope => scope as SettingScope;
// Column is non-null with a "" default standing for "no role" — normalize
// that back to `undefined` for API responses.
const asRoleId = (roleId: string): string | undefined => roleId || undefined;

@Injectable()
export class AppSettingsService {
  async getSettings(
    tenantId: string,
    appSlug: string,
    query: GetSettingsQuery = {},
  ): Promise<AppSettingResponse[]> {
    const settings = await prisma.appSettings.findMany({
      where: {
        tenantId,
        appSlug,
        ...(query.scope ? { scope: query.scope } : {}),
        ...(query.roleId ? { roleId: query.roleId } : {}),
      },
      orderBy: { key: "asc" },
    });

    return settings.map(
      (s): AppSettingResponse => ({
        key: s.key,
        value: s.value,
        scope: asScope(s.scope),
        roleId: asRoleId(s.roleId),
        updatedAt: s.updatedAt,
      }),
    );
  }

  async getSetting(
    tenantId: string,
    appSlug: string,
    key: string,
    query: GetSettingsQuery = {},
  ): Promise<AppSettingResponse> {
    const setting = await prisma.appSettings.findFirst({
      where: {
        tenantId,
        appSlug,
        key,
        ...(query.scope ? { scope: query.scope } : {}),
        ...(query.roleId ? { roleId: query.roleId } : {}),
      },
    });

    if (!setting) {
      throw new NotFoundException(
        `Setting ${key} not found for module ${appSlug}`,
      );
    }

    return {
      key: setting.key,
      value: setting.value,
      scope: asScope(setting.scope),
      roleId: asRoleId(setting.roleId),
      updatedAt: setting.updatedAt,
    };
  }

  async setSetting(
    tenantId: string,
    appSlug: string,
    key: string,
    input: SetSettingInput,
    schema: ModuleSettingsSchema,
  ): Promise<AppSettingResponse> {
    const config = schema[key];
    if (!config) {
      throw new NotFoundException(
        `Setting ${key} is not defined in ${appSlug} schema`,
      );
    }

    if (config.validation) {
      const result = config.validation.safeParse(input.value);
      if (!result.success) {
        throw new ForbiddenException(
          `Invalid value for ${key}: ${result.error.message}`,
        );
      }
    }

    const scope = input.scope ?? "TENANT";
    const roleId = input.roleId ?? "";

    if (scope === "ROLE" && !roleId) {
      throw new ForbiddenException("roleId is required when scope is ROLE");
    }

    const setting = await prisma.appSettings.upsert({
      where: {
        tenantId_appSlug_key_scope_roleId: {
          tenantId,
          appSlug,
          key,
          scope,
          roleId,
        },
      },
      create: {
        tenantId,
        appSlug,
        key,
        value: input.value,
        scope,
        roleId,
      },
      update: {
        value: input.value,
        scope,
        roleId,
      },
    });

    return {
      key: setting.key,
      value: setting.value,
      scope: asScope(setting.scope),
      roleId: asRoleId(setting.roleId),
      updatedAt: setting.updatedAt,
    };
  }

  async deleteSetting(
    tenantId: string,
    appSlug: string,
    key: string,
    query: GetSettingsQuery = {},
  ): Promise<void> {
    const deleted = await prisma.appSettings.deleteMany({
      where: {
        tenantId,
        appSlug,
        key,
        ...(query.scope ? { scope: query.scope } : {}),
        ...(query.roleId ? { roleId: query.roleId } : {}),
      },
    });

    if (deleted.count === 0) {
      throw new NotFoundException(
        `Setting ${key} not found for module ${appSlug}`,
      );
    }
  }

  getSchema(
    moduleSlug: string,
    schema: ModuleSettingsSchema,
  ): SettingsSchemaResponse {
    const sanitizedSchema: ModuleSettingsSchema = {};
    for (const [key, config] of Object.entries(schema)) {
      sanitizedSchema[key] = {
        ...config,
        validation: undefined,
      };
    }
    return {
      moduleSlug,
      schema: sanitizedSchema,
    };
  }

  async getAllSchemas(
    tenantId: string,
    moduleSchemas: Record<string, ModuleSettingsSchema>,
  ): Promise<Record<string, SettingsSchemaResponse>> {
    const installedApps = await prisma.installedApp.findMany({
      where: { tenantId, status: "INSTALLED" },
      select: { appSlug: true },
    });

    const result: Record<string, SettingsSchemaResponse> = {};
    for (const installed of installedApps) {
      const appSlug = installed.appSlug;
      if (appSlug && moduleSchemas[appSlug]) {
        result[appSlug] = this.getSchema(appSlug, moduleSchemas[appSlug]);
      }
    }
    return result;
  }
}
