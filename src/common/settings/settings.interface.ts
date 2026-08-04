import { z, ZodSchema } from "zod";

export type SettingType = "string" | "number" | "boolean" | "object" | "array";

export type SettingScope = "TENANT" | "USER" | "ROLE";

export interface SettingOption {
  value: any;
  label: string;
}

export interface ModuleSettingConfig {
  type: SettingType;
  label: string;
  description?: string;
  default?: any;
  options?: SettingOption[];
  validation?: ZodSchema;
  rbac?: {
    roles: string[];
    permission: string;
  };
}

export interface ModuleSettingsSchema {
  [key: string]: ModuleSettingConfig;
}

export interface AppSettingResponse {
  key: string;
  value: any;
  scope: SettingScope;
  roleId?: string;
  updatedAt: Date;
}

export interface SettingsSchemaResponse {
  moduleSlug: string;
  schema: ModuleSettingsSchema;
}

export interface SetSettingInput {
  value: any;
  scope?: SettingScope;
  roleId?: string;
}

export interface GetSettingsQuery {
  scope?: SettingScope;
  roleId?: string;
}

export const SettingScopeEnum = z.enum(["TENANT", "USER", "ROLE"]);
export const SetSettingInputSchema = z.object({
  value: z.any(),
  scope: SettingScopeEnum.optional(),
  roleId: z.string().optional(),
});
export const GetSettingsQuerySchema = z.object({
  scope: SettingScopeEnum.optional(),
  roleId: z.string().optional(),
});
