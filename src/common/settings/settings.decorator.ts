import { applyDecorators, Controller, UseInterceptors } from "@nestjs/common";
import { AppInstalledGuard } from "../guards/app-installed.guard";
import { ChangeHistoryInterceptor } from "../interceptors/change-history.interceptor";

export const ModuleSettings = (moduleSlug: string) =>
  applyDecorators(
    Controller(`${moduleSlug}/settings`),
    UseInterceptors(AppInstalledGuard, ChangeHistoryInterceptor),
  );
