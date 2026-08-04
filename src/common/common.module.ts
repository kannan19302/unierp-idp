import { Global, Module } from "@nestjs/common";
import { ChangeHistoryService } from "./services/change-history.service";
import { ChangeHistoryController } from "./controllers/change-history.controller";
import { ExportService } from "./services/export.service";
import { AppLogger } from "./services/logger.service";
import { CacheService } from "./services/cache.service";
import { I18nService } from "./services/i18n.service";

import { BulkOperationsService } from "./services/bulk-operations.service";
import { BulkOperationsController } from "./controllers/bulk-operations.controller";

import { ImportService } from "./services/import.service";
import { ImportController } from "./controllers/import.controller";

import { DataQualityService } from "./services/data-quality.service";
import { DataQualityController } from "./controllers/data-quality.controller";

import { EnterpriseAuditService } from "./services/enterprise-audit.service";
import { EnterpriseAuditController } from "./controllers/enterprise-audit.controller";

import { ExportV2Service } from "./services/export-v2.service";
import { ExportV2Controller } from "./controllers/export-v2.controller";

import { TenantGuard } from "./guards/tenant.guard";

import { IdpPrismaService } from "@unerp/database";
import { AppSettingsService } from "./settings/settings.service";

@Global()
@Module({
  controllers: [
    ChangeHistoryController,
    BulkOperationsController,
    ImportController,
    DataQualityController,
    EnterpriseAuditController,
    ExportV2Controller,
  ],
  providers: [
    IdpPrismaService,
    AppSettingsService,
    ChangeHistoryService,
    ExportService,
    AppLogger,
    CacheService,
    I18nService,
    BulkOperationsService,
    ImportService,
    DataQualityService,
    EnterpriseAuditService,
    ExportV2Service,
    TenantGuard,
  ],
  exports: [
    IdpPrismaService,
    AppSettingsService,
    ChangeHistoryService,
    ExportService,
    AppLogger,
    CacheService,
    I18nService,
    BulkOperationsService,
    ImportService,
    DataQualityService,
    EnterpriseAuditService,
    ExportV2Service,
    TenantGuard,
  ],
})
export class CommonModule {}
