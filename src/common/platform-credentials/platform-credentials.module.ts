import { Module } from "@nestjs/common";
import { PlatformCredentialsService } from "./platform-credentials.service";
import { PlatformCredentialsController } from "./platform-credentials.controller";
import { TestEmailController } from "./test-email.controller";
import { EmailTemplateAdminController } from "./email-template-admin.controller";

@Module({
  controllers: [
    PlatformCredentialsController,
    TestEmailController,
    EmailTemplateAdminController,
  ],
  providers: [PlatformCredentialsService],
  exports: [PlatformCredentialsService],
})
export class PlatformCredentialsModule {}
