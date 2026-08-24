import { Global, Module } from "@nestjs/common";
import { BullModule } from "@nestjs/bullmq";
import { EmailProcessor } from "./email.processor";
import { ExportProcessor } from "./export.processor";
import { PlatformCredentialsModule } from "../platform-credentials/platform-credentials.module";
import { IDENTITY_EMAIL_DLQ, IDENTITY_EMAIL_QUEUE } from "./queue.constants";
import { EmailDeliveryOperationsService } from "./email-delivery-operations.service";
import { EmailWebhookController } from "./email-webhook.controller";
import { EmailCanaryScheduler } from "./email-canary.scheduler";

const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";

@Global()
@Module({
  imports: [
    PlatformCredentialsModule,
    BullModule.forRoot({
      connection: {
        url: REDIS_URL,
      },
      defaultJobOptions: {
        attempts: 3,
        backoff: { type: "exponential", delay: 1000 },
        removeOnComplete: 100,
        removeOnFail: 500,
      },
    }),
    BullModule.registerQueue(
      { name: IDENTITY_EMAIL_QUEUE },
      { name: IDENTITY_EMAIL_DLQ },
      { name: "export" },
      { name: "payroll" },
      { name: "data-import" },
    ),
  ],
  controllers: [EmailWebhookController],
  providers: [EmailProcessor, ExportProcessor, EmailDeliveryOperationsService, EmailCanaryScheduler],
  exports: [BullModule, EmailDeliveryOperationsService],
})
export class QueueModule {}
