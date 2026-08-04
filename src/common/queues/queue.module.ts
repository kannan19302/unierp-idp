import { Global, Module } from "@nestjs/common";
import { BullModule } from "@nestjs/bullmq";
import { EmailProcessor } from "./email.processor";
import { ExportProcessor } from "./export.processor";
import { PlatformCredentialsModule } from "../platform-credentials/platform-credentials.module";

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
      { name: "email" },
      { name: "export" },
      { name: "payroll" },
      { name: "data-import" },
    ),
  ],
  providers: [EmailProcessor, ExportProcessor],
  exports: [BullModule],
})
export class QueueModule {}
