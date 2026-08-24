import { Module } from "@nestjs/common";
import { QueueModule } from "./common/queues/queue.module";
import { AuthModule } from "./modules/auth/auth.module";
import { OidcModule } from "./modules/oidc/oidc.module";
import { HealthController } from "./health.controller";
import { MetricsController } from "./metrics.controller";

@Module({
  imports: [QueueModule, AuthModule, OidcModule],
  controllers: [HealthController, MetricsController],
  providers: [],
})
export class AppModule {}
