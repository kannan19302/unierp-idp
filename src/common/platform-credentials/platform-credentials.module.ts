import { Module } from "@nestjs/common";
import { PlatformCredentialsService } from "./platform-credentials.service";
import { PlatformCredentialsController } from "./platform-credentials.controller";

@Module({
  controllers: [PlatformCredentialsController],
  providers: [PlatformCredentialsService],
  exports: [PlatformCredentialsService],
})
export class PlatformCredentialsModule {}
