import {
  Controller,
  Get,
  Put,
  Post,
  Param,
  Req,
  UseGuards,
  HttpCode,
  HttpStatus,
} from "@nestjs/common";
import { OnboardingService } from "./onboarding.service";

import { JwtAuthGuard } from "../../common/guards/jwt-auth.guard";
import { ApiTags, ApiOperation, ApiBearerAuth } from "@nestjs/swagger";

@ApiTags("onboarding")
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller("auth/onboarding")
export class OnboardingController {
  constructor(private readonly onboardingService: OnboardingService) {}

  @ApiOperation({ summary: "Get onboarding checklist status" })
  @Get()
  async getOnboardingState(@Req() req: any) {
    return this.onboardingService.getOnboardingState(
      req.user.tenantId,
      req.user.userId,
    );
  }

  @ApiOperation({ summary: "Mark an onboarding step as completed" })
  @Put("complete/:key")
  async completeStep(@Req() req: any, @Param("key") key: string) {
    return this.onboardingService.completeStep(
      req.user.tenantId,
      req.user.userId,
      key,
    );
  }
}
