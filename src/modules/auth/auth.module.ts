import { Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { AuthDeepController } from "./auth-deep.controller";
import { AuthDeepService } from "./auth-deep.service";
import { OAuthController } from "./oauth.controller";
import { OAuthService } from "./oauth.service";
import { SsoController } from "./sso.controller";
import { SsoService } from "./sso.service";
import { ProvisioningService } from "./provisioning.service";
import { OnboardingController } from "./onboarding.controller";
import { OnboardingService } from "./onboarding.service";

import { PlatformCredentialsModule } from "../../common/platform-credentials/platform-credentials.module";

@Module({
  imports: [PlatformCredentialsModule],
  controllers: [
    AuthController,
    AuthDeepController,
    OAuthController,
    SsoController,
    OnboardingController,
  ],
  providers: [
    AuthService,
    AuthDeepService,
    OAuthService,
    SsoService,
    ProvisioningService,
    OnboardingService,
  ],
  exports: [
    AuthService,
    AuthDeepService,
    OAuthService,
    SsoService,
    ProvisioningService,
    OnboardingService,
  ],
})
export class AuthModule {}
