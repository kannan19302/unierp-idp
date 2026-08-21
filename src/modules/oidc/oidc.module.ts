import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module";
import { DiscoveryController } from "./controllers/discovery.controller";
import { SigningKeyService } from "./services/signing-key.service";
import { AuthorizationService } from "./services/authorization.service";
import { OidcTokenService } from "./services/oidc-token.service";
import { OidcClientService } from "./services/oidc-client.service";
import { TokenController } from "./controllers/token.controller";
import { AuthorizeController } from "./controllers/authorize.controller";
import { PlatformEntitlementService } from "./services/platform-entitlement.service";
import { PlatformsController } from "./controllers/platforms.controller";
import { AgentDelegationService } from "./services/agent-delegation.service";
import { LoginController } from "./controllers/login.controller";
import {
  SessionController,
  ConsentController,
} from "./controllers/session.controller";

/**
 * The authorization server.
 *
 * Everything that mints a credential for the platform lives here and nowhere
 * else — that is the property the whole design rests on. Services outside this
 * module can verify tokens (public JWKS) but cannot issue them.
 */
@Module({
  // AuthModule supplies AuthService, whose resolveRolesAndPermissions builds
  // the role/permission claims — reused rather than reimplemented here.
  imports: [AuthModule],
  controllers: [
    DiscoveryController,
    AuthorizeController,
    TokenController,
    LoginController,
    SessionController,
    ConsentController,
    PlatformsController,
  ],
  providers: [
    SigningKeyService,
    AuthorizationService,
    OidcTokenService,
    OidcClientService,
    PlatformEntitlementService,
    AgentDelegationService,
  ],
  exports: [
    SigningKeyService,
    AuthorizationService,
    OidcTokenService,
    OidcClientService,
  ],
})
export class OidcModule {}
