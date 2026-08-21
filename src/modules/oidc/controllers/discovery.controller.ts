import { Controller, Get, Header } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { SigningKeyService } from "../services/signing-key.service";
import {
  ALL_SCOPES,
  GRANT_TYPE,
  PKCE_METHOD_S256,
} from "../oidc.constants";

/**
 * OIDC discovery and the public key set.
 *
 * Both routes are unauthenticated by design — a relying party has to be able to
 * fetch them before it holds any credential, and the JWKS contains only public
 * keys.
 *
 * These live at the issuer root, NOT under the /api/v1 global prefix.
 * RFC 8414 defines the discovery location as the issuer plus
 * /.well-known/openid-configuration, and clients construct that URL themselves
 * rather than reading it from anywhere. Serving it under a prefix means no
 * standard client can find it, so main.ts excludes these paths from the prefix.
 */
@ApiTags("oidc")
@Controller()
export class DiscoveryController {
  constructor(private readonly keys: SigningKeyService) {}

  private get issuer(): string {
    return process.env.OIDC_ISSUER ?? "http://localhost:3005";
  }

  @ApiOperation({ summary: "OpenID Connect discovery document" })
  @Get(".well-known/openid-configuration")
  // Cacheable, but not for long: rotating a key or adding a grant type should
  // reach clients in minutes rather than whenever they happen to restart.
  @Header("Cache-Control", "public, max-age=300")
  discovery() {
    const issuer = this.issuer;
    return {
      issuer,
      authorization_endpoint: `${issuer}/oidc/authorize`,
      token_endpoint: `${issuer}/oidc/token`,
      userinfo_endpoint: `${issuer}/oidc/userinfo`,
      jwks_uri: `${issuer}/oidc/jwks.json`,
      end_session_endpoint: `${issuer}/oidc/end_session`,
      revocation_endpoint: `${issuer}/oidc/revoke`,
      introspection_endpoint: `${issuer}/oidc/introspect`,

      scopes_supported: ALL_SCOPES,
      response_types_supported: ["code"],
      // No implicit or hybrid flow. Both return tokens through the browser
      // front channel, which is what PKCE + code exchange exists to avoid.
      //
      // Only what is actually implemented is advertised. client_credentials
      // (service-to-service) and the token-exchange grant that backs delegated
      // agent tokens land with W2; listing them now would have clients attempt
      // a grant this server rejects.
      grant_types_supported: [
        GRANT_TYPE.AUTHORIZATION_CODE,
        GRANT_TYPE.REFRESH_TOKEN,
      ],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
        // Public clients (browser, mobile, desktop) authenticate with PKCE
        // alone — they cannot keep a secret, and pretending otherwise just
        // ships the secret to every install.
        "none",
      ],
      code_challenge_methods_supported: [PKCE_METHOD_S256],
      claims_supported: [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "sid",
        "email",
        "name",
        "tenantId",
        "realm",
        "roles",
        "permissions",
        "scope",
        "plat",
        "amr",
        "mfaVerified",
      ],
      request_parameter_supported: false,
      require_pkce: true,
    };
  }

  @ApiOperation({ summary: "JSON Web Key Set (public signing keys)" })
  @Get("oidc/jwks.json")
  @Header("Cache-Control", "public, max-age=300")
  async jwks() {
    return this.keys.getPublicJwks();
  }
}
