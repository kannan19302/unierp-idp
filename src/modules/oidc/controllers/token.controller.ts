import {
  Body,
  Controller,
  Header,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
} from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { createLocalJWKSet, jwtVerify } from "jose";
import { idpPrisma, runWithTenantSession } from "@kannan19302/database";
import { AuthService } from "../../auth/auth.service";
import { AuthorizationService, OAuthError } from "../services/authorization.service";
import { OidcClientService } from "../services/oidc-client.service";
import { OidcTokenService } from "../services/oidc-token.service";
import { SigningKeyService } from "../services/signing-key.service";
import { AgentDelegationService } from "../services/agent-delegation.service";
import {
  GRANT_TYPE,
  OAUTH_ERROR,
  SCOPE,
  TOKEN_TTL,
} from "../oidc.constants";

interface TokenRequestBody {
  grant_type?: string;
  code?: string;
  redirect_uri?: string;
  code_verifier?: string;
  refresh_token?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
  // RFC 8693 token exchange (agent delegation only — see AgentDelegationService).
  subject_token?: string;
  subject_token_type?: string;
  requested_token_type?: string;
  // Which registered agent this exchange is for. Not an RFC 8693 standard
  // parameter — the closest standard fit (`resource`/`audience`) identifies an
  // API, not a delegate identity, so a dedicated parameter is clearer than
  // overloading one that means something else.
  agent_id?: string;
}

/**
 * The token endpoint.
 *
 * Everything the browser could have tampered with is re-checked here against
 * server-side state: the code, the client, the redirect URI, the PKCE verifier
 * and the session. Nothing is trusted because it arrived in the request.
 */
@ApiTags("oidc")
@Controller("oidc")
export class TokenController {
  constructor(
    private readonly clients: OidcClientService,
    private readonly authorization: AuthorizationService,
    private readonly tokens: OidcTokenService,
    private readonly auth: AuthService,
    private readonly keys: SigningKeyService,
    private readonly agents: AgentDelegationService,
  ) {}

  @ApiOperation({ summary: "OAuth 2.0 token endpoint" })
  @Post("token")
  @HttpCode(HttpStatus.OK)
  // Tokens must never be cached by an intermediary. RFC 6749 §5.1 requires it.
  @Header("Cache-Control", "no-store")
  @Header("Pragma", "no-cache")
  async token(
    @Body() body: TokenRequestBody,
    @Headers("authorization") authorizationHeader?: string,
  ) {
    try {
      const credentials = resolveClientCredentials(body, authorizationHeader);
      const client = await this.clients.getActiveClient(credentials.clientId);
      await this.clients.authenticateClient(client, credentials.clientSecret);

      switch (body.grant_type) {
        case GRANT_TYPE.AUTHORIZATION_CODE:
          this.clients.assertGrantAllowed(client, GRANT_TYPE.AUTHORIZATION_CODE);
          return await this.authorizationCodeGrant(client, body);

        case GRANT_TYPE.REFRESH_TOKEN:
          this.clients.assertGrantAllowed(client, GRANT_TYPE.REFRESH_TOKEN);
          return await this.refreshTokenGrant(client, body);

        case GRANT_TYPE.TOKEN_EXCHANGE:
          this.clients.assertGrantAllowed(client, GRANT_TYPE.TOKEN_EXCHANGE);
          return await this.tokenExchangeGrant(client, body);

        default:
          throw new OAuthError(
            OAUTH_ERROR.UNSUPPORTED_GRANT_TYPE,
            `Unsupported grant_type: ${body.grant_type ?? "(missing)"}`,
          );
      }
    } catch (err) {
      // OAuth errors are a protocol response, not an exception surface: clients
      // branch on `error`, so they must come back as a JSON body.
      if (err instanceof OAuthError) {
        return { error: err.code, error_description: err.message };
      }
      throw err;
    }
  }

  // ── grants ───────────────────────────────────────────────────────────────

  private async authorizationCodeGrant(
    client: Awaited<ReturnType<OidcClientService["getActiveClient"]>>,
    body: TokenRequestBody,
  ) {
    if (!body.code || !body.redirect_uri || !body.code_verifier) {
      throw new OAuthError(
        OAUTH_ERROR.INVALID_REQUEST,
        "code, redirect_uri and code_verifier are required",
      );
    }

    const grant = await this.authorization.redeemCode({
      code: body.code,
      clientId: client.clientId,
      redirectUri: body.redirect_uri,
      codeVerifier: body.code_verifier,
    });

    return this.issueTokens({
      client,
      userId: grant.userId,
      tenantId: grant.tenantId,
      sid: grant.sid,
      scopes: grant.scopes,
      nonce: grant.nonce,
      includeIdToken: grant.scopes.includes(SCOPE.OPENID),
    });
  }

  private async refreshTokenGrant(
    client: Awaited<ReturnType<OidcClientService["getActiveClient"]>>,
    body: TokenRequestBody,
  ) {
    if (!body.refresh_token) {
      throw new OAuthError(
        OAUTH_ERROR.INVALID_REQUEST,
        "refresh_token is required",
      );
    }

    const { grant, newRefreshToken } = await this.tokens.rotateRefreshToken({
      refreshToken: body.refresh_token,
      clientId: client.clientId,
    });

    // Permissions are re-read on every refresh rather than carried forward from
    // the original grant. Demoting a user must take effect at the next refresh
    // at the latest — a token that renews its own stale authority indefinitely
    // would make role changes unenforceable.
    return this.issueTokens({
      client,
      userId: grant.userId,
      tenantId: grant.tenantId,
      sid: grant.sid,
      scopes: grant.scopes,
      existingRefreshToken: newRefreshToken,
      includeIdToken: false,
    });
  }

  /**
   * RFC 8693 token exchange, restricted to minting delegated AGENT tokens.
   *
   * The subject_token must be a live, currently-valid access token this IdP
   * itself issued — verified the same way any relying party would verify it,
   * against the published JWKS, never trusted because it arrived in a request
   * body. A subject token that already carries an `act` claim is refused: it
   * is itself a delegated agent token, and chaining agent-for-agent delegation
   * would let effective authority drift arbitrarily far from the human
   * actually accountable for it.
   */
  private async tokenExchangeGrant(
    client: Awaited<ReturnType<OidcClientService["getActiveClient"]>>,
    body: TokenRequestBody,
  ) {
    if (!body.subject_token || !body.agent_id) {
      throw new OAuthError(
        OAUTH_ERROR.INVALID_REQUEST,
        "subject_token and agent_id are required",
      );
    }

    const jwks = createLocalJWKSet(await this.keys.getPublicJwks());
    let subject: Record<string, unknown>;
    try {
      const verified = await jwtVerify(body.subject_token, jwks, {
        issuer: process.env.OIDC_ISSUER ?? "http://localhost:3005",
      });
      subject = verified.payload;
    } catch {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid subject_token");
    }

    if (subject.typ !== "session") {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid subject_token");
    }
    if (subject.act) {
      // Chained delegation. Refused structurally, not merely discouraged.
      throw new OAuthError(
        OAUTH_ERROR.INVALID_GRANT,
        "An agent token cannot be exchanged for another agent token",
      );
    }

    const sid = String(subject.sid ?? "");
    const tenantIdForLookup = String(subject.tenantId ?? "");
    // Same RLS trap documented at length in api/src/common/guards/jwt-auth.guard.ts:
    // user_sessions is RLS-protected, so this read is invisible without a
    // tenant session established from the subject token's own (already
    // signature-verified) tenantId claim.
    const session = await runWithTenantSession(
      { tenantId: tenantIdForLookup, userId: String(subject.sub ?? "") },
      () =>
        idpPrisma.userSession.findUnique({
          where: { id: sid },
          select: { isActive: true, expiresAt: true },
        }),
    );
    if (
      !session ||
      !session.isActive ||
      (session.expiresAt && session.expiresAt < new Date())
    ) {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Subject session is no longer active");
    }

    const grant = await this.agents.exchange({
      subjectUserId: String(subject.sub ?? ""),
      subjectTenantId: String(subject.tenantId ?? ""),
      subjectSid: sid,
      subjectPermissions: (subject.permissions as string[]) ?? [],
      subjectRealm: (subject.realm as "tenant" | "provider") ?? "tenant",
      agentId: body.agent_id,
    });

    const accessToken = await this.tokens.mintAccessToken({
      sub: String(subject.sub ?? ""),
      sid: grant.sid,
      tenantId: String(subject.tenantId ?? ""),
      realm: (subject.realm as "tenant" | "provider") ?? "tenant",
      roles: [],
      permissions: grant.effectivePermissions,
      scopes: ["agent"],
      clientId: client.clientId,
      platformCode: client.platformCode,
      act: { agentId: grant.agentId },
    });

    return {
      access_token: accessToken,
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      token_type: "Bearer" as const,
      expires_in: Math.floor(TOKEN_TTL.AGENT_TOKEN_MS / 1000),
      scope: "agent",
    };
  }

  // ── token assembly ───────────────────────────────────────────────────────

  private async issueTokens(params: {
    client: Awaited<ReturnType<OidcClientService["getActiveClient"]>>;
    userId: string;
    tenantId: string;
    sid: string;
    scopes: string[];
    nonce?: string | null;
    includeIdToken: boolean;
    existingRefreshToken?: string;
  }) {
    const { roles, permissions } = await this.auth.resolveRolesAndPermissions(
      params.userId,
      params.tenantId,
    );

    // Tenant-scoped, like the user_sessions read above: `users` is RLS
    // ENABLE + FORCE, so an unscoped lookup returns null and the id_token is
    // minted with no email or name — the `email` and `profile` scopes appear
    // to be granted and then release nothing, which is much harder to spot
    // than an outright failure.
    const user = await runWithTenantSession(
      { tenantId: params.tenantId, userId: params.userId },
      () =>
        idpPrisma.user.findUnique({
          where: { id: params.userId },
          select: { email: true, firstName: true, lastName: true, tenantId: true },
        }),
    );

    // The realm decides whether control-plane permissions are even reachable.
    // It is derived from the client's platform binding, not sent by the caller.
    const realm =
      params.client.platformCode === "P2" ? ("provider" as const) : ("tenant" as const);

    const accessToken = await this.tokens.mintAccessToken({
      sub: params.userId,
      sid: params.sid,
      tenantId: params.tenantId,
      realm,
      roles,
      permissions,
      scopes: params.scopes,
      clientId: params.client.clientId,
      platformCode: params.client.platformCode,
    });

    const idToken = params.includeIdToken
      ? await this.tokens.mintIdToken({
          sub: params.userId,
          clientId: params.client.clientId,
          sid: params.sid,
          tenantId: params.tenantId,
          email: user?.email,
          name: user ? `${user.firstName} ${user.lastName}`.trim() : undefined,
          nonce: params.nonce ?? null,
          scopes: params.scopes,
        })
      : undefined;

    // A refresh token is only issued when offline_access was granted. Handing
    // one out unconditionally would give every client a long-lived credential
    // it never asked for.
    let refreshToken = params.existingRefreshToken;
    if (!refreshToken && params.scopes.includes(SCOPE.OFFLINE_ACCESS)) {
      refreshToken = await this.tokens.issueRefreshToken({
        clientId: params.client.clientId,
        userId: params.userId,
        tenantId: params.tenantId,
        sid: params.sid,
        scopes: params.scopes,
      });
    }

    return {
      access_token: accessToken,
      token_type: "Bearer" as const,
      expires_in: Math.floor(TOKEN_TTL.ACCESS_TOKEN_MS / 1000),
      scope: params.scopes.join(" "),
      ...(idToken ? { id_token: idToken } : {}),
      ...(refreshToken ? { refresh_token: refreshToken } : {}),
    };
  }
}

/**
 * Extracts client credentials from either supported location.
 *
 * `client_secret_basic` (the Authorization header) takes precedence over
 * `client_secret_post` (the body). RFC 6749 §2.3.1 prefers the header, and
 * accepting both at once would let a caller present two identities in one
 * request and leave which one applies up to implementation order.
 */
export function resolveClientCredentials(
  body: { client_id?: string; client_secret?: string },
  authorizationHeader?: string,
): { clientId: string; clientSecret?: string } {
  if (authorizationHeader?.toLowerCase().startsWith("basic ")) {
    const decoded = Buffer.from(
      authorizationHeader.slice(6).trim(),
      "base64",
    ).toString("utf8");
    // The separator is the FIRST colon: a secret may legitimately contain one.
    const idx = decoded.indexOf(":");
    if (idx === -1) {
      throw new OAuthError(
        OAUTH_ERROR.INVALID_CLIENT,
        "Malformed Basic authorization header",
      );
    }
    return {
      // Both halves are form-urlencoded per RFC 6749 §2.3.1.
      clientId: decodeURIComponent(decoded.slice(0, idx)),
      clientSecret: decodeURIComponent(decoded.slice(idx + 1)),
    };
  }

  return {
    clientId: body.client_id ?? "",
    clientSecret: body.client_secret,
  };
}
