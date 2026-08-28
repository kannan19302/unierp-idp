import {
  Controller,
  Get,
  Query,
  Req,
  Res,
  BadRequestException,
} from "@nestjs/common";
import type { Request, Response } from "express";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { verifyTypedToken, TOKEN_TYPE } from "@kannan19302/auth";
import { idpPrisma, runWithTenantSession } from "@kannan19302/database";
import { AuthorizationService, OAuthError } from "../services/authorization.service";
import { OidcClientService } from "../services/oidc-client.service";
import { PlatformEntitlementService } from "../services/platform-entitlement.service";
import { OAUTH_ERROR, PKCE_METHOD_S256 } from "../oidc.constants";
import { Public } from "../../../common/decorators/public.decorator";

const AUTH_COOKIE = "auth_token";

interface AuthorizeQuery {
  response_type?: string;
  client_id?: string;
  redirect_uri?: string;
  scope?: string;
  state?: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  prompt?: string;
}

/**
 * The authorization endpoint.
 *
 * Two rules govern how failures are reported here, and they differ from every
 * other endpoint:
 *
 *  1. Until the client and its redirect_uri are both validated, errors are
 *     shown to the USER and never redirected. Redirecting an error to an
 *     unverified URI turns this endpoint into an open redirect, which is the
 *     exact primitive phishing needs.
 *  2. Once the redirect_uri is known-good, errors go BACK to the client as
 *     query parameters, because that is where a relying party looks for them.
 */
@ApiTags("oidc")
@Controller("oidc")
export class AuthorizeController {
  constructor(
    private readonly clients: OidcClientService,
    private readonly authorization: AuthorizationService,
    private readonly platformAccess: PlatformEntitlementService,
  ) {}

  @ApiOperation({ summary: "OAuth 2.0 / OIDC authorization endpoint" })
  @Public("OIDC authorization begins a browser flow and validates client, redirect URI, PKCE and session itself")
  @Get("authorize")
  async authorize(
    @Query() query: AuthorizeQuery,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    // ── Phase 1: nothing may be redirected yet ────────────────────────────
    let client;
    try {
      client = await this.clients.getActiveClient(query.client_id ?? "");
      this.clients.validateRedirectUri(client, query.redirect_uri ?? "");
    } catch (err) {
      const message =
        err instanceof OAuthError ? err.message : "Invalid authorization request";
      throw new BadRequestException(message);
    }

    const redirectUri = query.redirect_uri as string;

    // ── Phase 2: the redirect target is trusted, so errors can go home ────
    try {
      if (query.response_type !== "code") {
        throw new OAuthError(
          OAUTH_ERROR.UNSUPPORTED_RESPONSE_TYPE,
          "Only the authorization code flow is supported",
        );
      }

      if (!query.code_challenge) {
        throw new OAuthError(
          OAUTH_ERROR.INVALID_REQUEST,
          "code_challenge is required (PKCE is mandatory)",
        );
      }
      if ((query.code_challenge_method ?? "") !== PKCE_METHOD_S256) {
        throw new OAuthError(
          OAUTH_ERROR.INVALID_REQUEST,
          "code_challenge_method must be S256",
        );
      }

      const scopes = this.clients.resolveScopes(
        client,
        (query.scope ?? "").split(" ").filter(Boolean),
      );

      // ── Who is signed in? ──────────────────────────────────────────────
      const session = await resolveSession(req);
      if (!session) {
        if (query.prompt === "none") {
          // The client asked for a silent attempt; tell it plainly rather than
          // bouncing the user's browser to a login form it did not expect.
          throw new OAuthError(
            OAUTH_ERROR.LOGIN_REQUIRED,
            "No active session",
          );
        }
        // Send the user to sign in, preserving the whole request so the flow
        // resumes exactly where it left off afterwards.
        const returnTo = `${req.baseUrl}${req.path}?${new URLSearchParams(
          query as Record<string, string>,
        ).toString()}`;
        res.redirect(
          `/oidc/login?return_to=${encodeURIComponent(returnTo)}`,
        );
        return;
      }

      // ── May this user enter this platform at all? ──────────────────────
      // Enforced here, at the issuer, rather than by hiding a tile in the UI:
      // a tenant user who types the provider console's URL is refused a token,
      // not merely shown a smaller menu.
      await this.platformAccess.assertMayAccess({
        platformCode: client.platformCode,
        realm: session.realm,
        roles: session.roles,
        permissions: session.permissions,
        tenantId: session.tenantId,
        userId: session.userId,
      });

      if (
        await this.clients.needsConsent(
          client,
          session.userId,
          session.tenantId,
          scopes,
        )
      ) {
        const returnTo = `${req.baseUrl}${req.path}?${new URLSearchParams(
          query as Record<string, string>,
        ).toString()}`;
        res.redirect(
          `/oidc/consent?client_id=${encodeURIComponent(
            client.clientId,
          )}&scope=${encodeURIComponent(scopes.join(" "))}&return_to=${encodeURIComponent(returnTo)}`,
        );
        return;
      }

      const code = await this.authorization.issueCode({
        clientId: client.clientId,
        userId: session.userId,
        tenantId: session.tenantId,
        sid: session.sid,
        redirectUri,
        scopes,
        codeChallenge: query.code_challenge,
        codeChallengeMethod: PKCE_METHOD_S256,
        nonce: query.nonce,
      });

      const success = new URL(redirectUri);
      success.searchParams.set("code", code);
      // `state` is echoed verbatim; it is the client's CSRF defence and it is
      // the client, not this server, that decides what it means.
      if (query.state) success.searchParams.set("state", query.state);
      res.redirect(success.toString());
    } catch (err) {
      const failure = new URL(redirectUri);
      failure.searchParams.set(
        "error",
        err instanceof OAuthError ? err.code : OAUTH_ERROR.SERVER_ERROR,
      );
      failure.searchParams.set(
        "error_description",
        err instanceof OAuthError ? err.message : "Authorization failed",
      );
      if (query.state) failure.searchParams.set("state", query.state);
      res.redirect(failure.toString());
    }
  }
}

export interface ResolvedSession {
  userId: string;
  tenantId: string;
  sid: string;
  permissions: string[];
  roles: string[];
  realm: "tenant" | "provider";
}

/**
 * Reads the current browser session.
 *
 * Deliberately mirrors JwtAuthGuard rather than trusting the cookie's contents:
 * the signature is verified, the purpose claim is checked so a password-reset
 * token cannot stand in for a session, and the session row must still be active.
 */
export async function resolveSession(
  req: Request,
): Promise<ResolvedSession | null> {
  const token = (req as unknown as { cookies?: Record<string, string> }).cookies?.[
    AUTH_COOKIE
  ];
  if (!token) return null;

  const decoded = verifyTypedToken<{
    userId?: string;
    tenantId?: string;
    sid?: string;
    permissions?: string[];
    roles?: string[];
    realm?: "tenant" | "provider";
  }>(token, TOKEN_TYPE.SESSION);

  if (!decoded?.sid || !decoded.userId || !decoded.tenantId) return null;

  // The lookup MUST run inside a tenant session derived from the token's own
  // (already signature-verified) tenantId.
  //
  // user_sessions carries RLS with ENABLE + FORCE and the application role is
  // NOBYPASSRLS, so querying it with no tenant context returns zero rows — not
  // "revoked", simply invisible. Without this, resolveSession() returned null
  // for every valid cookie and /oidc/authorize bounced every single request to
  // the login page: SSO could never work against a correctly-secured database,
  // and appeared to work only where RLS was unenforced or the connection was
  // the table owner. Same trap, same reasoning, and same fix as
  // common/guards/jwt-auth.guard.ts — see its comment for the longer history.
  const session = await runWithTenantSession(
    { tenantId: decoded.tenantId, userId: decoded.userId },
    () =>
      idpPrisma.userSession.findUnique({
        where: { id: decoded.sid },
        select: { isActive: true, expiresAt: true },
      }),
  );
  if (
    !session ||
    !session.isActive ||
    (session.expiresAt && session.expiresAt < new Date())
  ) {
    return null;
  }

  return {
    userId: decoded.userId,
    tenantId: decoded.tenantId,
    sid: decoded.sid,
    permissions: decoded.permissions ?? [],
    roles: decoded.roles ?? [],
    realm: decoded.realm ?? "tenant",
  };
}
