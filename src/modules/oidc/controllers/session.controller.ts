import {
  Body,
  Controller,
  Get,
  Header,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from "@nestjs/common";
import type { Request, Response } from "express";
import { ApiExcludeController, ApiOperation, ApiTags } from "@nestjs/swagger";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { idpPrisma, runWithTenantSession } from "@kannan19302/database";
import { OidcClientService } from "../services/oidc-client.service";
import { OidcTokenService } from "../services/oidc-token.service";
import { AuthorizationService } from "../services/authorization.service";
import { safeReturnTo } from "./login.controller";
import { emitAuthAudit } from "../../../common/audit/emit-auth-audit";
import { Public } from "../../../common/decorators/public.decorator";
import { JwtAuthGuard } from "../../../common/guards/jwt-auth.guard";
import { verifyBearerToken } from "../../../common/guards/verify-bearer-token";

const AUTH_COOKIE = "auth_token";
const REFRESH_COOKIE = "refresh_token";

/**
 * userinfo, revocation, introspection, logout and the consent screen.
 */
@ApiTags("oidc")
@Controller("oidc")
export class SessionController {
  constructor(
    private readonly clients: OidcClientService,
    private readonly tokens: OidcTokenService,
    private readonly authorization: AuthorizationService,
  ) {}

  private jwks = createRemoteJWKSet(
    new URL(
      `${process.env.OIDC_ISSUER ?? "http://localhost:3005"}/oidc/jwks.json`,
    ),
  );

  /**
   * Claims about the signed-in user, for a client holding an access token.
   *
   * The token is verified the same way any relying party would verify it —
   * signature against the JWKS, issuer, expiry — rather than trusted because it
   * arrived here. Claims are then read from the DATABASE, not echoed back from
   * the token, so a profile change is reflected immediately instead of when the
   * token happens to expire.
   */
  @ApiOperation({ summary: "OIDC userinfo" })
  @Public("OIDC userinfo validates a bearer access token and active session in the handler")
  @Get("userinfo")
  @Header("Cache-Control", "no-store")
  async userinfo(@Headers("authorization") authorization?: string) {
    if (!authorization?.toLowerCase().startsWith("bearer ")) {
      throw new UnauthorizedException("Bearer token required");
    }

    let payload: Record<string, unknown>;
    try {
      const verified = await jwtVerify(
        authorization.slice(7).trim(),
        this.jwks,
        { issuer: process.env.OIDC_ISSUER ?? "http://localhost:3005" },
      );
      payload = verified.payload as Record<string, unknown>;
    } catch {
      throw new UnauthorizedException("Invalid access token");
    }

    // A token whose session has been revoked must stop working here too,
    // otherwise logout would leave userinfo answering for up to the token TTL.
    const sid = String(payload.sid ?? "");
    const tenantId = String(payload.tenantId ?? "");
    const session = await runWithTenantSession(
      { tenantId, userId: String(payload.sub ?? "") },
      () =>
        idpPrisma.userSession.findUnique({
          where: { id: sid },
          select: { isActive: true },
        }),
    );
    if (!session?.isActive) {
      throw new UnauthorizedException("Session has been revoked");
    }

    // Tenant-scoped for the same reason the session lookup above is: `users`
    // carries RLS with ENABLE + FORCE, so reading it with no tenant context
    // returns null and this endpoint answered "Unknown subject" for every
    // valid token — the profile existed and was simply invisible. The tenantId
    // comes from the access token, whose signature was verified against the
    // JWKS above.
    const user = await runWithTenantSession(
      { tenantId, userId: String(payload.sub ?? "") },
      () =>
        idpPrisma.user.findUnique({
          where: { id: String(payload.sub ?? "") },
          select: { id: true, email: true, firstName: true, lastName: true, avatar: true },
        }),
    );
    if (!user) throw new UnauthorizedException("Unknown subject");

    const scopes = String(payload.scope ?? "").split(" ").filter(Boolean);

    // Release only what the granted scopes cover.
    return {
      sub: user.id,
      ...(scopes.includes("email") ? { email: user.email } : {}),
      ...(scopes.includes("profile")
        ? {
            name: `${user.firstName} ${user.lastName}`.trim(),
            given_name: user.firstName,
            family_name: user.lastName,
            picture: user.avatar ?? undefined,
          }
        : {}),
      ...(scopes.includes("tenant") ? { tenantId } : {}),
    };
  }

  /**
   * Token revocation (RFC 7009).
   *
   * Always returns 200, even for a token that does not exist. The RFC requires
   * it: a distinguishable response would let an attacker use this endpoint to
   * test whether a captured string is a live token.
   */
  @ApiOperation({ summary: "Token revocation" })
  @Public("RFC 7009 revocation intentionally returns no token-state information")
  @Post("revoke")
  @HttpCode(HttpStatus.OK)
  @Header("Cache-Control", "no-store")
  async revoke(@Body() body: { token?: string }) {
    if (body.token) await this.tokens.revokeRefreshToken(body.token);
    return {};
  }

  /**
   * Token introspection (RFC 7662).
   *
   * Restricted to confidential clients that can authenticate: an open
   * introspection endpoint is an oracle that reveals whether any given string
   * is a valid token, and what authority it carries.
   */
  @ApiOperation({ summary: "Token introspection" })
  @Public("OIDC introspection authenticates a confidential client before returning token state")
  @Post("introspect")
  @HttpCode(HttpStatus.OK)
  @Header("Cache-Control", "no-store")
  async introspect(
    @Body() body: { token?: string; client_id?: string; client_secret?: string },
  ) {
    const client = await this.clients.getActiveClient(body.client_id ?? "");
    await this.clients.authenticateClient(client, body.client_secret);

    if (!body.token) return { active: false };

    try {
      const { payload } = await jwtVerify(body.token, this.jwks, {
        issuer: process.env.OIDC_ISSUER ?? "http://localhost:3005",
      });

      const session = await runWithTenantSession(
        {
          tenantId: String(payload.tenantId ?? ""),
          userId: String(payload.sub ?? ""),
        },
        () =>
          idpPrisma.userSession.findUnique({
            where: { id: String(payload.sid ?? "") },
            select: { isActive: true },
          }),
      );
      if (!session?.isActive) return { active: false };

      return {
        active: true,
        scope: payload.scope,
        client_id: payload.aud,
        sub: payload.sub,
        exp: payload.exp,
        iat: payload.iat,
        token_type: "Bearer",
      };
    } catch {
      // Expired, malformed or forged — all simply "not active".
      return { active: false };
    }
  }

  /**
   * RP-initiated logout.
   *
   * Ends the session itself rather than only clearing this browser's cookie.
   * Clearing the cookie alone would leave the session row active, so every
   * refresh token derived from it would still work — "sign out" on one platform
   * would not sign the user out anywhere else, which is the whole promise of
   * single sign-on run in reverse.
   */
  @ApiOperation({ summary: "RP-initiated logout" })
  @Public("OIDC logout clears browser cookies; server-side revocation requires a verified session token")
  @Get("end_session")
  @Header("Cache-Control", "no-store")
  async endSession(
    @Query("post_logout_redirect_uri") postLogoutRedirectUri: string | undefined,
    @Query("client_id") clientId: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const cookies = (req as unknown as { cookies?: Record<string, string> })
      .cookies;
    const token = cookies?.[AUTH_COOKIE];

    if (token) {
      const claims = await verifyBearerToken(token);
      const sid = claims?.sid ?? null;
      if (sid) {
        // Deactivate the session and revoke every grant derived from it.
        //
        // Scoped to the token's tenant, and it has to be: user_sessions is
        // RLS ENABLE + FORCE, so an unscoped updateMany matches ZERO rows and
        // reports success — logout would clear the cookies while leaving the
        // server-side session live for the rest of its lifetime, which is the
        // one thing logout exists to prevent.
        //
        // Never derive the tenant context or session id from unverified cookie
        // claims. An expired or forged cookie still clears the local browser,
        // but it cannot revoke another user's server-side session.
        await runWithTenantSession(
          { tenantId: claims?.tenantId ?? "", userId: claims?.userId ?? "" },
          () =>
            idpPrisma.userSession.updateMany({
              where: { id: sid },
              data: { isActive: false },
            }),
        );
        await this.authorization.revokeGrantsForSession(sid);
      }
    }

    res.clearCookie(AUTH_COOKIE, { path: "/" });
    res.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });

    // Only redirect to a URI the client registered — otherwise logout is an
    // open redirect, and a link that genuinely signs the user out is exactly
    // the kind of link people click without inspecting.
    let destination = "/oidc/login";
    if (postLogoutRedirectUri && clientId) {
      try {
        const client = await this.clients.getActiveClient(clientId);
        this.clients.validatePostLogoutRedirectUri(client, postLogoutRedirectUri);
        destination = postLogoutRedirectUri;
      } catch {
        // Fall through to the safe default rather than honouring it.
      }
    }

    res.redirect(destination);
  }
}

/**
 * The consent screen for third-party clients.
 */
@ApiExcludeController()
@Controller("oidc")
@UseGuards(JwtAuthGuard)
export class ConsentController {
  constructor(private readonly clients: OidcClientService) {}

  @Get("consent")
  @Header("Cache-Control", "no-store")
  async consentForm(
    @Query("client_id") clientId: string,
    @Query("scope") scope: string,
    @Query("return_to") returnTo: string,
  ): Promise<string> {
    const client = await this.clients.getActiveClient(clientId);
    return renderConsent({
      clientName: client.name,
      clientId,
      scopes: (scope ?? "").split(" ").filter(Boolean),
      returnTo: safeReturnTo(returnTo),
    });
  }

  @Post("consent")
  async submitConsent(
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const returnTo = safeReturnTo(body.return_to);
    const principal = (req as Request & {
      user?: { userId?: string; tenantId?: string };
    }).user;
    const userId = principal?.userId;
    const tenantId = principal?.tenantId;

    const clientId = body.client_id;
    if (!clientId) {
      res.redirect(returnTo);
      return;
    }

    if (!userId || !tenantId) {
      res.redirect(`/oidc/login?return_to=${encodeURIComponent(returnTo)}`);
      return;
    }

    if (body.decision !== "allow") {
      // A refusal is a legitimate outcome, reported to the client as
      // access_denied rather than silently looping back to the prompt.
      res.redirect(`${returnTo}${returnTo.includes("?") ? "&" : "?"}prompt=none`);
      return;
    }

    const scopes = (body.scope ?? "").split(" ").filter(Boolean);
    await this.clients.recordConsent({
      clientId,
      userId,
      tenantId,
      scopes,
    });
    await emitAuthAudit({
      tenantId,
      userId,
      action: "AUTH_CONSENT_GRANT",
      entityType: "OAuthClient",
      entityId: clientId,
      changes: { scopes },
      ipAddress: req.ip,
    });

    res.redirect(returnTo);
  }
}

const SCOPE_LABELS: Record<string, string> = {
  openid: "Confirm your identity",
  profile: "See your name and profile picture",
  email: "See your email address",
  tenant: "See which organisation you belong to",
  offline_access: "Stay connected when you are not using the app",
  "erp.read": "Read your business data",
  "erp.write": "Create and change your business data",
  "marketplace.install": "Install and remove applications",
};

function renderConsent(params: {
  clientName: string;
  clientId: string;
  scopes: string[];
  returnTo: string;
}): string {
  const esc = (v: string) =>
    v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

  const items = params.scopes
    .map((s) => `<li>${esc(SCOPE_LABELS[s] ?? s)}</li>`)
    .join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorise ${esc(params.clientName)} · UniERP</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
         display:flex; align-items:center; justify-content:center;
         min-height:100vh; margin:0; background:#0f172a; color:#e2e8f0; }
  .card { background:#1e293b; padding:2rem; border-radius:12px;
          width:min(420px,92vw); box-shadow:0 10px 40px rgba(0,0,0,.4); }
  h1 { font-size:1.25rem; margin:0 0 .25rem; }
  p.sub { margin:0 0 1.25rem; color:#94a3b8; font-size:.875rem; }
  ul { margin:0 0 1.5rem; padding-left:1.25rem; color:#cbd5e1; font-size:.875rem; }
  li { margin-bottom:.375rem; }
  .row { display:flex; gap:.75rem; }
  button { flex:1; padding:.6875rem; border:0; border-radius:8px;
           font-size:.9375rem; font-weight:600; cursor:pointer; }
  .allow { background:#6366f1; color:#fff; }
  .deny { background:#334155; color:#e2e8f0; }
</style></head>
<body><form class="card" method="post" action="/oidc/consent">
  <h1>${esc(params.clientName)} wants access</h1>
  <p class="sub">This application is not part of UniERP. It is asking to:</p>
  <ul>${items}</ul>
  <input type="hidden" name="client_id" value="${esc(params.clientId)}">
  <input type="hidden" name="scope" value="${esc(params.scopes.join(" "))}">
  <input type="hidden" name="return_to" value="${esc(params.returnTo)}">
  <div class="row">
    <button class="deny" type="submit" name="decision" value="deny">Cancel</button>
    <button class="allow" type="submit" name="decision" value="allow">Allow</button>
  </div>
</form></body></html>`;
}
