import {
  Body,
  Controller,
  Get,
  Post,
  Param,
  Query,
  Req,
  Res,
} from "@nestjs/common";
import type { Request, Response } from "express";
import { ApiExcludeController } from "@nestjs/swagger";
import { ApiTags, ApiOperation, ApiBearerAuth } from "@nestjs/swagger";
import { SsoService } from "./sso.service";
import { setSessionCookies } from "../oidc/controllers/login.controller";

/**
 * Tenant-level inbound SSO federation: a tenant's OWN external IdP (SAML or
 * OIDC), configured from the tenant admin console
 * (api/src/modules/saas-portal/services/security.service.ts) and gated to
 * the Enterprise plan (sso-plan-gate.ts).
 *
 * The SAML and OIDC callbacks were DISABLED (W0) because the previous
 * implementation read an `email` out of an unsigned JSON request body and
 * minted a session cookie from it directly — no signature verification, no
 * library, and any unauthenticated caller who knew a tenant slug and a
 * user's email could obtain that user's session. This replaces that with
 * real verification: `@node-saml/node-saml` validates the SAML assertion's
 * signature against the tenant's stored certificate before any session is
 * issued, and the OIDC path exchanges the authorization code directly with
 * the tenant's own token endpoint over TLS (the same trust boundary
 * oauth.service.ts already relies on for Google/Microsoft) rather than
 * trusting anything handed to us by the browser.
 */
@ApiExcludeController()
@Controller("auth/sso")
export class SsoController {
  constructor(private readonly ssoService: SsoService) {}

  @ApiOperation({ summary: "Begin SAML federation" })
  @Get("saml/login/:tenantSlug")
  async samlLogin(
    @Param("tenantSlug") tenantSlug: string,
    @Query("return_to") returnTo: string | undefined,
    @Res() res: Response,
  ): Promise<void> {
    const url = await this.ssoService.buildSamlLoginUrl(tenantSlug, safeReturnTo(returnTo));
    res.redirect(url);
  }

  @ApiOperation({ summary: "SAML assertion consumer service" })
  @Post("saml/callback/:tenantSlug")
  async samlCallback(
    @Param("tenantSlug") tenantSlug: string,
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const { session, returnTo } = await this.ssoService.handleSamlCallback(
      tenantSlug,
      body,
      { ipAddress: req.ip, userAgent: req.headers["user-agent"] } as never,
    );
    setSessionCookies(res, session as unknown as Record<string, unknown>);
    res.redirect(safeReturnTo(returnTo));
  }

  @ApiOperation({ summary: "Begin OIDC federation" })
  @Get("oidc/login/:tenantSlug")
  async oidcLogin(
    @Param("tenantSlug") tenantSlug: string,
    @Query("return_to") returnTo: string | undefined,
    @Res() res: Response,
  ): Promise<void> {
    const url = await this.ssoService.buildOidcLoginUrl(tenantSlug, safeReturnTo(returnTo));
    res.redirect(url);
  }

  @ApiOperation({ summary: "OIDC federation callback" })
  @Get("oidc/callback/:tenantSlug")
  async oidcCallback(
    @Param("tenantSlug") tenantSlug: string,
    @Query("code") code: string,
    @Query("state") state: string,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const { session, returnTo } = await this.ssoService.handleOidcCallback(
      tenantSlug,
      code,
      state,
      { ipAddress: req.ip, userAgent: req.headers["user-agent"] } as never,
    );
    setSessionCookies(res, session as unknown as Record<string, unknown>);
    res.redirect(safeReturnTo(returnTo));
  }

  @ApiTags("auth")
  @ApiBearerAuth()
  @ApiOperation({ summary: "Get sso config" })
  @Get("config/:tenantSlug")
  async getSsoConfig(@Param("tenantSlug") tenantSlug: string) {
    // Public endpoint — returns SSO entry points for the login page. Mints
    // nothing; only advertises whether the buttons above should be shown.
    return this.ssoService.getSsoConfigByTenantSlug(tenantSlug);
  }
}

/** Mirrors login.controller.ts's safeReturnTo — same open-redirect concern, same fix. */
function safeReturnTo(candidate?: string): string {
  const fallback = "/oidc/authorize";
  if (!candidate) return fallback;
  if (!candidate.startsWith("/")) return fallback;
  if (candidate.startsWith("//")) return fallback;
  if (candidate.startsWith("/\\")) return fallback;
  return candidate;
}
