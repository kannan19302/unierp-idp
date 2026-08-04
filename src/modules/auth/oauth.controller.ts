import {
  Controller,
  Get,
  Param,
  Query,
  Req,
  Res,
  BadRequestException,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { Request, Response } from "express";
import { OAuthService, OAuthProviderName } from "./oauth.service";

const AUTH_COOKIE = "auth_token";
const REFRESH_COOKIE = "refresh_token";
const REFRESH_COOKIE_PATH = "/api/v1/auth";

function appUrl() {
  return process.env.APP_URL || "http://localhost:3000";
}

function assertProvider(value: string): OAuthProviderName {
  if (value !== "google" && value !== "microsoft") {
    throw new BadRequestException("Unknown OAuth provider.");
  }
  return value;
}

/**
 * Browser-redirect endpoints for the OAuth authorization-code flow. These are
 * top-level navigations (not fetch), so they live outside the JSON API shape:
 * errors surface as a redirect back to /login?error=…
 */
@ApiTags("auth")
@Controller("auth/oauth")
export class OAuthController {
  constructor(private readonly oauthService: OAuthService) {}

  @ApiOperation({ summary: "List configured OAuth providers" })
  @Get("providers")
  async listProviders() {
    return this.oauthService.listProviders();
  }

  @ApiOperation({ summary: "Start OAuth sign-in (302 to the provider)" })
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Get(":provider/start")
  async start(
    @Param("provider") providerParam: string,
    @Query("tenantSlug") tenantSlug: string | undefined,
    @Res() res: Response,
  ) {
    const provider = assertProvider(providerParam);
    const url = await this.oauthService.buildAuthorizationUrl(
      provider,
      tenantSlug,
    );
    res.redirect(url);
  }

  @ApiOperation({ summary: "OAuth provider callback (302 back to the app)" })
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Get(":provider/callback")
  async callback(
    @Param("provider") providerParam: string,
    @Query("code") code: string | undefined,
    @Query("state") state: string | undefined,
    @Query("error") providerError: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const provider = assertProvider(providerParam);
    const fail = (message: string) =>
      res.redirect(`${appUrl()}/login?error=${encodeURIComponent(message)}`);

    if (providerError) {
      return fail(`Sign-in was cancelled (${providerError}).`);
    }
    if (!code || !state) {
      return fail("Sign-in response was incomplete. Please try again.");
    }

    try {
      const result = await this.oauthService.handleCallback(
        provider,
        code,
        state,
        {
          ipAddress:
            (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
            req.ip ||
            null,
          userAgent: (req.headers["user-agent"] as string) || null,
        },
      );

      res.cookie(AUTH_COOKIE, result.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/",
        maxAge: 24 * 60 * 60 * 1000,
      });
      res.cookie(REFRESH_COOKIE, result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: REFRESH_COOKIE_PATH,
        expires: result.refreshExpiresAt,
      });
      // The complete page rotates the refresh cookie into a client-side
      // session (localStorage token + user) and forwards to the workspace.
      return res.redirect(`${appUrl()}/oauth/complete`);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Sign-in could not be completed.";
      return fail(message);
    }
  }
}
