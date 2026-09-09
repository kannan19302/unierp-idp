import {
  Controller,
  Get,
  Param,
  Query,
  Req,
  Res,
  BadRequestException,
  UseGuards,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { Request, Response } from "express";
import { OAuthService, OAuthProviderName } from "./oauth.service";
import type { ExternalAuthJourney } from "./external-auth.store";
import { JwtAuthGuard } from "../../common/guards/jwt-auth.guard";
import { Public } from "../../common/decorators/public.decorator";

const AUTH_COOKIE = "auth_token";
const REFRESH_COOKIE = "refresh_token";
const REFRESH_COOKIE_PATH = "/api/v1/auth";

function appUrl() {
  return process.env.APP_URL || "http://localhost:3000";
}

function assertProvider(value: string): OAuthProviderName {
  if (value !== "google" && value !== "microsoft" && value !== "github") {
    throw new BadRequestException("Unknown OAuth provider.");
  }
  return value;
}

function assertJourney(value?: string): ExternalAuthJourney {
  if (!value || value === "login") return "login";
  if (value === "register") return value;
  throw new BadRequestException("Unknown external authentication journey.");
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
  @Public("Authentication provider discovery contains no tenant session data")
  @Get("providers")
  async listProviders(@Query("journey") journeyParam?: string) {
    return this.oauthService.listProviders(assertJourney(journeyParam));
  }

  @ApiOperation({ summary: "Start OAuth sign-in (302 to the provider)" })
  @Public("OAuth sign-in initiation creates and later validates a server-side state transaction")
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Get(":provider/start")
  async start(
    @Param("provider") providerParam: string,
    @Query("tenantSlug") tenantSlug: string | undefined,
    @Query("return_to") returnTo: string | undefined,
    @Query("journey") journeyParam: string | undefined,
    @Res() res: Response,
  ) {
    const provider = assertProvider(providerParam);
    const url = await this.oauthService.buildAuthorizationUrl(
      provider,
      tenantSlug,
      returnTo,
      assertJourney(journeyParam),
    );
    res.redirect(url);
  }

  @ApiOperation({ summary: "Connect an external provider to the current account" })
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @UseGuards(JwtAuthGuard)
  @Get(":provider/link")
  async link(
    @Param("provider") providerParam: string,
    @Query("return_to") returnTo: string | undefined,
    @Req() req: Request & {
      user?: { userId?: string; tenantId?: string; sid?: string };
    },
    @Res() res: Response,
  ) {
    const provider = assertProvider(providerParam);
    const userId = req.user?.userId;
    const tenantId = req.user?.tenantId;
    const sid = req.user?.sid;
    if (!userId || !tenantId || !sid) {
      throw new BadRequestException("A tenant user session is required.");
    }
    const url = await this.oauthService.buildLinkAuthorizationUrl(
      provider,
      userId,
      tenantId,
      sid,
      returnTo || "/oidc/account",
    );
    res.redirect(url);
  }

  @ApiOperation({ summary: "OAuth provider callback (302 back to the app)" })
  @Public("OAuth callback validates the provider response against the one-time server-side state transaction")
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
      res.redirect(`/oidc/login?error=${encodeURIComponent(message)}`);

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

      if (result.kind === "registration") {
        const params = new URLSearchParams({
          external_auth: result.registrationTicket,
          return_to: result.returnTo,
        });
        return res.redirect(`/oidc/register?${params.toString()}`);
      }

      res.cookie(AUTH_COOKIE, String(result.token || ""), {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      res.cookie(REFRESH_COOKIE, String(result.refreshToken || ""), {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        expires: result.refreshExpiresAt as Date,
      });

      const defaultDestination =
        process.env.TENANT_APP_URL
          ? `${process.env.TENANT_APP_URL}/apps`
          : process.env.PLATFORM_WIZARD_URL || "http://localhost:4000";

      if (result.returnTo && result.returnTo !== "/" && result.returnTo !== "") {
        if (
          result.returnTo.startsWith("http://") ||
          result.returnTo.startsWith("https://") ||
          result.returnTo.startsWith("/oidc/")
        ) {
          return res.redirect(result.returnTo);
        }
      }
      return res.redirect(defaultDestination);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Sign-in could not be completed.";
      return fail(message);
    }
  }
}
