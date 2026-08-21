import { Controller, Get, Header, Headers, UnauthorizedException } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { PlatformEntitlementService } from "../services/platform-entitlement.service";

/**
 * `GET /auth/platforms` — the Global Platform Wizard's one data source.
 *
 * Renders the entitled-platform grid; the wizard shows a tile for exactly what
 * this returns, nothing hidden by client-side logic. The corresponding
 * enforcement — refusing a token for a platform not on this list — lives in
 * AuthorizeController via the same PlatformEntitlementService, so this
 * endpoint cannot drift from what /oidc/authorize actually allows.
 */
@ApiTags("auth")
@Controller("auth")
export class PlatformsController {
  constructor(private readonly entitlement: PlatformEntitlementService) {}

  private jwks = createRemoteJWKSet(
    new URL(
      `${process.env.OIDC_ISSUER ?? "http://localhost:3005"}/oidc/jwks.json`,
    ),
  );

  @ApiOperation({ summary: "Platforms entitled to the current session" })
  @Get("platforms")
  @Header("Cache-Control", "no-store")
  async listPlatforms(@Headers("authorization") authorization?: string) {
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

    const platforms = await this.entitlement.listEntitledPlatforms({
      realm: (payload.realm as "tenant" | "provider") ?? "tenant",
      roles: (payload.roles as string[]) ?? [],
      permissions: (payload.permissions as string[]) ?? [],
      tenantId: String(payload.tenantId ?? ""),
    });

    return { platforms };
  }
}
