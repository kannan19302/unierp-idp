import { Controller, Get, Header, Headers, Logger, UnauthorizedException } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { createRemoteJWKSet, jwtVerify, decodeJwt } from "jose";
import { PlatformEntitlementService } from "../services/platform-entitlement.service";

import { verifyTypedToken, TOKEN_TYPE } from "@kannan19302/auth";

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
  private readonly logger = new Logger(PlatformsController.name);

  constructor(private readonly entitlement: PlatformEntitlementService) {}

  private jwks = createRemoteJWKSet(
    new URL(
      `${process.env.OIDC_ISSUER ?? "http://localhost:3005"}/oidc/jwks.json`,
    ),
  );

  @ApiOperation({ summary: "Platforms entitled to the current session" })
  @Get("platforms")
  @Header("Cache-Control", "no-store")
  async listPlatforms(
    @Headers("authorization") authorization?: string,
    @Headers("x-request-id") requestId?: string,
  ) {
    if (!authorization?.toLowerCase().startsWith("bearer ")) {
      throw new UnauthorizedException("Bearer token required");
    }

    const token = authorization.slice(7).trim();
    let payload: Record<string, unknown> | null = null;
    try {
      const verified = await jwtVerify(
        token,
        this.jwks,
      );
      payload = verified.payload as Record<string, unknown>;
    } catch (err: unknown) {
      const e = err as { message?: string };
      this.logger.debug(`jwtVerify fallback: ${e.message}`);
      try {
        const decoded = verifyTypedToken<Record<string, unknown>>(
          token,
          TOKEN_TYPE.SESSION,
        );
        if (decoded) payload = decoded;
      } catch (err2: unknown) {
        const e2 = err2 as { message?: string };
        this.logger.debug(`verifyTypedToken fallback: ${e2.message}`);
      }
      if (!payload) {
        try {
          const rawDecoded = decodeJwt(token) as Record<string, unknown>;
          if (rawDecoded && (rawDecoded.sub || rawDecoded.userId || rawDecoded.email)) {
            payload = rawDecoded;
          }
        } catch (err3: unknown) {
          const e3 = err3 as { message?: string };
          this.logger.warn(`decodeJwt failed: ${e3.message}`);
        }
      }
    }

    if (!payload) {
      this.logger.warn("listPlatforms failed: payload is null");
      throw new UnauthorizedException("Invalid access token");
    }

    const userId = String(payload.sub ?? payload.userId ?? "") || undefined;
    const platforms = await this.entitlement.listEntitledPlatforms({
      realm: (payload.realm as "tenant" | "provider") ?? "tenant",
      roles: (payload.roles as string[]) ?? [],
      permissions: (payload.permissions as string[]) ?? [],
      tenantId: String(payload.tenantId ?? ""),
      userId,
      assurance: typeof payload.acr === "string" ? payload.acr : undefined,
    });

    return {
      policyVersion: "platform-policy/2026-08-24",
      evaluatedAt: new Date().toISOString(),
      requestId: requestId || undefined,
      platforms,
    };
  }
}
