import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Header,
  Post,
  Req,
  Res,
  UseGuards,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ApiExcludeController } from "@nestjs/swagger";
import type { Request, Response } from "express";
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { JwtAuthGuard } from "../../../common/guards/jwt-auth.guard";
import { Public } from "../../../common/decorators/public.decorator";
import { PasskeyService } from "../../auth/passkey.service";
import {
  safeReturnTo,
  setSessionCookies,
  verifyCsrf,
} from "./login.controller";

type PasskeyRequest = Request & {
  user?: { userId?: string; tenantId?: string; sid?: string };
};

@ApiExcludeController()
@Controller("oidc/passkeys")
export class PasskeyController {
  constructor(private readonly passkeys: PasskeyService) {}

  @Post("registration/options")
  @Header("Cache-Control", "no-store")
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  async registrationOptions(
    @Body() body: Record<string, unknown>,
    @Req() req: PasskeyRequest,
  ) {
    this.assertCsrf(req, body._csrf);
    return this.passkeys.registrationOptions(
      req.user?.userId || "",
      req.user?.tenantId || "",
      req.user?.sid || "",
    );
  }

  @Post("registration/verify")
  @Header("Cache-Control", "no-store")
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  async verifyRegistration(
    @Body() body: Record<string, unknown>,
    @Req() req: PasskeyRequest,
  ) {
    this.assertCsrf(req, body._csrf);
    return this.passkeys.verifyRegistration({
      userId: req.user?.userId || "",
      tenantId: req.user?.tenantId || "",
      sid: req.user?.sid || "",
      handle: typeof body.handle === "string" ? body.handle : "",
      name: typeof body.name === "string" ? body.name : undefined,
      response: parseRegistrationResponse(body.response),
    });
  }

  @Post("authentication/options")
  @Public("Passkey authentication option creation validates the browser CSRF token and issues a one-time challenge")
  @Header("Cache-Control", "no-store")
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  async authenticationOptions(
    @Body() body: Record<string, unknown>,
    @Req() req: Request,
  ) {
    this.assertCsrf(req, body._csrf);
    return this.passkeys.authenticationOptions(
      safeReturnTo(typeof body.returnTo === "string" ? body.returnTo : undefined),
    );
  }

  @Post("authentication/verify")
  @Public("Passkey authentication validates an assertion and one-time challenge before issuing a session")
  @Header("Cache-Control", "no-store")
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  async verifyAuthentication(
    @Body() body: Record<string, unknown>,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    this.assertCsrf(req, body._csrf);
    const result = await this.passkeys.verifyAuthentication({
      handle: typeof body.handle === "string" ? body.handle : "",
      response: parseAuthenticationResponse(body.response),
      context: {
        ipAddress: req.ip || req.socket.remoteAddress,
        userAgent: req.headers["user-agent"],
      },
    });
    setSessionCookies(res, result as unknown as Record<string, unknown>);
    return { authenticated: true, returnTo: safeReturnTo(result.returnTo) };
  }

  @Post("delete")
  @Header("Cache-Control", "no-store")
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  async deletePasskey(
    @Body() body: Record<string, unknown>,
    @Req() req: PasskeyRequest,
  ) {
    this.assertCsrf(req, body._csrf);
    await this.passkeys.deletePasskey({
      userId: req.user?.userId || "",
      tenantId: req.user?.tenantId || "",
      sid: req.user?.sid || "",
      passkeyId: typeof body.passkeyId === "string" ? body.passkeyId : "",
    });
    return { deleted: true };
  }

  private assertCsrf(req: Request, value: unknown): void {
    if (!verifyCsrf(req, typeof value === "string" ? value : undefined)) {
      throw new ForbiddenException("Invalid or expired security token.");
    }
  }
}

function parseRegistrationResponse(value: unknown): RegistrationResponseJSON {
  const response = publicKeyCredential(value);
  const payload = response.response;
  if (
    !isRecord(payload) ||
    typeof payload.clientDataJSON !== "string" ||
    typeof payload.attestationObject !== "string"
  ) {
    throw new BadRequestException("Invalid passkey registration response.");
  }
  return response as unknown as RegistrationResponseJSON;
}

function parseAuthenticationResponse(value: unknown): AuthenticationResponseJSON {
  const response = publicKeyCredential(value);
  const payload = response.response;
  if (
    !isRecord(payload) ||
    typeof payload.clientDataJSON !== "string" ||
    typeof payload.authenticatorData !== "string" ||
    typeof payload.signature !== "string" ||
    (payload.userHandle !== null && typeof payload.userHandle !== "string")
  ) {
    throw new BadRequestException("Invalid passkey authentication response.");
  }
  return response as unknown as AuthenticationResponseJSON;
}

function publicKeyCredential(value: unknown): Record<string, unknown> {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    typeof value.rawId !== "string" ||
    value.type !== "public-key" ||
    !isRecord(value.clientExtensionResults)
  ) {
    throw new BadRequestException("Invalid passkey credential response.");
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
