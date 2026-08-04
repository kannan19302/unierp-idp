import {
  Controller,
  Post,
  Get,
  Patch,
  Delete,
  Param,
  Query,
  Body,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  NotFoundException,
  BadRequestException,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { FileInterceptor } from "@nestjs/platform-express";
import { ApiConsumes } from "@nestjs/swagger";
import { RbacGuard } from "../../common/guards/rbac.guard";
import { Permissions } from "../../common/decorators/permissions.decorator";
import { z } from "zod";
import { ZodBody } from "../../common/decorators/zod-body.decorator";
import { Request, Response } from "express";
import { AuthService } from "./auth.service";
import { ProvisioningService } from "./provisioning.service";
import { JwtAuthGuard } from "../../common/guards/jwt-auth.guard";
import { ZodValidationPipe } from "../../common/pipes/zod-validation.pipe";
import {
  registerSchema,
  loginSchema,
  RegisterInput,
  LoginInput,
  forgotPasswordSchema,
  resetPasswordSchema,
  ForgotPasswordInput,
  ResetPasswordInput,
  mfaLoginSchema,
  MfaLoginInput,
  verifyEmailSchema,
  VerifyEmailInput,
  resendVerificationSchema,
  ResendVerificationInput,
  sendOtpSchema,
  verifyOtpSchema,
  SendOtpInput,
  VerifyOtpInput,
} from "@unerp/shared";
import { ApiTags, ApiOperation, ApiBearerAuth } from "@nestjs/swagger";

const AUTH_COOKIE = "auth_token";
const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict" as const,
  path: "/",
  maxAge: 24 * 60 * 60 * 1000, // outlives the short access token; guard enforces real expiry
};

const REFRESH_COOKIE = "refresh_token";
/** Scoped to the auth routes so the refresh token never rides other requests. */
const REFRESH_COOKIE_PATH = "/api/v1/auth";
const refreshCookieOptions = (expiresAt: Date) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict" as const,
  path: REFRESH_COOKIE_PATH,
  expires: expiresAt,
});

/** Session payload with the refresh token split out for cookie transport. */
type SessionResult = {
  refreshToken?: string;
  refreshExpiresAt?: Date;
  token?: string;
  [key: string]: unknown;
};

/**
 * Moves the refresh token from the service result into httpOnly cookies and
 * strips it from the JSON body — client JS must never see it.
 */
function sealSessionCookies(result: SessionResult, res: Response) {
  if (result.token) {
    res.cookie(AUTH_COOKIE, result.token, COOKIE_OPTIONS);
  }
  if (result.refreshToken && result.refreshExpiresAt) {
    res.cookie(
      REFRESH_COOKIE,
      result.refreshToken,
      refreshCookieOptions(result.refreshExpiresAt),
    );
  }
  const { refreshToken: _rt, refreshExpiresAt: _re, ...body } = result;
  return body;
}

interface AuthenticatedRequest extends Request {
  user: {
    sid?: string;
    userId: string;
    tenantId: string;
    email: string;
    firstName: string;
    lastName: string;
    roles: string[];
  };
}

/**
 * Pulls IP / user-agent off the request for the active-sessions record, plus
 * the multi-client device headers Flutter mobile/desktop clients send
 * (.ai/MULTI_CLIENT_MASTER_PLAN.md § 7) — browsers simply omit these.
 */
function sessionContext(req: Request) {
  return {
    ipAddress:
      (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
      req.ip ||
      null,
    userAgent: (req.headers["user-agent"] as string) || null,
    deviceId: (req.headers["x-device-id"] as string) || null,
    platform: (req.headers["x-platform"] as string) || null,
    appVersion: (req.headers["x-app-version"] as string) || null,
  };
}

@ApiTags("auth")
@ApiBearerAuth()
@Controller("auth")
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly provisioningService: ProvisioningService,
  ) {}

  @ApiOperation({ summary: "Get database provisioning progress for a tenant" })
  @Get("provisioning/:tenantId/status")
  async getProvisioningStatus(@Param("tenantId") tenantId: string) {
    return this.provisioningService.getProgress(tenantId);
  }

  @ApiOperation({
    summary: "Real-time email-availability check for the register wizard",
  })
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  @Get("check-email")
  async checkEmail(@Query("email") email: string) {
    const parsed = z.string().email().safeParse(email);
    if (!parsed.success) {
      return { available: null };
    }
    return this.authService.checkEmailAvailability(parsed.data);
  }

  @ApiOperation({ summary: "Register" })
  @Permissions("auth.create")
  @Post("register")
  @HttpCode(HttpStatus.CREATED)
  async register(
    @Body(new ZodValidationPipe(registerSchema)) dto: RegisterInput,
  ) {
    return this.authService.register(dto);
  }

  @ApiOperation({ summary: "Login" })
  @Permissions("auth.create")
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post("login")
  @HttpCode(HttpStatus.OK)
  async login(
    @ZodBody(z.any()) body: Record<string, unknown>,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const validationPipe = new ZodValidationPipe(loginSchema);
    const loginData = validationPipe.transform(body, {
      type: "body",
      metatype: Object,
    }) as LoginInput;

    const result = await this.authService.login(
      {
        ...loginData,
        tenantSlug: body.tenantSlug as string | undefined,
      },
      sessionContext(req),
    );

    // Only a completed login carries a session token; an MFA challenge does not.
    if ("token" in result) {
      return sealSessionCookies(result as SessionResult, res);
    }

    return result;
  }

  @ApiOperation({ summary: "Rotate the refresh token and mint a new session" })
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken =
      (req.cookies?.[REFRESH_COOKIE] as string | undefined) ?? "";
    try {
      const result = await this.authService.refreshSession(
        refreshToken,
        sessionContext(req),
      );
      return sealSessionCookies(result as SessionResult, res);
    } catch (err) {
      // A dead refresh token ends the session client-side too.
      res.clearCookie(AUTH_COOKIE, { path: "/" });
      res.clearCookie(REFRESH_COOKIE, { path: REFRESH_COOKIE_PATH });
      throw err;
    }
  }

  @ApiOperation({ summary: "Logout" })
  @Post("logout")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(
    @Req() req: AuthenticatedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    // Revoke the server-side session so the token is dead even if it is replayed.
    if (req.user?.sid) {
      await this.authService.revokeSessionById(req.user.sid);
    }
    res.clearCookie(AUTH_COOKIE, { path: "/" });
    res.clearCookie(REFRESH_COOKIE, { path: REFRESH_COOKIE_PATH });
    return { message: "Logged out" };
  }

  @ApiOperation({ summary: "Get profile" })
  @Permissions("auth.read")
  @Get("me")
  @UseGuards(JwtAuthGuard, RbacGuard)
  async getProfile(@Req() req: AuthenticatedRequest) {
    return this.authService.getProfile(req.user.userId);
  }

  @ApiOperation({ summary: "Update profile" })
  @Permissions("auth.update")
  @Patch("me")
  @UseGuards(JwtAuthGuard, RbacGuard)
  async updateProfile(
    @Req() req: AuthenticatedRequest,
    @ZodBody(z.any()) body: Record<string, unknown>,
  ) {
    const validationPipe = new ZodValidationPipe(
      require("@unerp/shared").updateProfileSchema,
    );
    const dto = validationPipe.transform(body, {
      type: "body",
      metatype: Object,
    });
    return this.authService.updateProfile(req.user.userId, dto);
  }

  @ApiOperation({ summary: "List tenants this account can sign in to" })
  @Permissions("auth.read")
  @Get("tenants")
  @UseGuards(JwtAuthGuard, RbacGuard)
  async listTenants(@Req() req: AuthenticatedRequest) {
    return this.authService.listUserTenants(req.user.userId);
  }

  @ApiOperation({ summary: "Switch the active tenant (re-issues the session)" })
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post("switch-tenant")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async switchTenant(
    @Req() req: AuthenticatedRequest,
    @ZodBody(z.object({ tenantSlug: z.string().min(1).max(100) }))
    body: { tenantSlug: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.switchTenant(
      req.user.userId,
      req.user.sid,
      body.tenantSlug,
      sessionContext(req),
    );
    return sealSessionCookies(result as SessionResult, res);
  }

  @ApiOperation({ summary: "Request password reset" })
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Post("forgot-password")
  @HttpCode(HttpStatus.OK)
  async forgotPassword(
    @Body(new ZodValidationPipe(forgotPasswordSchema)) dto: ForgotPasswordInput,
  ) {
    return this.authService.forgotPassword(dto);
  }

  @ApiOperation({ summary: "Verify email address" })
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post("verify-email")
  @HttpCode(HttpStatus.OK)
  async verifyEmail(
    @Body(new ZodValidationPipe(verifyEmailSchema)) dto: VerifyEmailInput,
  ) {
    return this.authService.verifyEmail(dto);
  }

  @ApiOperation({ summary: "Resend email verification link" })
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Post("resend-verification")
  @HttpCode(HttpStatus.OK)
  async resendVerification(
    @Body(new ZodValidationPipe(resendVerificationSchema))
    dto: ResendVerificationInput,
  ) {
    return this.authService.resendVerification(dto);
  }

  @ApiOperation({ summary: "Reset password" })
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post("reset-password")
  @HttpCode(HttpStatus.OK)
  async resetPassword(
    @Body(new ZodValidationPipe(resetPasswordSchema)) dto: ResetPasswordInput,
  ) {
    return this.authService.resetPassword(dto);
  }

  @ApiOperation({ summary: "Login demo user (non-production only)" })
  @Throttle({
    short: { limit: 10, ttl: 1000 },
    medium: { limit: 30, ttl: 60000 },
  })
  @Post("login-demo")
  @HttpCode(HttpStatus.OK)
  async loginDemo(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (process.env.NODE_ENV === "production") {
      throw new NotFoundException();
    }
    // Defense in depth: even outside production this is a shared dev
    // database seed shortcut, not a real account — never reachable from
    // anything but the machine running the dev server.
    const rawHostHeader =
      (req.headers["x-forwarded-host"] as string | string[] | undefined) ||
      (req.headers["host"] as string | string[] | undefined);
    let hostWithPort = "";
    if (typeof rawHostHeader === "string") {
      hostWithPort = rawHostHeader;
    } else if (
      Array.isArray(rawHostHeader) &&
      rawHostHeader.length > 0 &&
      typeof rawHostHeader[0] === "string"
    ) {
      hostWithPort = rawHostHeader[0];
    } else if (typeof req.hostname === "string") {
      hostWithPort = req.hostname;
    }
    const host = (hostWithPort.split(":")[0] as string).toLowerCase();
    const isLocal =
      [
        "localhost",
        "127.0.0.1",
        "::1",
        "api",
        "web",
        "host.docker.internal",
        "unerp-dev",
        "0.0.0.0",
      ].includes(host) ||
      host.startsWith("172.") ||
      host.startsWith("192.168.") ||
      host.startsWith("10.") ||
      host.endsWith(".local");
    if (!isLocal) {
      throw new NotFoundException();
    }
    // Only Super Admin is offered today — HR/Finance/Viewer demo personas
    // were removed.
    const result = await this.authService.loginDemo();
    return sealSessionCookies(result as SessionResult, res);
  }

  @ApiOperation({ summary: "List active sessions for this account" })
  @Permissions("auth.read")
  @Get("sessions")
  @UseGuards(JwtAuthGuard, RbacGuard)
  async listSessions(@Req() req: AuthenticatedRequest) {
    return this.authService.listSessions(
      req.user.userId,
      req.user.tenantId,
      req.user.sid,
    );
  }

  @ApiOperation({ summary: "List login history for this account" })
  @Permissions("auth.read")
  @Get("login-history")
  @UseGuards(JwtAuthGuard, RbacGuard)
  async listLoginHistory(@Req() req: AuthenticatedRequest) {
    return this.authService.listLoginHistory(
      req.user.userId,
      req.user.tenantId,
    );
  }

  @ApiOperation({ summary: "Revoke every session except the current one" })
  @Permissions("auth.update")
  @Post("sessions/revoke-others")
  @UseGuards(JwtAuthGuard, RbacGuard)
  @HttpCode(HttpStatus.OK)
  async revokeOtherSessions(@Req() req: AuthenticatedRequest) {
    return this.authService.revokeOtherSessions(
      req.user.userId,
      req.user.tenantId,
      req.user.sid,
    );
  }

  @ApiOperation({
    summary: 'Revoke one specific device/session ("log out this device")',
  })
  @Permissions("auth.update")
  @Delete("sessions/:id")
  @UseGuards(JwtAuthGuard, RbacGuard)
  @HttpCode(HttpStatus.OK)
  async revokeSession(
    @Req() req: AuthenticatedRequest,
    @Param("id") id: string,
  ) {
    return this.authService.revokeOwnSessionById(
      req.user.userId,
      req.user.tenantId,
      id,
    );
  }

  @ApiOperation({ summary: "Upload a profile avatar (JPG/PNG/GIF, max 800KB)" })
  @Permissions("auth.update")
  @Post("me/avatar")
  @UseGuards(JwtAuthGuard, RbacGuard)
  @UseInterceptors(FileInterceptor("file"))
  @ApiConsumes("multipart/form-data")
  @HttpCode(HttpStatus.OK)
  async uploadAvatar(
    @Req() req: AuthenticatedRequest,
    @UploadedFile() file: Express.Multer.File,
  ) {
    if (!file) throw new BadRequestException("No file provided.");
    if (!["image/jpeg", "image/png", "image/gif"].includes(file.mimetype)) {
      throw new BadRequestException(
        "Only JPG, PNG, or GIF images are allowed.",
      );
    }
    if (file.size > 800 * 1024) {
      throw new BadRequestException("Image exceeds the 800KB size limit.");
    }
    const dataUri = `data:${file.mimetype};base64,${file.buffer.toString("base64")}`;
    return this.authService.updateAvatar(req.user.userId, dataUri);
  }

  @ApiOperation({ summary: "Setup TOTP MFA" })
  @Post("mfa/setup")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async setupMfa(@Req() req: AuthenticatedRequest) {
    return this.authService.generateMfaSecret(req.user.userId);
  }

  @ApiOperation({ summary: "Verify and enable/disable TOTP MFA" })
  @Post("mfa/verify")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async verifyMfa(
    @Req() req: AuthenticatedRequest,
    @Body() body: { code: string; enable: boolean },
  ) {
    return this.authService.verifyMfaAndEnable(
      req.user.userId,
      body.code,
      body.enable,
    );
  }

  @ApiOperation({ summary: "Verify MFA and Login" })
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post("mfa/verify-login")
  @HttpCode(HttpStatus.OK)
  async verifyMfaLogin(
    @Body(new ZodValidationPipe(mfaLoginSchema)) body: MfaLoginInput,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.verifyMfaLogin(
      body.challengeToken,
      body.code,
      sessionContext(req),
    );
    return sealSessionCookies(result as SessionResult, res);
  }

  @ApiOperation({
    summary: "Register this device for MFA push-approval prompts",
  })
  @Permissions("auth.update")
  @Post("push/subscribe")
  @UseGuards(JwtAuthGuard, RbacGuard)
  @HttpCode(HttpStatus.OK)
  async subscribeToPush(
    @Req() req: AuthenticatedRequest,
    @ZodBody(
      z.object({
        subscription: z.object({
          endpoint: z.string().url(),
          keys: z.object({ p256dh: z.string(), auth: z.string() }),
        }),
        label: z.string().max(100).optional(),
      }),
    )
    body: {
      subscription: {
        endpoint: string;
        keys: { p256dh: string; auth: string };
      };
      label?: string;
    },
  ) {
    return this.authService.subscribeToPush(
      req.user.userId,
      req.user.tenantId,
      body.subscription,
      body.label,
    );
  }

  @ApiOperation({
    summary: "Stop sending push-approval prompts to this device",
  })
  @Permissions("auth.update")
  @Post("push/unsubscribe")
  @UseGuards(JwtAuthGuard, RbacGuard)
  @HttpCode(HttpStatus.OK)
  async unsubscribeFromPush(
    @Req() req: AuthenticatedRequest,
    @ZodBody(z.object({ endpoint: z.string().url() }))
    body: { endpoint: string },
  ) {
    return this.authService.unsubscribeFromPush(
      req.user.userId,
      req.user.tenantId,
      body.endpoint,
    );
  }

  @ApiOperation({ summary: "List devices registered for MFA push-approval" })
  @Permissions("auth.read")
  @Get("push/devices")
  @UseGuards(JwtAuthGuard, RbacGuard)
  async listPushDevices(@Req() req: AuthenticatedRequest) {
    return this.authService.listPushSubscriptions(
      req.user.userId,
      req.user.tenantId,
    );
  }

  @ApiOperation({ summary: "Remove a registered push-approval device" })
  @Permissions("auth.update")
  @Post("push/devices/:id/remove")
  @UseGuards(JwtAuthGuard, RbacGuard)
  @HttpCode(HttpStatus.OK)
  async removePushDevice(
    @Req() req: AuthenticatedRequest,
    @Param("id") id: string,
  ) {
    return this.authService.removePushDeviceById(
      req.user.userId,
      req.user.tenantId,
      id,
    );
  }

  @ApiOperation({ summary: "Poll a pending login's push-approval status" })
  @Throttle({ default: { limit: 60, ttl: 60000 } })
  @Post("mfa/push/status")
  @HttpCode(HttpStatus.OK)
  async mfaPushStatus(
    @ZodBody(z.object({ challengeToken: z.string() }))
    body: { challengeToken: string },
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.getMfaPushStatus(
      body.challengeToken,
      sessionContext(req),
    );
    if (result.status === "approved" && "token" in result) {
      return sealSessionCookies(result as unknown as SessionResult, res);
    }
    return result;
  }

  @ApiOperation({
    summary: "Approve or deny a push-approval login request from this device",
  })
  @Permissions("auth.update")
  @Post("mfa/push/respond")
  @UseGuards(JwtAuthGuard, RbacGuard)
  @HttpCode(HttpStatus.OK)
  async respondToMfaPush(
    @Req() req: AuthenticatedRequest,
    @ZodBody(z.object({ challengeToken: z.string(), approve: z.boolean() }))
    body: { challengeToken: string; approve: boolean },
  ) {
    return this.authService.respondToMfaPushChallenge(
      req.user.userId,
      req.user.tenantId,
      body.challengeToken,
      body.approve,
    );
  }

  @ApiOperation({ summary: "Send email OTP verification code" })
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @Post("send-otp")
  @HttpCode(HttpStatus.OK)
  async sendOtp(@Body(new ZodValidationPipe(sendOtpSchema)) dto: SendOtpInput) {
    return this.authService.sendOtp(dto.email);
  }

  @ApiOperation({ summary: "Verify email OTP code" })
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post("verify-otp")
  @HttpCode(HttpStatus.OK)
  async verifyOtp(
    @Body(new ZodValidationPipe(verifyOtpSchema)) dto: VerifyOtpInput,
  ) {
    return this.authService.verifyOtp(dto.email, dto.code);
  }

  @ApiOperation({ summary: "Get onboarding status (for mandatory redirect)" })
  @Permissions("auth.read")
  @Get("onboarding/status")
  @UseGuards(JwtAuthGuard, RbacGuard)
  @HttpCode(HttpStatus.OK)
  async getOnboardingStatus(@Req() req: AuthenticatedRequest) {
    return this.authService.getOnboardingStatus(
      req.user.tenantId,
      req.user.userId,
    );
  }
}
