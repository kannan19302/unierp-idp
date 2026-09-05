import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
  Header,
  Optional,
  UseGuards,
} from "@nestjs/common";
import type { Request, Response } from "express";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { ApiExcludeController } from "@nestjs/swagger";
import { AuthService } from "../../auth/auth.service";
import {
  OAuthService,
  type OAuthProviderName,
} from "../../auth/oauth.service";
import { idpPrisma, runWithTenantSession } from "@kannan19302/database";
import { JwtAuthGuard } from "../../../common/guards/jwt-auth.guard";
import { Public } from "../../../common/decorators/public.decorator";
import { getRegistrationLegalConfig } from "../../../common/legal/legal-document.config";
import { getPlatformNavigationConfig } from "../../../common/navigation/platform-navigation.config";
import {
  AccountGovernanceService,
  type AccountOrganization,
} from "../../auth/account-governance.service";

const AUTH_COOKIE = "auth_token";
const REFRESH_COOKIE = "refresh_token";
const CSRF_COOKIE = "oidc_csrf";

/**
 * Extracts an existing CSRF token or issues a fresh one via an httpOnly cookie.
 */
function getOrSetCsrf(req: Request, res: Response): string {
  const cookieHeader = req.headers?.cookie || "";
  const cookieMatch = cookieHeader.match(/(?:^|;\s*)oidc_csrf=([^;]+)/);
  let token =
    (req.cookies as Record<string, string> | undefined)?.[CSRF_COOKIE] ||
    (cookieMatch && cookieMatch[1] ? decodeURIComponent(cookieMatch[1]) : undefined);
  if (!token || token.length < 16) {
    token = randomBytes(24).toString("hex");
    res.cookie(CSRF_COOKIE, token, {
      httpOnly: true,
      sameSite: "lax",
      path: "/oidc",
      maxAge: 60 * 60 * 1000,
    });
  }
  return token;
}

/**
 * Constant-time verification of submitted CSRF token against the request cookie.
 */
export function verifyCsrf(req: Request, submittedToken?: string): boolean {
  const cookieHeader = req.headers?.cookie || "";
  const cookieMatch = cookieHeader.match(/(?:^|;\s*)oidc_csrf=([^;]+)/);
  const cookieToken =
    (req.cookies as Record<string, string> | undefined)?.[CSRF_COOKIE] ||
    (cookieMatch && cookieMatch[1] ? decodeURIComponent(cookieMatch[1]) : undefined);
  if (!cookieToken || !submittedToken) return false;
  if (cookieToken.length !== submittedToken.length) return false;
  try {
    return timingSafeEqual(Buffer.from(cookieToken), Buffer.from(submittedToken));
  } catch {
    return false;
  }
}

/**
 * The unified, enterprise-grade hosted OIDC auth portal.
 *
 * Responsive, theme-aware UX with social SSO, accessible risk controls,
 * CSRF security, server-derived tenant/provider scope, and multi-modal MFA.
 */
@ApiExcludeController()
@Controller("oidc")
export class LoginController {
  constructor(
    private readonly auth: AuthService,
    private readonly oauth: OAuthService,
    @Optional() private readonly governance?: AccountGovernanceService,
  ) {}

  private async configuredProviders(
    journey: "login" | "register",
  ): Promise<OAuthProviderName[]> {
    try {
      return (await this.oauth.listProviders(journey)).providers;
    } catch {
      return [];
    }
  }

  // ── 0. CENTRAL ACCOUNT CENTER ─────────────────────────────────────────

  @Get("account")
  @Header("Cache-Control", "no-store")
  @UseGuards(JwtAuthGuard)
  async accountCenter(
    @Req()
    req: Request & {
      user?: {
        userId?: string;
        tenantId?: string;
        sid?: string;
        email?: string;
        name?: string;
      };
    },
    @Res({ passthrough: true }) res: Response,
    @Query("return_to") returnTo?: string,
    @Query("error") error?: string,
    @Query("success") success?: string,
  ): Promise<string> {
    const userId = req.user?.userId || "";
    const tenantId = req.user?.tenantId || "";
    const csrfToken = getOrSetCsrf(req, res);
    const referer = typeof req.headers.referer === "string" ? req.headers.referer : undefined;
    const backNavigation = resolvePlatformBackNavigation(returnTo, referer);
    const [configured, connected, account, organizations, privacy] = await Promise.all([
      this.configuredProviders("login"),
      this.oauth.getConnectedProviders(userId, tenantId),
      runWithTenantSession({ tenantId, userId }, async () => {
        const [user, sessions, passkeys, contacts] = await Promise.all([
          idpPrisma.user.findUnique({
            where: { id: userId },
            select: {
              firstName: true,
              lastName: true,
              email: true,
              avatar: true,
              preferences: true,
              mfaEnabled: true,
              emailVerifiedAt: true,
            },
          }),
          idpPrisma.userSession.findMany({
            where: { userId, isActive: true },
            orderBy: { lastActivityAt: "desc" },
            take: 20,
            select: {
              id: true,
              device: true,
              browser: true,
              location: true,
              platform: true,
              lastActivityAt: true,
              expiresAt: true,
            },
          }),
          idpPrisma.passkey.findMany({
            where: { userId },
            orderBy: { createdAt: "desc" },
            select: {
              id: true,
              name: true,
              deviceType: true,
              backedUp: true,
              createdAt: true,
              lastUsedAt: true,
            },
          }),
          idpPrisma.accountContact.findMany({
            where: { userId },
            orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
            select: {
              id: true,
              value: true,
              label: true,
              isPrimary: true,
              verifiedAt: true,
              createdAt: true,
            },
          }),
        ]);
        return { user, sessions, passkeys, contacts };
      }),
      this.governance?.listOrganizations(userId, tenantId).catch(() => []) ?? [],
      this.governance?.privacyState(userId, tenantId).catch(() => ({ exports: [], erasures: [] })) ?? {
        exports: [],
        erasures: [],
      },
    ]);
    return renderAccountCenter({
      configured,
      connected,
      email: account.user?.email ?? req.user?.email,
      firstName: account.user?.firstName,
      lastName: account.user?.lastName,
      avatar: account.user?.avatar,
      preferences: account.user?.preferences,
      mfaEnabled: account.user?.mfaEnabled ?? false,
      emailVerified: !!account.user?.emailVerifiedAt,
      sessions: account.sessions.map((session) => ({
        ...session,
        current: session.id === req.user?.sid,
      })),
      passkeys: account.passkeys,
      contacts: account.contacts,
      organizations,
      privacy,
      backNavigation,
      csrfToken,
      error,
      success,
    });
  }

  @Post("account/profile")
  @Header("Cache-Control", "no-store")
  @UseGuards(JwtAuthGuard)
  async updateAccountProfile(
    @Body() body: Record<string, string>,
    @Req() req: Request & { user?: { userId?: string; tenantId?: string } },
    @Res() res: Response,
  ): Promise<void> {
    if (!verifyCsrf(req, body._csrf)) {
      res.redirect(302, "/oidc/account?error=Invalid%20or%20expired%20security%20token.");
      return;
    }
    const userId = req.user?.userId;
    const tenantId = req.user?.tenantId;
    const firstName = body.first_name?.trim();
    const lastName = body.last_name?.trim();
    if (!userId || !tenantId || !firstName || !lastName || firstName.length > 80 || lastName.length > 80) {
      res.redirect(302, "/oidc/account?error=Enter%20a%20valid%20first%20and%20last%20name.");
      return;
    }
    await runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.user.update({
        where: { id: userId },
        data: { firstName, lastName },
      }),
    );
    res.redirect(302, "/oidc/account?success=Profile%20updated.#profile");
  }

  @Post("account/preferences")
  @Header("Cache-Control", "no-store")
  @UseGuards(JwtAuthGuard)
  async updateAccountPreferences(
    @Body() body: Record<string, string>,
    @Req() req: Request & { user?: { userId?: string; tenantId?: string } },
    @Res() res: Response,
  ): Promise<void> {
    if (!verifyCsrf(req, body._csrf)) {
      res.redirect(302, "/oidc/account?error=Invalid%20or%20expired%20security%20token.");
      return;
    }
    const userId = req.user?.userId;
    const tenantId = req.user?.tenantId;
    const allowedThemes = new Set(["system", "light", "dark", "enterprise", "modern", "minimal", "classic", "high-contrast"]);
    const allowedDensities = new Set(["comfortable", "compact"]);
    const theme = body.theme && allowedThemes.has(body.theme) ? body.theme : "system";
    const density = body.density && allowedDensities.has(body.density) ? body.density : "comfortable";
    if (!userId || !tenantId) {
      res.redirect(302, "/oidc/account?error=Invalid%20account%20request.");
      return;
    }
    await runWithTenantSession({ tenantId, userId }, async () => {
      const user = await idpPrisma.user.findUnique({
        where: { id: userId },
        select: { preferences: true },
      });
      const current = user?.preferences && typeof user.preferences === "object" && !Array.isArray(user.preferences)
        ? user.preferences as Record<string, unknown>
        : {};
      await idpPrisma.user.update({
        where: { id: userId },
        data: {
          preferences: {
            ...current,
            theme,
            density,
            reduceMotion: body.reduce_motion === "on",
          },
        },
      });
    });
    res.cookie("unierp_theme", theme, { sameSite: "lax", path: "/", maxAge: 365 * 24 * 60 * 60 * 1000 });
    res.redirect(302, "/oidc/account?success=Preferences%20saved.#appearance");
  }

  @Post("account/sessions/revoke")
  @Header("Cache-Control", "no-store")
  @UseGuards(JwtAuthGuard)
  async revokeAccountSession(
    @Body() body: Record<string, string>,
    @Req() req: Request & { user?: { userId?: string; tenantId?: string; sid?: string } },
    @Res() res: Response,
  ): Promise<void> {
    if (!verifyCsrf(req, body._csrf)) {
      res.redirect(302, "/oidc/account?error=Invalid%20or%20expired%20security%20token.");
      return;
    }
    const userId = req.user?.userId;
    const tenantId = req.user?.tenantId;
    const sessionId = body.session_id;
    if (!userId || !tenantId || !sessionId || sessionId === req.user?.sid) {
      res.redirect(302, "/oidc/account?error=The%20current%20session%20cannot%20be%20revoked%20here.");
      return;
    }
    await runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.userSession.updateMany({
        where: { id: sessionId, userId },
        data: { isActive: false },
      }),
    );
    res.redirect(302, "/oidc/account?success=Session%20revoked.#sessions");
  }

  @Post("account/unlink")
  @Header("Cache-Control", "no-store")
  @UseGuards(JwtAuthGuard)
  async unlinkExternalAccount(
    @Body() body: Record<string, string>,
    @Req()
    req: Request & {
      user?: { userId?: string; tenantId?: string; sid?: string };
    },
    @Res() res: Response,
  ): Promise<void> {
    if (!verifyCsrf(req, body._csrf)) {
      res.redirect(
        302,
        "/oidc/account?error=Invalid%20or%20expired%20security%20token.",
      );
      return;
    }
    const provider = parseOAuthProvider(body.provider);
    const userId = req.user?.userId;
    const tenantId = req.user?.tenantId;
    const sid = req.user?.sid;
    if (!provider || !userId || !tenantId || !sid) {
      res.redirect(302, "/oidc/account?error=Invalid%20account%20request.");
      return;
    }
    try {
      await this.oauth.unlinkProvider(provider, userId, tenantId, sid);
      res.redirect(
        302,
        `/oidc/account?success=${encodeURIComponent(`${providerLabel(provider)} disconnected.`)}`,
      );
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Provider could not be disconnected.";
      res.redirect(302, `/oidc/account?error=${encodeURIComponent(message)}`);
    }
  }

  /**
   * Whether this login attempt is for an INTERNAL platform (Provider Admin OS, P2),
   * determined from the client_id embedded in `return_to`.
   */
  private async isInternalPlatformLogin(returnTo: string): Promise<boolean> {
    try {
      const url = new URL(returnTo, "http://placeholder");
      const clientId = url.searchParams.get("client_id");
      if (!clientId) return false;

      const client = await idpPrisma.oAuthClient.findUnique({
        where: { clientId },
        select: { platformCode: true },
      });
      if (!client?.platformCode) return false;

      const platform = await idpPrisma.platform.findUnique({
        where: { code: client.platformCode },
        select: { audience: true },
      });
      return platform?.audience === "INTERNAL";
    } catch {
      return false;
    }
  }

  // ── 1. SIGN IN ──────────────────────────────────────────────────────────

  @Get("login")
  @Public("Hosted sign-in form creates only a CSRF token before credential verification")
  @Header("Cache-Control", "no-store")
  async loginForm(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query("return_to") returnTo?: string,
    @Query("error") error?: string,
    @Query("success") success?: string,
  ): Promise<string> {
    const csrfToken = getOrSetCsrf(req, res);
    const safeReturn = safeReturnTo(returnTo);
    return renderLogin({
      returnTo: safeReturn,
      error,
      success,
      csrfToken,
      providers: (await this.isInternalPlatformLogin(safeReturn))
        ? []
        : await this.configuredProviders("login"),
    });
  }

  @Post("login")
  @Public("Hosted sign-in validates credentials, CSRF and throttling before creating a session")
  @Header("Cache-Control", "no-store")
  async submitLogin(
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const returnTo = safeReturnTo(body.return_to);
    const csrfToken = getOrSetCsrf(req, res);
    // Scope is a server-owned property of the relying-party destination. The
    // browser must not be able to request provider authority or steer tenant
    // discovery with hidden/form fields.
    const isProviderLogin = await this.isInternalPlatformLogin(returnTo);
    const providers = isProviderLogin
      ? []
      : await this.configuredProviders("login");

    // CSRF verification
    if (!verifyCsrf(req, body._csrf)) {
      res.status(403).send(
        renderLogin({
          returnTo,
          error: "Invalid or expired security token. Please try again.",
          csrfToken,
          providers,
        }),
      );
      return;
    }

    // Bot Wall: Honeypot Check
    if (body.hp_website) {
      res.status(401).send(
        renderLogin({
          returnTo,
          error: "Automated verification failed. Please try again.",
          csrfToken,
          providers,
        }),
      );
      return;
    }

    try {
      const result = (await (isProviderLogin
        ? this.auth.providerLogin(
            { email: body.email, password: body.password } as never,
            { ipAddress: req.ip || req.socket.remoteAddress, userAgent: req.headers["user-agent"] } as never,
          )
        : this.auth.login(
            {
              email: body.email,
              password: body.password,
              rememberMe: body.remember === "on",
            } as never,
            {
              ipAddress: req.ip || req.socket.remoteAddress,
              userAgent: req.headers["user-agent"],
            } as never,
          ))) as Record<string, unknown>;

      if (result.mfaRequired) {
        res.status(200).send(
          renderMfa({
            returnTo,
            challengeToken: String(result.challengeToken ?? ""),
            email: body.email,
            csrfToken,
          }),
        );
        return;
      }

      this.setAuthCookies(res, result);
      res.redirect(302, returnTo);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Invalid credentials";
      res.status(401).send(
        renderLogin({
          returnTo,
          error: message,
          email: body.email,
          csrfToken,
          providers,
        }),
      );
    }
  }

  // ── 2. MULTI-FACTOR AUTHENTICATION (MFA / 2FA) ──────────────────────────

  @Post("login/mfa")
  @Public("MFA completion validates a short-lived challenge and CSRF before creating a session")
  @Header("Cache-Control", "no-store")
  async submitMfa(
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const returnTo = safeReturnTo(body.return_to);
    const challengeToken = body.challenge_token;
    const csrfToken = getOrSetCsrf(req, res);

    if (!verifyCsrf(req, body._csrf)) {
      res.status(403).send(
        renderMfa({
          returnTo,
          challengeToken: challengeToken || "",
          error: "Invalid or expired security token. Please try again.",
          csrfToken,
        }),
      );
      return;
    }

    if (!challengeToken) {
      res.status(400).send(
        renderLogin({
          returnTo,
          error: "MFA challenge expired. Please sign in again.",
          csrfToken,
        }),
      );
      return;
    }

    try {
      const code = (body.recovery_code || body.totp_code || body.code || "").trim();
      const result = (await this.auth.verifyMfaLogin(
        challengeToken,
        code,
        { ipAddress: req.ip || req.socket.remoteAddress, userAgent: req.headers["user-agent"] } as never,
      )) as Record<string, unknown>;

      setSessionCookies(res, result);
      res.redirect(302, returnTo);
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : "Invalid verification code. Please try again.";
      res.status(401).send(
        renderMfa({
          returnTo,
          challengeToken,
          error: message,
          email: body.email,
          csrfToken,
        }),
      );
    }
  }

  // ── 3. ORGANIZATION REGISTRATION ────────────────────────────────────────

  @Get("register")
  @Public("Hosted registration form creates only a CSRF token and uses rate-limited public registration")
  @Header("Cache-Control", "no-store")
  async registerForm(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query("return_to") returnTo?: string,
    @Query("error") error?: string,
    @Query("external_auth") externalAuth?: string,
  ): Promise<string> {
    const csrfToken = getOrSetCsrf(req, res);
    const externalProfile = externalAuth
      ? await this.oauth.getRegistrationProfile(externalAuth)
      : null;
    return renderRegister({
      returnTo: safeReturnTo(externalProfile?.returnTo || returnTo),
      error:
        externalAuth && !externalProfile
          ? "External registration expired. Please choose your provider again."
          : error,
      csrfToken,
      providers: await this.configuredProviders("register"),
      externalAuth: externalProfile ? externalAuth : undefined,
      externalProvider: externalProfile?.provider,
      values: externalProfile
        ? {
            email: externalProfile.email,
            first_name: externalProfile.firstName || "",
            last_name: externalProfile.lastName || "",
          }
        : undefined,
    });
  }

  @Post("register")
  @Public("Registration validates CSRF, legal acceptance and input before creating a tenant account")
  @Header("Cache-Control", "no-store")
  async submitRegister(
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const returnTo = safeReturnTo(body.return_to);
    const csrfToken = getOrSetCsrf(req, res);
    const providers = await this.configuredProviders("register");

    if (!verifyCsrf(req, body._csrf)) {
      res.status(403).send(
        renderRegister({
          returnTo,
          error: "Invalid or expired security token. Please try again.",
          values: body,
          csrfToken,
          providers,
          externalAuth: body.external_auth,
        }),
      );
      return;
    }

    // Bot Wall Honeypot
    if (body.hp_website) {
      res.status(401).send(
        renderRegister({
          returnTo,
          error: "Automated verification failed. Please try again.",
          values: body,
          csrfToken,
          providers,
          externalAuth: body.external_auth,
        }),
      );
      return;
    }

    if (!body.terms_accepted) {
      res.status(400).send(
        renderRegister({
          returnTo,
          error: "You must accept the Terms of Service to continue.",
          values: body,
          csrfToken,
          providers,
          externalAuth: body.external_auth,
        }),
      );
      return;
    }

    try {
      if (body.external_auth) {
        const result = await this.oauth.completeExternalRegistration(
          body.external_auth,
          {
            organizationName: body.organization_name ?? "",
            firstName: body.first_name,
            lastName: body.last_name,
            termsAccepted: true,
          },
          {
            ipAddress: req.ip || req.socket.remoteAddress,
            userAgent: req.headers["user-agent"],
          },
        );
        this.setAuthCookies(res, result);
        res.redirect(302, result.returnTo || returnTo);
        return;
      }

      await this.auth.register(
        {
          organizationName: body.organization_name ?? "",
          firstName: body.first_name ?? "",
          lastName: body.last_name ?? "",
          email: body.email ?? "",
          password: body.password ?? "",
          confirmPassword: body.confirm_password ?? body.password ?? "",
          termsAccepted: true,
        },
        {
          ipAddress: req.ip || req.socket.remoteAddress,
          userAgent: req.headers["user-agent"],
        },
      );

      // Auto-authenticate newly registered organization admin
      const result = (await this.auth.login(
        {
          email: body.email ?? "",
          password: body.password ?? "",
        } as never,
        {
          ipAddress: req.ip || req.socket.remoteAddress,
          userAgent: req.headers["user-agent"],
        } as never,
      )) as Record<string, unknown>;

      this.setAuthCookies(res, result);
      res.redirect(302, returnTo);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Registration failed.";
      res.status(400).send(
        renderRegister({
          returnTo,
          error: message,
          values: body,
          csrfToken,
          providers,
          externalAuth: body.external_auth,
        }),
      );
    }
  }

  // ── 4. FORGOT PASSWORD & RECOVERY ────────────────────────────────────────

  @Get("forgot-password")
  @Public("Password-recovery form creates only a CSRF token")
  @Header("Cache-Control", "no-store")
  forgotPasswordForm(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query("return_to") returnTo?: string,
    @Query("error") error?: string,
    @Query("success") success?: string,
  ): string {
    const csrfToken = getOrSetCsrf(req, res);
    return renderForgotPassword({
      returnTo: safeReturnTo(returnTo),
      error,
      success,
      csrfToken,
    });
  }

  @Post("forgot-password")
  @Public("Password recovery is rate limited and sends an opaque one-time reset token")
  @Header("Cache-Control", "no-store")
  async submitForgotPassword(
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const returnTo = safeReturnTo(body.return_to);
    const csrfToken = getOrSetCsrf(req, res);

    if (!verifyCsrf(req, body._csrf)) {
      res.status(403).send(
        renderForgotPassword({
          returnTo,
          error: "Invalid or expired security token. Please try again.",
          csrfToken,
        }),
      );
      return;
    }

    if (!body.email) {
      res.status(400).send(
        renderForgotPassword({
          returnTo,
          error: "Please enter your email address.",
          csrfToken,
        }),
      );
      return;
    }

    try {
      await this.auth.forgotPassword({ email: body.email });
      res.send(
        renderForgotPassword({
          returnTo,
          success:
            "If an account matches that email address, a password reset link has been dispatched.",
          csrfToken,
        }),
      );
    } catch {
      res.send(
        renderForgotPassword({
          returnTo,
          success:
            "If an account matches that email address, a password reset link has been dispatched.",
          csrfToken,
        }),
      );
    }
  }

  // ── 5. RESET PASSWORD ───────────────────────────────────────────────────

  @Get("reset-password")
  @Public("Password-reset form requires an opaque one-time reset token")
  @Header("Cache-Control", "no-store")
  resetPasswordForm(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query("token") token?: string,
    @Query("return_to") returnTo?: string,
    @Query("error") error?: string,
  ): string {
    const csrfToken = getOrSetCsrf(req, res);
    return renderResetPassword({
      token: token || "",
      returnTo: safeReturnTo(returnTo),
      error,
      csrfToken,
    });
  }

  @Post("reset-password")
  @Public("Password reset consumes an opaque one-time reset token with CSRF validation")
  @Header("Cache-Control", "no-store")
  async submitResetPassword(
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const returnTo = safeReturnTo(body.return_to);
    const token = body.token;
    const csrfToken = getOrSetCsrf(req, res);

    if (!verifyCsrf(req, body._csrf)) {
      res.status(403).send(
        renderResetPassword({
          token: token || "",
          returnTo,
          error: "Invalid or expired security token. Please try again.",
          csrfToken,
        }),
      );
      return;
    }

    if (!token) {
      res.status(400).send(
        renderResetPassword({
          token: "",
          returnTo,
          error: "Missing or invalid password reset token.",
          csrfToken,
        }),
      );
      return;
    }

    if (body.password !== body.confirm_password) {
      res.status(400).send(
        renderResetPassword({
          token,
          returnTo,
          error: "Passwords do not match.",
          csrfToken,
        }),
      );
      return;
    }

    try {
      await this.auth.resetPassword({
        token,
        password: body.password ?? "",
        confirmPassword: body.confirm_password ?? "",
      });

      res.send(
        renderLogin({
          returnTo,
          success:
            "Password reset successfully. Please sign in with your new password.",
          csrfToken,
        }),
      );
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Invalid or expired reset token.";
      res.status(400).send(
        renderResetPassword({
          token,
          returnTo,
          error: message,
          csrfToken,
        }),
      );
    }
  }

  // ── 6. EMAIL VERIFICATION ───────────────────────────────────────────────

  @Get("verify-email")
  @Public("Email verification consumes an opaque one-time verification token")
  @Header("Cache-Control", "no-store")
  async verifyEmailPage(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query("token") token?: string,
    @Query("return_to") returnTo?: string,
  ): Promise<string> {
    const safeReturn = safeReturnTo(returnTo);
    const csrfToken = getOrSetCsrf(req, res);
    if (!token) {
      return renderVerifyEmail({
        returnTo: safeReturn,
        status: "missing",
        csrfToken,
      });
    }

    try {
      await this.auth.verifyEmail({ token });
      return renderVerifyEmail({
        returnTo: safeReturn,
        status: "success",
        csrfToken,
      });
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : "Verification token expired or invalid.";
      return renderVerifyEmail({
        returnTo: safeReturn,
        status: "error",
        error: message,
        csrfToken,
      });
    }
  }

  @Post("verify-email/resend")
  @Public("Email-verification resend is rate limited and does not require an existing session")
  @Header("Cache-Control", "no-store")
  async resendEmailVerification(
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const returnTo = safeReturnTo(body.return_to);
    const csrfToken = getOrSetCsrf(req, res);

    if (!verifyCsrf(req, body._csrf)) {
      res.status(403).send(
        renderVerifyEmail({
          returnTo,
          status: "error",
          error: "Invalid or expired security token. Please try again.",
          csrfToken,
        }),
      );
      return;
    }

    if (!body.email) {
      res.status(400).send(
        renderVerifyEmail({
          returnTo,
          status: "error",
          error: "Please provide an email address.",
          csrfToken,
        }),
      );
      return;
    }

    try {
      await this.auth.resendVerification({ email: body.email });
      res.send(
        renderVerifyEmail({
          returnTo,
          status: "resent",
          message: "A fresh verification link has been sent to your email.",
          csrfToken,
        }),
      );
    } catch {
      res.send(
        renderVerifyEmail({
          returnTo,
          status: "resent",
          message: "If an unverified account exists, a link was sent.",
          csrfToken,
        }),
      );
    }
  }

  // ── HELPERS ─────────────────────────────────────────────────────────────

  private setAuthCookies(
    res: Response,
    result: Record<string, unknown>,
  ): void {
    setSessionCookies(res, result);
  }
}


export function setSessionCookies(
  res: Response,
  result: Record<string, unknown>,
): void {
  const accessToken =
    (result.token as string) ??
    (result.accessToken as string) ??
    (result.rawAccessToken as string);
  const refreshToken =
    (result.refreshToken as string) ??
    (result.rawRefreshToken as string);

  if (accessToken) {
    res.cookie(AUTH_COOKIE, accessToken, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
  }

  if (refreshToken) {
    res.cookie(REFRESH_COOKIE, refreshToken, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });
  }
}

export function safeReturnTo(raw?: string): string {
  if (!raw) return "/";
  if (raw.startsWith("/") && !raw.startsWith("//")) return raw;
  try {
    const parsed = new URL(raw);
    const isAllowedHost =
      parsed.hostname === "localhost" ||
      parsed.hostname === "127.0.0.1" ||
      parsed.hostname.endsWith(".uni-erp.com") ||
      parsed.hostname.endsWith(".unierp.internal");
    if (isAllowedHost) return raw;
  } catch {
    // Invalid absolute URLs are intentionally reduced to the safe root route.
  }
  return "/";
}

function escapeHtml(s?: string): string {
  if (!s) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ──────────────────────────────────────────────────────────────────────────
// UNIFIED LIGHT-MODE FIRST ENTERPRISE UI TEMPLATE
// ──────────────────────────────────────────────────────────────────────────

const BASE_STYLES = `
  :root, [data-theme="light"] {
    --bg-page: #f8fafc;
    --bg-mesh-1: rgba(99, 102, 241, 0.08);
    --bg-mesh-2: rgba(14, 165, 233, 0.06);
    --bg-card: #ffffff;
    --bg-hero: #f1f5f9;
    --bg-hero-subtle: #e2e8f0;
    --bg-input: #ffffff;
    --bg-input-hover: #f8fafc;
    --bg-input-focus: #ffffff;
    --bg-btn-sec: #ffffff;
    --bg-btn-sec-hover: #f8fafc;
    --bg-pill: #f1f5f9;
    --bg-pill-active: #ffffff;
    --bg-slider-track: #f1f5f9;
    --bg-slider-handle: #ffffff;

    --border-card: #e2e8f0;
    --border-subtle: #f1f5f9;
    --border-input: #cbd5e1;
    --border-input-hover: #94a3b8;
    --border-input-focus: #4f46e5;
    --border-btn-sec: #e2e8f0;
    --border-btn-sec-hover: #cbd5e1;

    --text-title: #0f172a;
    --text-primary: #1e293b;
    --text-secondary: #475569;
    --text-muted: #64748b;
    --text-placeholder: #94a3b8;
    --text-btn-sec: #1e293b;

    --brand-primary: #4f46e5;
    --brand-primary-hover: #4338ca;
    --brand-accent: #6366f1;
    --brand-light: #eef2ff;
    --brand-text-on-light: #4338ca;
    --brand-ring: rgba(79, 70, 229, 0.16);

    --success-bg: #ecfdf5;
    --success-border: #a7f3d0;
    --success-text: #065f46;
    --success-solid: #10b981;

    --error-bg: #fff1f2;
    --error-border: #fecdd3;
    --error-text: #9f1239;
    --error-solid: #f43f5e;

    --shadow-sm: 0 1px 2px 0 rgba(15, 23, 42, 0.04);
    --shadow-md: 0 4px 6px -1px rgba(15, 23, 42, 0.06), 0 2px 4px -2px rgba(15, 23, 42, 0.04);
    --shadow-card: 0 20px 25px -5px rgba(15, 23, 42, 0.06), 0 8px 10px -6px rgba(15, 23, 42, 0.04);
    --shadow-btn: 0 2px 4px rgba(79, 70, 229, 0.2);
  }

  [data-theme="dark"] {
    --bg-page: #0b0f19;
    --bg-mesh-1: rgba(99, 102, 241, 0.12);
    --bg-mesh-2: rgba(14, 165, 233, 0.08);
    --bg-card: #111827;
    --bg-hero: #0f172a;
    --bg-hero-subtle: #1e293b;
    --bg-input: #1f2937;
    --bg-input-hover: #283548;
    --bg-input-focus: #1f2937;
    --bg-btn-sec: #1f2937;
    --bg-btn-sec-hover: #374151;
    --bg-pill: #1f2937;
    --bg-pill-active: #374151;
    --bg-slider-track: #1f2937;
    --bg-slider-handle: #374151;

    --border-card: #1f2937;
    --border-subtle: #1f2937;
    --border-input: #374151;
    --border-input-hover: #4b5563;
    --border-input-focus: #6366f1;
    --border-btn-sec: #374151;
    --border-btn-sec-hover: #4b5563;

    --text-title: #f8fafc;
    --text-primary: #f1f5f9;
    --text-secondary: #cbd5e1;
    --text-muted: #94a3b8;
    --text-placeholder: #64748b;
    --text-btn-sec: #f8fafc;

    --brand-primary: #6366f1;
    --brand-primary-hover: #4f46e5;
    --brand-accent: #818cf8;
    --brand-light: #1e1b4b;
    --brand-text-on-light: #a5b4fc;
    --brand-ring: rgba(99, 102, 241, 0.25);

    --success-bg: rgba(16, 185, 129, 0.12);
    --success-border: rgba(16, 185, 129, 0.3);
    --success-text: #34d399;
    --success-solid: #10b981;

    --error-bg: rgba(244, 63, 94, 0.12);
    --error-border: rgba(244, 63, 94, 0.3);
    --error-text: #fb7185;
    --error-solid: #f43f5e;

    --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.2);
    --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    --shadow-card: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    --shadow-btn: 0 2px 8px rgba(99, 102, 241, 0.35);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, Helvetica, Arial, sans-serif;
    background: var(--bg-page);
    color: var(--text-primary);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 48px 16px 16px;
    position: relative;
    overflow-x: hidden;
    background-image: 
      radial-gradient(at 0% 0%, var(--bg-mesh-1) 0px, transparent 50%),
      radial-gradient(at 100% 100%, var(--bg-mesh-2) 0px, transparent 50%);
  }

  /* Top Navigation Bar */
  .auth-top-bar {
    position: absolute;
    top: 14px;
    left: 20px;
    right: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    z-index: 20;
  }
  .auth-brand-logo {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    text-decoration: none;
    color: var(--text-title);
    font-weight: 700;
    font-size: 1.05rem;
    letter-spacing: -0.02em;
  }
  .auth-brand-icon {
    width: 28px;
    height: 28px;
    background: linear-gradient(135deg, #4f46e5 0%, #0ea5e9 100%);
    border-radius: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #ffffff;
    box-shadow: 0 2px 6px rgba(79, 70, 229, 0.25);
  }
  .theme-toggle-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    background: var(--bg-card);
    border: 1px solid var(--border-card);
    color: var(--text-secondary);
    font-size: 0.75rem;
    font-weight: 500;
    padding: 4px 10px;
    border-radius: 9999px;
    cursor: pointer;
    box-shadow: var(--shadow-sm);
    transition: all 0.15s ease;
  }
  .theme-toggle-btn:hover {
    border-color: var(--border-input);
    color: var(--text-title);
  }
  .theme-toggle-btn:focus-visible,
  .social-btn:focus-visible,
  .btn-submit:focus-visible,
  .input-icon-btn:focus-visible,
  .auth-link:focus-visible,
  .checkbox-label input:focus-visible {
    outline: 2px solid var(--brand-ring);
    outline-offset: 2px;
  }

  /* Centered Card Layout */
  .auth-container {
    width: 100%;
    max-width: 396px;
    margin: 8px auto;
    background: var(--bg-card);
    border: 1px solid var(--border-card);
    border-radius: 12px;
    box-shadow: var(--shadow-card);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    position: relative;
    z-index: 10;
  }
  .auth-container--register {
    max-width: 760px;
    width: 100%;
  }
  .form-grid--two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px 18px;
  }
  @media (max-width: 640px) {
    .form-grid--two-col {
      grid-template-columns: 1fr;
      gap: 10px;
    }
  }

  /* Form Panel */
  .auth-form-panel {
    padding: 24px 28px 22px;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }

  @media (max-width: 640px) {
    body { padding: 52px 10px 12px; align-items: flex-start; }
    .auth-top-bar { top: 10px; left: 12px; right: 12px; }
    .auth-form-panel { padding: 18px 16px 16px; }
  }

  .auth-header {
    margin-bottom: 12px;
  }
  .auth-eyebrow {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    margin-bottom: 5px;
    padding: 2px 7px;
    border-radius: 9999px;
    background: var(--brand-light);
    color: var(--brand-primary);
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .auth-eyebrow::before {
    content: "";
    width: 5px;
    height: 5px;
    border-radius: 50%;
    background: var(--success-solid);
    box-shadow: 0 0 0 2px var(--success-bg);
  }
  .auth-header h1 {
    font-size: 1.1875rem;
    font-weight: 700;
    color: var(--text-title);
    letter-spacing: -0.02em;
    margin-bottom: 2px;
    line-height: 1.25;
  }
  .auth-header p {
    font-size: 0.78125rem;
    color: var(--text-secondary);
    line-height: 1.35;
  }

  .auth-alternative {
    margin-top: 10px;
    padding-top: 8px;
    border-top: 1px solid var(--border-subtle);
    color: var(--text-secondary);
    font-size: 0.75rem;
    text-align: center;
  }

  /* Social SSO Grid */
  .social-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(88px, 1fr));
    gap: 6px;
    margin-bottom: 8px;
  }
  @media (max-width: 340px) {
    .social-grid { grid-template-columns: 1fr; }
  }
  .social-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    height: 34px;
    padding: 0 10px;
    background: var(--bg-btn-sec);
    border: 1px solid var(--border-btn-sec);
    border-radius: 6px;
    color: var(--text-btn-sec);
    font-size: 0.78125rem;
    font-weight: 500;
    text-decoration: none;
    box-shadow: var(--shadow-sm);
    transition: all 0.15s ease;
  }
  .social-btn:hover {
    background: var(--bg-btn-sec-hover);
    border-color: var(--border-btn-sec-hover);
    transform: translateY(-1px);
    box-shadow: var(--shadow-md);
  }
  .social-btn svg {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
  }

  /* Separator */
  .auth-divider {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 8px 0;
    color: var(--text-muted);
    font-size: 0.65625rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .auth-divider::before, .auth-divider::after {
    content: "";
    flex: 1;
    height: 1px;
    background: var(--border-card);
  }

  /* Form Elements */
  .form-group {
    margin-bottom: 9px;
  }
  .form-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }
  @media (max-width: 340px) {
    .form-row { grid-template-columns: 1fr; }
  }
  .form-label {
    display: block;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-secondary);
    margin-bottom: 3px;
  }
  .input-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }
  .form-input {
    width: 100%;
    height: 35px;
    padding: 0 10px;
    font-size: 0.8125rem;
    background: var(--bg-input);
    border: 1px solid var(--border-input);
    border-radius: 6px;
    color: var(--text-primary);
    outline: none;
    transition: all 0.15s ease;
  }
  .form-input:hover {
    border-color: var(--border-input-hover);
    background: var(--bg-input-hover);
  }
  .form-input:focus {
    border-color: var(--border-input-focus);
    background: var(--bg-input-focus);
    box-shadow: 0 0 0 2px var(--brand-ring);
  }
  .form-input::placeholder {
    color: var(--text-placeholder);
    font-size: 0.78125rem;
  }
  .input-icon-btn {
    position: absolute;
    right: 6px;
    background: transparent;
    border: none;
    padding: 4px;
    border-radius: 4px;
    color: var(--text-muted);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: color 0.15s ease;
  }
  .input-icon-btn:hover {
    color: var(--text-primary);
  }

  /* Form Flex Row (Remember + Forgot) */
  .form-extra-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 2px;
    margin-bottom: 10px;
    font-size: 0.75rem;
  }
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
    font-size: 0.75rem;
  }
  .checkbox-label input[type="checkbox"] {
    accent-color: var(--brand-primary);
    width: 13px;
    height: 13px;
  }
  .auth-link {
    color: var(--brand-primary);
    text-decoration: none;
    font-weight: 500;
    font-size: 0.75rem;
    transition: color 0.15s ease;
  }
  .auth-link:hover {
    color: var(--brand-primary-hover);
    text-decoration: underline;
  }
  .skip-link {
    position: fixed;
    top: 8px;
    left: 8px;
    z-index: 1000;
    transform: translateY(-160%);
    padding: 8px 12px;
    border-radius: 6px;
    background: var(--bg-card);
    color: var(--text-title);
    box-shadow: var(--shadow-md);
    font-size: 0.75rem;
  }
  .skip-link:focus { transform: translateY(0); }

  /* Human Verification Slider (Buzzle) */
  .slider-wall-box {
    margin-bottom: 14px;
    background: var(--bg-slider-track);
    border: 1px solid var(--border-card);
    border-radius: 6px;
    padding: 2px;
    position: relative;
    user-select: none;
    overflow: hidden;
    height: 38px;
  }
  .slider-track-text {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.75rem;
    font-weight: 500;
    color: var(--text-muted);
    pointer-events: none;
    z-index: 1;
    transition: opacity 0.2s ease;
  }
  .slider-fill {
    position: absolute;
    top: 0;
    bottom: 0;
    left: 0;
    width: 0;
    background: var(--brand-light);
    border-radius: 5px 0 0 5px;
    pointer-events: none;
  }
  .slider-handle {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 38px;
    height: 32px;
    background: var(--bg-slider-handle);
    border: 1px solid var(--border-input);
    border-radius: 5px;
    box-shadow: var(--shadow-sm);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: grab;
    z-index: 2;
    color: var(--text-secondary);
    transition: background 0.15s ease;
  }
  .slider-handle:active {
    cursor: grabbing;
    background: var(--bg-card);
  }
  .slider-wall-box.verified {
    background: var(--success-bg);
    border-color: var(--success-border);
  }
  .slider-wall-box.verified .slider-track-text {
    color: var(--success-text);
    font-weight: 600;
    opacity: 1;
  }
  .slider-wall-box.verified .slider-handle {
    display: none;
  }

  /* Primary Button */
  .btn-submit {
    width: 100%;
    height: 36px;
    background: linear-gradient(135deg, var(--brand-primary) 0%, var(--brand-accent) 100%);
    border: none;
    border-radius: 6px;
    color: #ffffff;
    font-size: 0.8125rem;
    font-weight: 600;
    letter-spacing: -0.01em;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    box-shadow: var(--shadow-btn);
    transition: all 0.15s ease;
  }
  .btn-submit:hover {
    filter: brightness(1.05);
    transform: translateY(-1px);
    box-shadow: 0 4px 10px rgba(79, 70, 229, 0.28);
  }
  .btn-submit:active {
    transform: translateY(0);
  }

  /* Password Strength Indicator */
  .strength-container {
    margin-top: 4px;
    margin-bottom: 2px;
  }
  .strength-bars {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 3px;
    height: 3px;
    margin-bottom: 3px;
  }
  .strength-bar {
    background: var(--border-card);
    border-radius: 1.5px;
    transition: background 0.2s ease;
  }
  .strength-label {
    font-size: 0.6875rem;
    color: var(--text-muted);
  }

  /* Alerts */
  .alert-banner {
    padding: 7px 10px;
    border-radius: 6px;
    font-size: 0.75rem;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    gap: 8px;
    line-height: 1.35;
  }
  .alert-error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }
  .alert-success {
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    color: var(--success-text);
  }

  /* MFA PIN Inputs */
  .mfa-pin-grid {
    display: flex;
    justify-content: center;
    gap: 8px;
    margin: 20px 0;
  }
  .mfa-pin-box {
    width: 44px;
    height: 52px;
    text-align: center;
    font-size: 1.35rem;
    font-weight: 700;
    font-family: monospace;
    background: var(--bg-input);
    border: 1px solid var(--border-input);
    border-radius: 8px;
    color: var(--text-title);
    outline: none;
    transition: all 0.15s ease;
  }
  .mfa-pin-box:focus {
    border-color: var(--brand-primary);
    box-shadow: 0 0 0 3px var(--brand-ring);
  }

  /* Pulse animation for Web Push */
  .radar-ring {
    position: relative;
    width: 48px;
    height: 48px;
    margin: 0 auto 16px;
    border-radius: 50%;
    background: var(--brand-light);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--brand-primary);
  }
  .radar-ring::after {
    content: "";
    position: absolute;
    inset: -4px;
    border: 2px solid var(--brand-accent);
    border-radius: 50%;
    animation: radarPulse 2s cubic-bezier(0.24, 0, 0.38, 1) infinite;
  }
  @keyframes radarPulse {
    0% { transform: scale(0.9); opacity: 0.8; }
    100% { transform: scale(1.6); opacity: 0; }
  }

  .hp-field { display: none !important; }

  /* Unified Account Center */
  .account-shell {
    width: min(1180px, calc(100% - 32px));
    margin: 28px auto 64px;
    display: grid;
    grid-template-columns: 250px minmax(0, 1fr);
    gap: 28px;
    align-items: start;
  }
  .account-rail {
    position: sticky;
    top: 84px;
    display: grid;
    gap: 20px;
    padding: 20px;
    border: 1px solid var(--border-card);
    border-radius: 16px;
    background: var(--bg-card);
    box-shadow: var(--shadow-sm);
  }
  .account-person { display:flex;align-items:center;gap:12px;min-width:0; }
  .account-person > span,.account-person > img { width:42px;height:42px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;object-fit:cover;background:var(--brand-accent);color:white;font-weight:700;flex:0 0 auto; }
  .account-person div { min-width:0; }
  .account-person strong,.account-person small { display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
  .account-person small { color:var(--text-muted);margin-top:2px; }
  .account-rail nav { display:grid;gap:3px; }
  .account-rail nav a { padding:9px 10px;border-radius:8px;color:var(--text-secondary);font-size:.85rem;text-decoration:none; }
  .account-rail nav a:hover,.account-rail nav a:focus-visible { background:var(--bg-pill);color:var(--text-title); }
  .account-main { display:grid;gap:16px;min-width:0; }
  .account-heading { padding:14px 4px 10px; }
  .account-heading > span { color:var(--brand-accent);font-size:.72rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase; }
  .account-heading h1 { margin:8px 0 6px;font-size:clamp(2rem,5vw,3.5rem);letter-spacing:-.05em;line-height:1; }
  .account-heading p,.account-section p { color:var(--text-secondary); }
  .account-section { scroll-margin-top:84px;padding:24px;border:1px solid var(--border-card);border-radius:16px;background:var(--bg-card);box-shadow:var(--shadow-sm); }
  .account-section-head { display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:18px; }
  .account-section-head h2 { margin:0 0 4px;font-size:1.05rem; }
  .account-section-head p { margin:0;font-size:.825rem; }
  .account-status { display:inline-flex;padding:3px 8px;border:1px solid var(--border-subtle);border-radius:999px;background:var(--bg-pill);color:var(--text-secondary);font-size:.7rem;font-weight:650;white-space:nowrap; }
  .account-form-grid { display:grid;grid-template-columns:1fr 1fr;gap:16px; }
  .account-form-grid label:not(.checkbox-label) { display:grid;gap:7px;color:var(--text-secondary);font-size:.8rem;font-weight:600; }
  .account-span { grid-column:1 / -1; }
  .account-save { width:auto;justify-self:start;padding-inline:24px; }
  .account-row { display:flex;align-items:center;justify-content:space-between;gap:16px;padding:15px 0;border-bottom:1px solid var(--border-subtle); }
  .account-row:last-child { border-bottom:0; }
  .account-muted { color:var(--text-muted);font-size:.78rem;margin-top:3px; }
  .account-danger { border:1px solid color-mix(in srgb,#ef4444 35%,var(--border-subtle));border-radius:8px;background:transparent;color:#dc2626;padding:7px 11px;cursor:pointer; }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      scroll-behavior: auto !important;
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
    }
  }
  @media (max-width: 820px) {
    .account-shell { grid-template-columns:1fr; }
    .account-rail { position:static; }
    .account-rail nav { grid-template-columns:repeat(2,minmax(0,1fr)); }
  }
  @media (max-width: 520px) {
    .account-shell { width:min(100% - 20px,1180px); }
    .account-section { padding:18px; }
    .account-form-grid { grid-template-columns:1fr; }
    .account-span { grid-column:auto; }
    .account-section-head,.account-row { align-items:flex-start;flex-direction:column; }
  }
`;

function renderDocument(title: string, content: string): string {
  const navigation = getPlatformNavigationConfig();
  const documentContent = /<main[\s>]/i.test(content)
    ? content
    : `<main id="main-content">${content}</main>`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>${escapeHtml(title)} · UniERP</title>
  <style>${BASE_STYLES}</style>
  <script>
    function toggleTheme() {
      const current = document.documentElement.getAttribute('data-theme') || 'light';
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('unierp.theme', next);
      document.cookie = 'unierp_theme=' + next + '; Path=/; Max-Age=31536000; SameSite=Lax';
      updateThemeIcon(next);
    }
    function updateThemeIcon(t) {
      const el = document.getElementById('theme-icon');
      if (el) el.textContent = t === 'dark' ? '☀️' : '🌙';
    }
    (function() {
      const cookie = document.cookie.split('; ').find(function(entry){ return entry.indexOf('unierp_theme=') === 0; });
      const saved = (cookie ? decodeURIComponent(cookie.split('=').slice(1).join('=')) : null) || localStorage.getItem('unierp.theme') || localStorage.getItem('unerp.theme') || 'light';
      document.documentElement.setAttribute('data-theme', saved);
    })();
  </script>
</head>
<body>
  <a class="skip-link" href="#main-content">Skip to main content</a>
  <div class="auth-top-bar">
    <a href="${escapeHtml(navigation.wizardUrl)}" class="auth-brand-logo">
      <div class="auth-brand-icon">
        <svg width="20" height="20" viewBox="0 0 32 32" fill="none" aria-hidden="true">
          <path d="M4 5.5 16 1l12 4.5v9.7c0 7.2-4.8 12.5-12 15.8C8.8 27.7 4 22.4 4 15.2V5.5Z" fill="currentColor"/>
          <path d="M10 9v7.2c0 4 2.2 6.1 6 6.1s6-2.1 6-6.1V9h-3.7v7c0 2.1-.7 3.1-2.3 3.1s-2.3-1-2.3-3.1V9H10Z" fill="var(--bg-card)"/>
        </svg>
      </div>
      <span>UniERP</span>
    </a>
    <button type="button" id="theme-toggle" class="theme-toggle-btn" aria-label="Toggle theme">
      <span id="theme-icon">🌙</span> Theme
    </button>
  </div>

  ${documentContent}

  <script>
    // Eye toggle function
    function togglePassword(inputId, btn) {
      const input = document.getElementById(inputId);
      if (!input) return;
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      btn.innerHTML = isPassword
        ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>'
        : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
    }
    var themeButton = document.getElementById('theme-toggle');
    if (themeButton) themeButton.addEventListener('click', toggleTheme);
    document.querySelectorAll('[data-password-target]').forEach(function (button) {
      button.addEventListener('click', function () {
        togglePassword(button.getAttribute('data-password-target'), button);
      });
    });
    var strengthInput = document.querySelector('[data-password-strength]');
    if (strengthInput) strengthInput.addEventListener('input', function () {
      if (typeof checkPasswordStrength === 'function') checkPasswordStrength(strengthInput.value);
    });
  </script>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────────────────────
// 1. SIGN IN VIEW
// ──────────────────────────────────────────────────────────────────────────

function providerLabel(provider?: OAuthProviderName): string {
  if (provider === "google") return "Google";
  if (provider === "microsoft") return "Microsoft";
  if (provider === "github") return "GitHub";
  return "External";
}

function parseOAuthProvider(value?: string): OAuthProviderName | null {
  if (value === "google" || value === "microsoft" || value === "github") {
    return value;
  }
  return null;
}

function providerIcon(provider: OAuthProviderName): string {
  if (provider === "google") {
    return '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#4285F4" d="M21.6 12.23c0-.71-.06-1.4-.18-2.06H12v3.9h5.38a4.6 4.6 0 0 1-2 3.02v2.53h3.25c1.9-1.75 2.97-4.33 2.97-7.39Z"/><path fill="#34A853" d="M12 22c2.7 0 4.98-.9 6.63-2.38l-3.25-2.53c-.9.6-2.05.96-3.38.96-2.6 0-4.8-1.76-5.6-4.12H3.05v2.6A10 10 0 0 0 12 22Z"/><path fill="#FBBC05" d="M6.4 13.93A6 6 0 0 1 6.08 12c0-.67.12-1.32.32-1.93v-2.6H3.05A10 10 0 0 0 2 12c0 1.63.39 3.17 1.05 4.53l3.35-2.6Z"/><path fill="#EA4335" d="M12 5.95c1.47 0 2.79.5 3.83 1.5l2.87-2.88A9.63 9.63 0 0 0 12 2a10 10 0 0 0-8.95 5.47l3.35 2.6c.8-2.36 3-4.12 5.6-4.12Z"/></svg>';
  }
  if (provider === "microsoft") {
    return '<svg viewBox="0 0 23 23" aria-hidden="true"><path fill="#f35325" d="M1 1h10v10H1z"/><path fill="#81bc06" d="M12 1h10v10H12z"/><path fill="#05a6f0" d="M1 12h10v10H1z"/><path fill="#ffba08" d="M12 12h10v10H12z"/></svg>';
  }
  return '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.88c-2.78.6-3.37-1.18-3.37-1.18-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.89 1.53 2.34 1.09 2.91.83.09-.65.35-1.09.64-1.34-2.22-.25-4.56-1.11-4.56-4.94 0-1.09.39-1.99 1.03-2.69-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.03A9.6 9.6 0 0 1 12 6.8c.85 0 1.71.12 2.5.34 1.91-1.3 2.75-1.03 2.75-1.03.55 1.38.2 2.4.1 2.65.64.7 1.03 1.6 1.03 2.69 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.86v2.77c0 .27.18.58.69.48A10 10 0 0 0 12 2Z"/></svg>';
}

function renderProviderButtons(
  providers: OAuthProviderName[],
  journey: "login" | "register",
  returnTo: string,
): string {
  if (!providers.length) return "";
  const returnToEnc = encodeURIComponent(returnTo);
  return `<div class="social-grid" aria-label="Continue with an existing account">
    ${providers
      .map((provider) => {
        const label = providerLabel(provider);
        return `<a href="/api/v1/auth/oauth/${provider}/start?journey=${journey}&return_to=${returnToEnc}" class="social-btn" title="Continue with ${label}" aria-label="Continue with ${label}">
          ${providerIcon(provider)}<span>${label}</span>
        </a>`;
      })
      .join("")}
  </div>`;
}

function resolvePlatformBackNavigation(
  returnTo?: string,
  referer?: string,
): { label: string; url: string } {
  const target = returnTo || referer;
  const wizardUrl = getPlatformNavigationConfig().wizardUrl;

  if (!target) {
    return { label: "← Platform Wizard", url: wizardUrl };
  }

  try {
    const url = new URL(target, "http://localhost:4000");
    const port = url.port;
    const path = url.pathname;

    // Port 4003 - Tenant Applications
    if (port === "4003") {
      if (path.startsWith("/apps") || path === "/" || path === "") {
        return { label: "← Back to app list", url: `${url.origin}/apps` };
      }
      if (path.startsWith("/dashboard")) {
        return { label: "← Back to Dashboard", url: `${url.origin}/dashboard` };
      }
      return { label: "← Back to Tenant Applications", url: `${url.origin}/apps` };
    }

    // Port 4000 - Platform Wizard
    if (port === "4000") {
      return { label: "← Back to Platform Wizard", url: `${url.origin}/` };
    }

    // Port 4001 - Marketing Site
    if (port === "4001") {
      return { label: "← Back to Marketing Site", url: `${url.origin}/` };
    }

    // Port 4002 - Provider Admin OS / Console
    if (port === "4002") {
      return { label: "← Back to Provider Admin OS", url: `${url.origin}/` };
    }

    // Port 4004 - Tenant Websites
    if (port === "4004") {
      return { label: "← Back to Tenant Website", url: `${url.origin}/` };
    }

    // Port 4005 - Web Studio
    if (port === "4005") {
      return { label: "← Back to Web Studio", url: `${url.origin}/` };
    }

    // Port 4006 - Tenant Admin OS / OCC
    if (port === "4006") {
      return { label: "← Back to Tenant Admin", url: `${url.origin}/` };
    }

    // Port 4007 - Marketplace
    if (port === "4007") {
      return { label: "← Back to Marketplace", url: `${url.origin}/` };
    }

    // Port 4008 - Developer Platform
    if (port === "4008") {
      return { label: "← Back to Developer Platform", url: `${url.origin}/` };
    }

    // Generic URL fallback
    if (path.includes("app")) {
      return { label: "← Back to app list", url: target };
    }
    return { label: "← Back to application", url: target };
  } catch {
    return { label: "← Platform Wizard", url: wizardUrl };
  }
}

function renderAccountCenter(opts: {
  configured: OAuthProviderName[];
  connected: OAuthProviderName[];
  email?: string;
  firstName?: string;
  lastName?: string;
  avatar?: string | null;
  preferences?: unknown;
  mfaEnabled: boolean;
  emailVerified: boolean;
  sessions: Array<{
    id: string;
    device: string | null;
    browser: string | null;
    location: string | null;
    platform: string | null;
    lastActivityAt: Date;
    expiresAt: Date | null;
    current: boolean;
  }>;
  passkeys: Array<{
    id: string;
    name: string;
    deviceType: string | null;
    backedUp: boolean;
    createdAt: Date;
    lastUsedAt: Date | null;
  }>;
  contacts: Array<{
    id: string;
    value: string;
    label: string;
    isPrimary: boolean;
    verifiedAt: Date | null;
    createdAt: Date;
  }>;
  organizations: AccountOrganization[];
  privacy: {
    exports: Array<{
      id: string;
      status: string;
      createdAt: Date;
      completedAt: Date | null;
      expiresAt: Date | null;
    }>;
    erasures: Array<{
      id: string;
      status: string;
      createdAt: Date;
      eligibleAt: Date | null;
      cancelledAt: Date | null;
      erasedAt: Date | null;
    }>;
  };
  backNavigation?: { label: string; url: string };
  csrfToken: string;
  error?: string;
  success?: string;
}): string {
  const navigation = getPlatformNavigationConfig();
  const preferences = opts.preferences && typeof opts.preferences === "object" && !Array.isArray(opts.preferences)
    ? opts.preferences as Record<string, unknown>
    : {};
  const selectedTheme = typeof preferences.theme === "string" ? preferences.theme : "system";
  const selectedDensity = typeof preferences.density === "string" ? preferences.density : "comfortable";
  const reduceMotion = preferences.reduceMotion === true;
  const initials = `${opts.firstName?.[0] ?? ""}${opts.lastName?.[0] ?? ""}`.toUpperCase() || "U";
  const rows = (["google", "microsoft", "github"] as const)
    .map((provider) => {
      const label = providerLabel(provider);
      const connected = opts.connected.includes(provider);
      const available = opts.configured.includes(provider);
      const action = connected
        ? `<form method="POST" action="/oidc/account/unlink" style="margin:0">
            <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken)}"/>
            <input type="hidden" name="provider" value="${provider}"/>
            <button type="submit" class="social-btn" style="width:auto">Disconnect</button>
          </form>`
        : available
          ? `<a class="social-btn" style="width:auto" href="/api/v1/auth/oauth/${provider}/link?return_to=${encodeURIComponent("/oidc/account")}">Connect</a>`
          : `<span style="color:var(--text-muted);font-size:.8125rem">Not configured</span>`;
      return `<div style="display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px 0;border-bottom:1px solid var(--border-subtle)">
        <div style="display:flex;align-items:center;gap:12px">
          <span style="width:24px;height:24px;display:inline-flex">${providerIcon(provider)}</span>
          <div><strong>${label}</strong><div style="color:var(--text-muted);font-size:.8125rem">${connected ? "Connected" : "Not connected"}</div></div>
        </div>
        ${action}
      </div>`;
    })
    .join("");

  const sessions = opts.sessions.map((session) => `<div class="account-row">
    <div>
      <strong>${escapeHtml(session.device || session.platform || "Web session")}${session.current ? ' <span class="account-status">Current</span>' : ""}</strong>
      <div class="account-muted">${escapeHtml([session.browser, session.location].filter(Boolean).join(" · ") || "Unknown browser or location")}</div>
      <div class="account-muted">Active ${escapeHtml(session.lastActivityAt.toISOString().replace("T", " ").slice(0, 16))} UTC</div>
    </div>
    ${session.current ? '<span class="account-muted">This device</span>' : `<form method="POST" action="/oidc/account/sessions/revoke">
      <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken)}"/>
      <input type="hidden" name="session_id" value="${escapeHtml(session.id)}"/>
      <button type="submit" class="account-danger">Revoke</button>
    </form>`}
  </div>`).join("");

  const passkeys = opts.passkeys.map((passkey) => `<div class="account-row">
    <div>
      <strong>${escapeHtml(passkey.name)}</strong>
      <div class="account-muted">${passkey.deviceType === "multiDevice" ? "Synced passkey" : "Device-bound passkey"}${passkey.backedUp ? " · backed up" : ""}</div>
      <div class="account-muted">Added ${escapeHtml(passkey.createdAt.toISOString().slice(0, 10))}${passkey.lastUsedAt ? ` · last used ${escapeHtml(passkey.lastUsedAt.toISOString().slice(0, 10))}` : ""}</div>
    </div>
    <button type="button" class="account-danger" data-passkey-delete="${escapeHtml(passkey.id)}">Remove</button>
  </div>`).join("");

  const contacts = opts.contacts.map((contact) => `<div class="account-row">
    <div>
      <strong>${escapeHtml(contact.label)}${contact.isPrimary ? ' <span class="account-status">Primary</span>' : ""}</strong>
      <div class="account-muted">${escapeHtml(contact.value)}</div>
      <div class="account-muted">${contact.verifiedAt ? `Verified ${escapeHtml(contact.verifiedAt.toISOString().slice(0, 10))}` : "Verification pending"}</div>
    </div>
    <div style="display:flex;align-items:center;gap:8px">
      <span class="account-status">${contact.verifiedAt ? "Verified" : "Pending"}</span>
      ${!contact.isPrimary && !contact.verifiedAt ? `<button type="button" class="social-btn" style="width:auto" data-contact-resend="${escapeHtml(contact.id)}">Resend</button>` : ""}
      ${!contact.isPrimary ? `<button type="button" class="account-danger" data-contact-remove="${escapeHtml(contact.id)}">Remove</button>` : ""}
    </div>
  </div>`).join("");

  const organizations = opts.organizations.map((organization) => `<div class="account-row">
    <div>
      <strong>${escapeHtml(organization.tenant_name)}${organization.is_current ? ' <span class="account-status">Current</span>' : ""}</strong>
      <div class="account-muted">${escapeHtml(organization.tenant_slug)}</div>
    </div>
    ${organization.is_current
      ? '<span class="account-muted">Active workspace</span>'
      : `<div style="display:flex;align-items:center;gap:8px"><button type="button" class="social-btn" style="width:auto" data-organization-switch="${escapeHtml(organization.tenant_id)}">Switch</button><button type="button" class="account-danger" data-organization-leave="${escapeHtml(organization.tenant_id)}" data-organization-name="${escapeHtml(organization.tenant_name)}">Leave</button></div>`}
  </div>`).join("");
  const pendingErasure = opts.privacy.erasures.find((request) => request.status === "PENDING");
  const exportHistory = opts.privacy.exports.map((job) => `<div class="account-row">
    <div><strong>Identity export</strong><div class="account-muted">Requested ${escapeHtml(job.createdAt.toISOString().slice(0, 10))} · ${escapeHtml(job.status.toLowerCase())}${job.expiresAt ? ` · expires ${escapeHtml(job.expiresAt.toISOString().slice(0, 10))}` : ""}</div></div>
    <span class="account-status">${escapeHtml(job.status)}</span>
  </div>`).join("");

  const backBtnUrl = opts.backNavigation?.url || navigation.wizardUrl;
  const backBtnLabel = opts.backNavigation?.label || "← Platform Wizard";

  const content = `<div class="account-shell">
    <aside class="account-rail" aria-label="Account settings">
      <div class="account-person">
        ${opts.avatar ? `<img src="${escapeHtml(opts.avatar)}" alt=""/>` : `<span>${escapeHtml(initials)}</span>`}
        <div><strong>${escapeHtml([opts.firstName, opts.lastName].filter(Boolean).join(" ") || "UniERP account")}</strong><small>${escapeHtml(opts.email || "")}</small></div>
      </div>
      <nav>
        <a href="#profile">Profile</a><a href="#organizations">Organizations</a><a href="#security">Sign-in & security</a><a href="#sessions">Sessions & devices</a><a href="#connections">Connected accounts</a><a href="#appearance">Appearance & accessibility</a><a href="#notifications">Notifications</a><a href="#privacy">Privacy & data</a><a href="#billing">Plans & billing</a><a href="#support">Help & support</a>
      </nav>
      <a class="auth-link" href="${escapeHtml(backBtnUrl)}">${escapeHtml(backBtnLabel)}</a>
    </aside>
    <main class="account-main" id="main-content">
      <header class="account-heading"><span>Unified settings</span><h1>Account Center</h1><p>One identity and preference center for every UniERP platform.</p></header>
      ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}
      ${opts.success ? `<div class="alert-banner alert-success"><span>✓ ${escapeHtml(opts.success)}</span></div>` : ""}
      <section id="profile" class="account-section"><div class="account-section-head"><div><h2>Profile</h2><p>Your name and identity across all workspaces.</p></div><span class="account-status">${opts.emailVerified ? "Verified email" : "Email pending"}</span></div>
        <form method="POST" action="/oidc/account/profile" class="account-form-grid">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken)}"/>
          <label>First name<input class="form-input" name="first_name" required maxlength="80" value="${escapeHtml(opts.firstName || "")}"/></label>
          <label>Last name<input class="form-input" name="last_name" required maxlength="80" value="${escapeHtml(opts.lastName || "")}"/></label>
          <label class="account-span">Email<input class="form-input" value="${escapeHtml(opts.email || "")}" readonly aria-describedby="email-help"/></label>
          <small id="email-help" class="account-span account-muted">Email changes require a verified security flow and are never accepted by this profile form.</small>
          <button class="btn-submit account-save" type="submit">Save profile</button>
        </form>
      </section>
      <section id="organizations" class="account-section"><div class="account-section-head"><div><h2>Organizations</h2><p>Verified workspaces linked to this email identity. Access is re-evaluated after every switch.</p></div><span class="account-status">${opts.organizations.length} workspace${opts.organizations.length === 1 ? "" : "s"}</span></div>
        <input type="hidden" id="account-governance-csrf" value="${escapeHtml(opts.csrfToken)}"/>
        ${organizations || '<p class="account-muted">No verified organization membership is available.</p>'}
        <p id="account-governance-status" class="account-muted" role="status" aria-live="polite"></p>
      </section>
      <section id="security" class="account-section"><div class="account-section-head"><div><h2>Sign-in & security</h2><p>Password, verification, and recovery controls.</p></div><span class="account-status">MFA ${opts.mfaEnabled ? "on" : "off"}</span></div>
        <input type="hidden" id="account-passkey-csrf" value="${escapeHtml(opts.csrfToken)}"/>
        <div class="account-section-head"><div><h3>Contact methods</h3><p>Verified recovery addresses can be used for security notices and future account recovery flows.</p></div><span class="account-status">${opts.contacts.length} contact${opts.contacts.length === 1 ? "" : "s"}</span></div>
        ${contacts || `<div class="account-row"><div><strong>Primary email</strong><div class="account-muted">${escapeHtml(opts.email || "No email configured")}</div></div><span class="account-status">${opts.emailVerified ? "Verified" : "Pending"}</span></div>`}
        <div class="account-form-grid" style="margin-top:16px">
          <label>Label<input id="contact-label" class="form-input" maxlength="40" value="Recovery email" autocomplete="off"/></label>
          <label>Recovery email<input id="contact-email" class="form-input" type="email" maxlength="254" autocomplete="email" placeholder="recovery@example.com"/></label>
          <button id="add-account-contact" class="btn-submit account-save" type="button">Add recovery email</button>
          <p id="account-contact-status" class="account-span account-muted" role="status" aria-live="polite"></p>
        </div>
        <div class="account-row"><div><strong>Password</strong><div class="account-muted">Use a recovery link to rotate your password securely.</div></div><a class="social-btn" href="/oidc/forgot-password">Change password</a></div>
        <div class="account-row"><div><strong>Multi-factor authentication</strong><div class="account-muted">${opts.mfaEnabled ? "Your account requires a second factor." : "Add a second factor to protect privileged actions."}</div></div><a class="social-btn" href="${escapeHtml(navigation.mfaUrl)}">Manage MFA</a></div>
        <div class="account-section-head" style="margin-top:20px"><div><h3>Passkeys and security keys</h3><p>Phishing-resistant sign-in protected by your device PIN, fingerprint, or face.</p></div><span class="account-status">${opts.passkeys.length} enrolled</span></div>
        ${passkeys || '<p class="account-muted">No passkeys enrolled yet.</p>'}
        <div class="account-form-grid" style="margin-top:16px">
          <label class="account-span">Passkey name<input id="passkey-name" class="form-input" maxlength="60" value="My passkey"/></label>
          <button id="add-passkey" class="btn-submit account-save" type="button">Add passkey</button>
          <p id="passkey-account-status" class="account-span account-muted" role="status" aria-live="polite"></p>
        </div>
      </section>
      <section id="sessions" class="account-section"><div class="account-section-head"><div><h2>Sessions & devices</h2><p>Review and revoke active sign-ins.</p></div><span class="account-status">${opts.sessions.length} active</span></div>${sessions || '<p class="account-muted">No active sessions found.</p>'}</section>
      <section id="connections" class="account-section"><div class="account-section-head"><div><h2>Connected accounts</h2><p>External identities you can use to sign in. Changes require a recent sign-in.</p></div></div>${rows}</section>
      <section id="appearance" class="account-section"><div class="account-section-head"><div><h2>Appearance & accessibility</h2><p>Light/dark is always available in navigation; advanced preferences live here.</p></div></div>
        <form method="POST" action="/oidc/account/preferences" class="account-form-grid">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken)}"/>
          <label>Theme<select class="form-input" name="theme">${["system","light","dark","enterprise","modern","minimal","classic","high-contrast"].map((theme) => `<option value="${theme}"${selectedTheme === theme ? " selected" : ""}>${theme.replace("-", " ")}</option>`).join("")}</select></label>
          <label>Density<select class="form-input" name="density"><option value="comfortable"${selectedDensity === "comfortable" ? " selected" : ""}>Comfortable</option><option value="compact"${selectedDensity === "compact" ? " selected" : ""}>Compact</option></select></label>
          <label class="checkbox-label account-span"><input type="checkbox" name="reduce_motion"${reduceMotion ? " checked" : ""}/><span>Reduce non-essential motion</span></label>
          <button class="btn-submit account-save" type="submit">Save preferences</button>
        </form>
      </section>
      <section id="notifications" class="account-section"><div class="account-section-head"><div><h2>Notifications</h2><p>Control email, browser, mobile, and in-product delivery.</p></div><a class="social-btn" href="${escapeHtml(navigation.notificationPreferencesUrl)}">Open preferences</a></div></section>
      <section id="privacy" class="account-section"><div class="account-section-head"><div><h2>Privacy & data</h2><p>Export your identity data or request governed account deletion with a 14-day cooling-off period and legal-hold review.</p></div><a class="social-btn" href="${escapeHtml(navigation.privacyCenterUrl)}">Privacy policy</a></div>
        ${exportHistory}
        <div class="account-row"><div><strong>Portable identity export</strong><div class="account-muted">Downloads a JSON package of your profile, roles, connected identities, sessions, preferences, and passkey metadata. Secrets and credential public keys are excluded.</div></div><button id="privacy-export" type="button" class="social-btn" style="width:auto">Download export</button></div>
        ${pendingErasure
          ? `<div class="account-row"><div><strong>Deletion requested</strong><div class="account-muted">Eligible after ${escapeHtml((pendingErasure.eligibleAt || pendingErasure.createdAt).toISOString().slice(0, 10))}; execution remains subject to legal holds and retention obligations.</div></div><button type="button" class="account-danger" data-deletion-cancel="${escapeHtml(pendingErasure.id)}">Cancel request</button></div>`
          : `<div class="account-form-grid" style="margin-top:16px"><label class="account-span">Deletion reason (optional)<textarea id="deletion-reason" class="form-input" maxlength="500" rows="3"></textarea></label><button id="deletion-request" type="button" class="account-danger account-save">Request account deletion</button></div>`}
        <p id="privacy-status" class="account-muted" role="status" aria-live="polite"></p>
      </section>
      <section id="billing" class="account-section"><div class="account-section-head"><div><h2>Plans & billing</h2><p>Trial status, invoices, payment methods, and plan changes for your organization.</p></div><a class="social-btn" href="${escapeHtml(navigation.billingPortalUrl)}">Billing portal</a></div></section>
      <section id="support" class="account-section"><div class="account-section-head"><div><h2>Help & support</h2><p>Open a support request with the current organization, environment, platform, and policy decision context attached.</p></div><a class="social-btn" href="${escapeHtml(navigation.supportUrl)}">Contact support</a></div></section>
    </main>
  </div>${renderPasskeyClientScript("account")}${renderAccountGovernanceClientScript()}`;
  return renderDocument("Account Center", content);
}

function renderAccountGovernanceClientScript(): string {
  return `<script>
  (function () {
    var csrfNode = document.getElementById('account-governance-csrf');
    if (!csrfNode) return;
    var csrf = csrfNode.value;
    var governanceStatus = document.getElementById('account-governance-status');
    var contactStatus = document.getElementById('account-contact-status');
    var privacyStatus = document.getElementById('privacy-status');
    function status(node, message, error) {
      if (!node) return;
      node.textContent = message;
      node.style.color = error ? 'var(--error-text)' : 'var(--text-muted)';
    }
    async function post(path, body) {
      var response = await fetch(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(Object.assign({ _csrf: csrf }, body || {}))
      });
      var payload = await response.json().catch(function () { return {}; });
      if (!response.ok) throw new Error(payload.message || 'The account action could not be completed.');
      return payload;
    }
    document.querySelectorAll('[data-organization-switch]').forEach(function (button) {
      button.addEventListener('click', async function () {
        try {
          button.disabled = true;
          status(governanceStatus, 'Switching organization…', false);
          var result = await post('/oidc/account/governance/organization/switch', {
            targetTenantId: button.getAttribute('data-organization-switch')
          });
          window.location.assign(result.returnTo || '/oidc/account');
        } catch (error) {
          button.disabled = false;
          status(governanceStatus, error.message, true);
        }
      });
    });
    document.querySelectorAll('[data-organization-leave]').forEach(function (button) {
      button.addEventListener('click', async function () {
        var name = button.getAttribute('data-organization-name') || 'this organization';
        if (!window.confirm('Leave ' + name + '? Your membership and its active sessions will be disabled. This does not delete organization records.')) return;
        try {
          button.disabled = true;
          status(governanceStatus, 'Removing the organization membership…', false);
          await post('/oidc/account/governance/organization/leave', {
            targetTenantId: button.getAttribute('data-organization-leave')
          });
          window.location.reload();
        } catch (error) {
          button.disabled = false;
          status(governanceStatus, error.message, true);
        }
      });
    });
    var addContactButton = document.getElementById('add-account-contact');
    if (addContactButton) addContactButton.addEventListener('click', async function () {
      var email = (document.getElementById('contact-email') || {}).value || '';
      var label = (document.getElementById('contact-label') || {}).value || '';
      if (!email) {
        status(contactStatus, 'Enter a recovery email address.', true);
        return;
      }
      try {
        addContactButton.disabled = true;
        status(contactStatus, 'Adding the address and sending a verification link…', false);
        await post('/oidc/account/contact/add', { email: email, label: label });
        window.location.reload();
      } catch (error) {
        addContactButton.disabled = false;
        status(contactStatus, error.message, true);
      }
    });
    document.querySelectorAll('[data-contact-resend]').forEach(function (button) {
      button.addEventListener('click', async function () {
        try {
          button.disabled = true;
          status(contactStatus, 'Sending a fresh verification link…', false);
          await post('/oidc/account/contact/resend', { contactId: button.getAttribute('data-contact-resend') });
          status(contactStatus, 'Verification email sent. The new link expires in 30 minutes.', false);
        } catch (error) {
          button.disabled = false;
          status(contactStatus, error.message, true);
        }
      });
    });
    document.querySelectorAll('[data-contact-remove]').forEach(function (button) {
      button.addEventListener('click', async function () {
        if (!window.confirm('Remove this recovery email from your account?')) return;
        try {
          button.disabled = true;
          await post('/oidc/account/contact/remove', { contactId: button.getAttribute('data-contact-remove') });
          window.location.reload();
        } catch (error) {
          button.disabled = false;
          status(contactStatus, error.message, true);
        }
      });
    });
    var exportButton = document.getElementById('privacy-export');
    if (exportButton) exportButton.addEventListener('click', async function () {
      try {
        exportButton.disabled = true;
        status(privacyStatus, 'Preparing your identity export…', false);
        var result = await post('/oidc/account/governance/privacy/export');
        var blob = new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var link = document.createElement('a');
        link.href = url;
        link.download = 'unierp-identity-export-' + result.jobId + '.json';
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        status(privacyStatus, 'Export downloaded. The request record expires in seven days.', false);
      } catch (error) {
        status(privacyStatus, error.message, true);
      } finally {
        exportButton.disabled = false;
      }
    });
    var deletionButton = document.getElementById('deletion-request');
    if (deletionButton) deletionButton.addEventListener('click', async function () {
      if (!window.confirm('Request deletion of this account after the 14-day cooling-off period? Organization ownership and legal holds will be checked before execution.')) return;
      try {
        deletionButton.disabled = true;
        status(privacyStatus, 'Recording your deletion request…', false);
        await post('/oidc/account/governance/privacy/deletion/request', {
          reason: (document.getElementById('deletion-reason') || {}).value || ''
        });
        window.location.reload();
      } catch (error) {
        deletionButton.disabled = false;
        status(privacyStatus, error.message, true);
      }
    });
    document.querySelectorAll('[data-deletion-cancel]').forEach(function (button) {
      button.addEventListener('click', async function () {
        if (!window.confirm('Cancel this pending account-deletion request?')) return;
        try {
          button.disabled = true;
          await post('/oidc/account/governance/privacy/deletion/cancel', {
            requestId: button.getAttribute('data-deletion-cancel')
          });
          window.location.reload();
        } catch (error) {
          button.disabled = false;
          status(privacyStatus, error.message, true);
        }
      });
    });
  })();
  </script>`;
}

function renderPasskeyClientScript(mode: "login" | "account"): string {
  const modeScript = mode === "login"
    ? `
      var loginButton = document.getElementById('passkey-login');
      if (loginButton) loginButton.addEventListener('click', async function () {
        var status = document.getElementById('passkey-login-status');
        try {
          ensureWebAuthn();
          loginButton.disabled = true;
          setStatus(status, 'Waiting for your passkey…');
          var csrf = document.getElementById('passkey-login-csrf').value;
          var returnTo = document.getElementById('passkey-return-to').value;
          var start = await postJson('/oidc/passkeys/authentication/options', { _csrf: csrf, returnTo: returnTo });
          var publicKey = requestOptions(start.options);
          var credential = await navigator.credentials.get({ publicKey: publicKey });
          var assertion = authenticationResponse(credential);
          var result = await postJson('/oidc/passkeys/authentication/verify', {
            _csrf: csrf, handle: start.handle, response: assertion
          });
          setStatus(status, 'Passkey verified. Redirecting…');
          window.location.assign(result.returnTo || '/');
        } catch (error) {
          setStatus(status, friendlyPasskeyError(error));
          loginButton.disabled = false;
        }
      });`
    : `
      var addButton = document.getElementById('add-passkey');
      if (addButton) addButton.addEventListener('click', async function () {
        var status = document.getElementById('passkey-account-status');
        try {
          ensureWebAuthn();
          addButton.disabled = true;
          setStatus(status, 'Waiting for your authenticator…');
          var csrf = document.getElementById('account-passkey-csrf').value;
          var start = await postJson('/oidc/passkeys/registration/options', { _csrf: csrf });
          var publicKey = creationOptions(start.options);
          var credential = await navigator.credentials.create({ publicKey: publicKey });
          await postJson('/oidc/passkeys/registration/verify', {
            _csrf: csrf,
            handle: start.handle,
            name: document.getElementById('passkey-name').value,
            response: registrationResponse(credential)
          });
          setStatus(status, 'Passkey added. Refreshing…');
          window.location.reload();
        } catch (error) {
          setStatus(status, friendlyPasskeyError(error));
          addButton.disabled = false;
        }
      });
      document.querySelectorAll('[data-passkey-delete]').forEach(function (button) {
        button.addEventListener('click', async function () {
          var status = document.getElementById('passkey-account-status');
          if (!window.confirm('Remove this passkey? Other active sessions will be revoked.')) return;
          try {
            button.disabled = true;
            await postJson('/oidc/passkeys/delete', {
              _csrf: document.getElementById('account-passkey-csrf').value,
              passkeyId: button.getAttribute('data-passkey-delete')
            });
            setStatus(status, 'Passkey removed. Refreshing…');
            window.location.reload();
          } catch (error) {
            setStatus(status, friendlyPasskeyError(error));
            button.disabled = false;
          }
        });
      });`;

  return `<script>
    (function () {
      function ensureWebAuthn() {
        if (!window.PublicKeyCredential || !navigator.credentials) {
          throw new Error('Passkeys are not supported by this browser.');
        }
      }
      function bytes(value) {
        var base64 = value.replace(/-/g, '+').replace(/_/g, '/');
        base64 += '='.repeat((4 - base64.length % 4) % 4);
        return Uint8Array.from(atob(base64), function (char) { return char.charCodeAt(0); });
      }
      function base64url(value) {
        var data = new Uint8Array(value);
        var binary = '';
        data.forEach(function (byte) { binary += String.fromCharCode(byte); });
        return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '');
      }
      function creationOptions(options) {
        var result = Object.assign({}, options, {
          challenge: bytes(options.challenge),
          user: Object.assign({}, options.user, { id: bytes(options.user.id) })
        });
        result.excludeCredentials = (options.excludeCredentials || []).map(function (item) {
          return Object.assign({}, item, { id: bytes(item.id) });
        });
        return result;
      }
      function requestOptions(options) {
        var result = Object.assign({}, options, { challenge: bytes(options.challenge) });
        if (options.allowCredentials) {
          result.allowCredentials = options.allowCredentials.map(function (item) {
            return Object.assign({}, item, { id: bytes(item.id) });
          });
        }
        return result;
      }
      function registrationResponse(credential) {
        return {
          id: credential.id,
          rawId: base64url(credential.rawId),
          type: credential.type,
          authenticatorAttachment: credential.authenticatorAttachment || undefined,
          clientExtensionResults: credential.getClientExtensionResults(),
          response: {
            clientDataJSON: base64url(credential.response.clientDataJSON),
            attestationObject: base64url(credential.response.attestationObject),
            transports: credential.response.getTransports ? credential.response.getTransports() : undefined
          }
        };
      }
      function authenticationResponse(credential) {
        var response = {
          clientDataJSON: base64url(credential.response.clientDataJSON),
          authenticatorData: base64url(credential.response.authenticatorData),
          signature: base64url(credential.response.signature)
        };
        if (credential.response.userHandle) response.userHandle = base64url(credential.response.userHandle);
        return {
          id: credential.id,
          rawId: base64url(credential.rawId),
          type: credential.type,
          authenticatorAttachment: credential.authenticatorAttachment || undefined,
          clientExtensionResults: credential.getClientExtensionResults(),
          response: response
        };
      }
      async function postJson(url, body) {
        var response = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify(body)
        });
        var payload = await response.json().catch(function () { return {}; });
        if (!response.ok) throw new Error(payload.message || 'Passkey request failed.');
        return payload;
      }
      function setStatus(node, message) { if (node) node.textContent = message; }
      function friendlyPasskeyError(error) {
        if (error && error.name === 'NotAllowedError') return 'Passkey request cancelled or timed out.';
        return error && error.message ? error.message : 'Passkey request failed.';
      }
      ${modeScript}
    })();
  </script>`;
}

function renderLogin(opts: {
  returnTo: string;
  error?: string;
  success?: string;
  email?: string;
  csrfToken?: string;
  providers?: OAuthProviderName[];
}): string {
  const returnToEnc = encodeURIComponent(opts.returnTo);
  const content = `
    <div class="auth-container auth-container--login">
      <!-- Form Panel -->
      <div class="auth-form-panel">
        <div class="auth-header">
          <span class="auth-eyebrow">Secure identity</span>
          <h1>Sign in to UniERP</h1>
          <p>Use your work account. We’ll route you to the right workspace.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}
        ${opts.success ? `<div class="alert-banner alert-success"><span>✓ ${escapeHtml(opts.success)}</span></div>` : ""}

        ${renderProviderButtons(opts.providers || [], "login", opts.returnTo)}

        ${(opts.providers || []).length ? '<div class="auth-divider">or continue with email</div>' : ""}

        <input type="hidden" id="passkey-login-csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
        <input type="hidden" id="passkey-return-to" value="${escapeHtml(opts.returnTo)}"/>
        <button type="button" id="passkey-login" class="social-btn" style="width:100%;justify-content:center">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="m21 2-2 2m-1.5 1.5L16 7m-1.5 1.5L13 10m-1.5 1.5L10 13m-2-2a5 5 0 1 0-7 7 5 5 0 0 0 7-7z"></path>
          </svg>
          <span>Sign in with a passkey</span>
        </button>
        <p id="passkey-login-status" class="account-muted" role="status" aria-live="polite"></p>
        <div class="auth-divider">or use your password</div>

        <form method="POST" action="/oidc/login">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo)}"/>
          <input type="text" name="hp_website" class="hp-field" tabindex="-1" autocomplete="off"/>

          <div class="form-group">
            <label class="form-label" for="login-email">Work Email</label>
            <input 
              id="login-email" 
              type="email" 
              name="email" 
              required 
              autofocus 
              autocomplete="email" 
              placeholder="name@company.com" 
              value="${escapeHtml(opts.email || "")}" 
              class="form-input"
            />
          </div>

          <div class="form-group">
            <label class="form-label" for="login-password">Password</label>
            <div class="input-wrapper">
              <input 
                id="login-password" 
                type="password" 
                name="password" 
                required 
                autocomplete="current-password" 
                placeholder="••••••••••••" 
                class="form-input"
              />
              <button 
                type="button" 
                class="input-icon-btn" 
                data-password-target="login-password"
                aria-label="Show password"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                  <circle cx="12" cy="12" r="3"></circle>
                </svg>
              </button>
            </div>
          </div>

          <div class="form-extra-row">
            <label class="checkbox-label">
              <input type="checkbox" name="remember" checked />
              <span>Remember me</span>
            </label>
            <a href="/oidc/forgot-password?return_to=${returnToEnc}" class="auth-link">Forgot password?</a>
          </div>

          <button type="submit" class="btn-submit">
            <span>Sign in</span>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
          </button>
        </form>
        <p class="auth-alternative">New to UniERP? <a href="/oidc/register?return_to=${returnToEnc}" class="auth-link">Create a free-trial workspace</a></p>
        ${renderPasskeyClientScript("login")}
      </div>
    </div>
  `;
  return renderDocument("Sign In", content);
}

// ──────────────────────────────────────────────────────────────────────────
// 2. MFA CHALLENGE VIEW
// ──────────────────────────────────────────────────────────────────────────

function renderMfa(opts: {
  returnTo: string;
  challengeToken: string;
  error?: string;
  email?: string;
  csrfToken?: string;
}): string {
  const content = `
    <div class="auth-container" style="max-width: 520px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="radar-ring">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect>
            <line x1="12" y1="18" x2="12.01" y2="18"></line>
          </svg>
        </div>

        <div class="auth-header" style="text-align: center;">
          <h1>Two-Step Verification</h1>
          <p>Approve the push request sent to your mobile device, or enter your 6-digit code.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <form method="POST" action="/oidc/login/mfa" id="mfa-form">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo)}"/>
          <input type="hidden" name="challenge_token" value="${escapeHtml(opts.challengeToken)}"/>
          <input type="hidden" name="email" value="${escapeHtml(opts.email || "")}"/>
          <input type="hidden" name="totp_code" id="totp-combined"/>

          <div class="mfa-pin-grid">
            <input type="text" maxlength="1" class="mfa-pin-box" data-idx="0" autofocus pattern="[0-9]" inputmode="numeric"/>
            <input type="text" maxlength="1" class="mfa-pin-box" data-idx="1" pattern="[0-9]" inputmode="numeric"/>
            <input type="text" maxlength="1" class="mfa-pin-box" data-idx="2" pattern="[0-9]" inputmode="numeric"/>
            <input type="text" maxlength="1" class="mfa-pin-box" data-idx="3" pattern="[0-9]" inputmode="numeric"/>
            <input type="text" maxlength="1" class="mfa-pin-box" data-idx="4" pattern="[0-9]" inputmode="numeric"/>
            <input type="text" maxlength="1" class="mfa-pin-box" data-idx="5" pattern="[0-9]" inputmode="numeric"/>
          </div>

          <button type="submit" class="btn-submit">
            <span>Verify & Continue</span>
          </button>
        </form>

        <div style="margin-top: 20px; text-align: center;">
          <a href="/oidc/login?return_to=${encodeURIComponent(opts.returnTo)}" class="auth-link" style="font-size: 0.8125rem;">← Back to sign in</a>
        </div>
      </div>
    </div>

    <script>
      // Auto-advance PIN inputs
      const boxes = document.querySelectorAll('.mfa-pin-box');
      const combined = document.getElementById('totp-combined');
      const form = document.getElementById('mfa-form');

      boxes.forEach((box, i) => {
        box.addEventListener('input', (e) => {
          if (box.value.length === 1 && i < boxes.length - 1) {
            boxes[i + 1].focus();
          }
          updateCombined();
        });
        box.addEventListener('keydown', (e) => {
          if (e.key === 'Backspace' && !box.value && i > 0) {
            boxes[i - 1].focus();
          }
        });
      });

      function updateCombined() {
        let code = '';
        boxes.forEach(b => code += b.value);
        combined.value = code;
        if (code.length === 6) form.submit();
      }
    </script>
  `;
  return renderDocument("Two-Step Verification", content);
}

// ──────────────────────────────────────────────────────────────────────────
// 3. ORGANIZATION REGISTRATION VIEW
// ──────────────────────────────────────────────────────────────────────────

function renderRegister(opts: {
  returnTo: string;
  error?: string;
  values?: Record<string, string>;
  csrfToken?: string;
  providers?: OAuthProviderName[];
  externalAuth?: string;
  externalProvider?: OAuthProviderName;
}): string {
  const returnToEnc = encodeURIComponent(opts.returnTo);
  const v = opts.values || {};
  const legal = getRegistrationLegalConfig();
  const content = `
    <div class="auth-container auth-container--register">
      <!-- Form Panel -->
      <div class="auth-form-panel">
        <div class="auth-header">
          <span class="auth-eyebrow">30-day free trial</span>
          <h1>Create your UniERP workspace</h1>
          <p>Set up your secure organization account in less than a minute.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        ${opts.externalAuth ? `<div class="alert-banner alert-success"><span>✓ ${escapeHtml(providerLabel(opts.externalProvider))} account verified. Complete your organization details.</span></div>` : renderProviderButtons(opts.providers || [], "register", opts.returnTo)}

        ${!opts.externalAuth && (opts.providers || []).length ? '<div class="auth-divider">or continue with email</div>' : ""}

        <form method="POST" action="/oidc/register">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo)}"/>
          <input type="hidden" name="external_auth" value="${escapeHtml(opts.externalAuth || "")}"/>
          <input type="text" name="hp_website" class="hp-field" tabindex="-1" autocomplete="off"/>

          <div class="form-grid--two-col">
            <div class="form-group">
              <label class="form-label" for="reg-org">Organization Name</label>
              <input 
                id="reg-org" 
                type="text" 
                name="organization_name" 
                autocomplete="organization"
                required 
                placeholder="Acme Global Inc." 
                value="${escapeHtml(v.organization_name || "")}" 
                class="form-input"
              />
            </div>

            <div class="form-group">
              <label class="form-label" for="reg-slug">Workspace Domain Slug</label>
              <input 
                id="reg-slug" 
                type="text" 
                name="workspace_slug" 
                autocomplete="off"
                placeholder="acme-global" 
                value="${escapeHtml(v.workspace_slug || "")}" 
                class="form-input"
              />
            </div>

            <div class="form-group">
              <label class="form-label" for="reg-first">First Name</label>
              <input 
                id="reg-first" 
                type="text" 
                name="first_name" 
                autocomplete="given-name"
                required 
                placeholder="Jane" 
                value="${escapeHtml(v.first_name || "")}" 
                class="form-input"
              />
            </div>

            <div class="form-group">
              <label class="form-label" for="reg-last">Last Name</label>
              <input 
                id="reg-last" 
                type="text" 
                name="last_name" 
                autocomplete="family-name"
                required 
                placeholder="Doe" 
                value="${escapeHtml(v.last_name || "")}" 
                class="form-input"
              />
            </div>

            <div class="form-group">
              <label class="form-label" for="reg-email">Corporate Work Email</label>
              <input 
                id="reg-email" 
                type="email" 
                name="email" 
                required 
                autocomplete="email" 
                placeholder="jane@acme.com" 
                value="${escapeHtml(v.email || "")}" 
                class="form-input"
                ${opts.externalAuth ? "readonly" : ""}
              />
            </div>

            <div class="form-group">
              <label class="form-label" for="reg-phone">Corporate Mobile Number</label>
              <input 
                id="reg-phone" 
                type="tel" 
                name="phone" 
                autocomplete="tel" 
                placeholder="+1 (555) 000-0000" 
                value="${escapeHtml(v.phone || "")}" 
                class="form-input"
              />
            </div>

            ${!opts.externalAuth ? `
            <div class="form-group">
              <label class="form-label" for="reg-password">Password</label>
              <div class="input-wrapper">
                <input 
                  id="reg-password" 
                  type="password" 
                  name="password" 
                  required 
                  autocomplete="new-password" 
                  placeholder="Minimum 8 characters" 
                  class="form-input"
                  data-password-strength
                />
                <button 
                  type="button" 
                  class="input-icon-btn" 
                  data-password-target="reg-password"
                  aria-label="Show password"
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                    <circle cx="12" cy="12" r="3"></circle>
                  </svg>
                </button>
              </div>
              
              <div class="strength-container">
                <div class="strength-bars">
                  <div class="strength-bar" id="bar-1"></div>
                  <div class="strength-bar" id="bar-2"></div>
                  <div class="strength-bar" id="bar-3"></div>
                  <div class="strength-bar" id="bar-4"></div>
                </div>
                <span class="strength-label" id="strength-text">Password strength: requires 8+ chars</span>
              </div>
            </div>

            <div class="form-group">
              <label class="form-label" for="reg-confirm-password">Confirm Password</label>
              <div class="input-wrapper">
                <input 
                  id="reg-confirm-password" 
                  type="password" 
                  name="confirm_password" 
                  required 
                  autocomplete="new-password" 
                  placeholder="Re-enter password" 
                  class="form-input"
                />
                <button 
                  type="button" 
                  class="input-icon-btn" 
                  data-password-target="reg-confirm-password"
                  aria-label="Show confirm password"
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                    <circle cx="12" cy="12" r="3"></circle>
                  </svg>
                </button>
              </div>
            </div>
            ` : ""}
          </div>

          <div class="form-group" style="margin-bottom: 8px;">
            <label class="checkbox-label" style="font-size: 0.75rem; line-height: 1.35;">
              <input type="checkbox" name="terms_accepted" required />
              <span>I agree to the <a href="${escapeHtml(legal.terms.url)}" target="_blank" rel="noopener noreferrer" class="auth-link" aria-label="Terms of Service, version ${escapeHtml(legal.terms.version)} (opens in a new tab)">Terms of Service</a> and acknowledge the <a href="${escapeHtml(legal.privacy.url)}" target="_blank" rel="noopener noreferrer" class="auth-link" aria-label="Privacy Policy, version ${escapeHtml(legal.privacy.version)} (opens in a new tab)">Privacy Policy</a>.</span>
            </label>
            <p class="strength-label" style="margin-top: 3px; font-size: 0.6875rem;">Terms ${escapeHtml(legal.terms.version)} &bull; Privacy ${escapeHtml(legal.privacy.version)}, effective ${escapeHtml(legal.privacy.effectiveDate)}.</p>
          </div>

          <button type="submit" class="btn-submit">
            <span>Create workspace</span>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
          </button>
        </form>
        <p class="auth-alternative">Already have an account? <a href="/oidc/login?return_to=${returnToEnc}" class="auth-link">Sign in</a></p>
      </div>
    </div>

    <script>
      function checkPasswordStrength(p) {
        let score = 0;
        if (p.length >= 8) score++;
        if (p.length >= 12) score++;
        if (/[A-Z]/.test(p) && /[0-9]/.test(p)) score++;
        if (/[^A-Za-z0-9]/.test(p)) score++;

        const colors = ['#f43f5e', '#f59e0b', '#0ea5e9', '#10b981'];
        const labels = ['Weak', 'Fair', 'Good', 'Strong'];
        const activeColor = colors[score - 1] || '#e2e8f0';

        for (let i = 1; i <= 4; i++) {
          const bar = document.getElementById('bar-' + i);
          if (bar) {
            bar.style.background = i <= score ? activeColor : 'var(--border-card)';
          }
        }
        const text = document.getElementById('strength-text');
        if (text) {
          text.textContent = score > 0 ? 'Password strength: ' + labels[score - 1] : 'Password strength: requires 8+ chars';
          text.style.color = score > 0 ? activeColor : 'var(--text-muted)';
        }
      }
    </script>
  `;
  return renderDocument("Create Organization", content);
}

// ──────────────────────────────────────────────────────────────────────────
// 4. FORGOT PASSWORD VIEW
// ──────────────────────────────────────────────────────────────────────────

function renderForgotPassword(opts: {
  returnTo: string;
  error?: string;
  success?: string;
  csrfToken?: string;
}): string {
  const content = `
    <div class="auth-container" style="max-width: 480px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header">
          <h1>Recover Password</h1>
          <p>Enter the email address associated with your account and we will send a password reset link.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}
        ${opts.success ? `<div class="alert-banner alert-success"><span>✓ ${escapeHtml(opts.success)}</span></div>` : ""}

        <form method="POST" action="/oidc/forgot-password">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo)}"/>

          <div class="form-group">
            <label class="form-label" for="rec-email">Work Email Address</label>
            <input 
              id="rec-email" 
              type="email" 
              name="email" 
              required 
              autofocus 
              placeholder="name@company.com" 
              class="form-input"
            />
          </div>

          <button type="submit" class="btn-submit">
            <span>Send Recovery Link</span>
          </button>
        </form>

        <div style="margin-top: 20px; text-align: center;">
          <a href="/oidc/login?return_to=${encodeURIComponent(opts.returnTo)}" class="auth-link" style="font-size: 0.8125rem;">← Back to sign in</a>
        </div>
      </div>
    </div>
  `;
  return renderDocument("Forgot Password", content);
}

// ──────────────────────────────────────────────────────────────────────────
// 5. RESET PASSWORD VIEW
// ──────────────────────────────────────────────────────────────────────────

function renderResetPassword(opts: {
  token: string;
  returnTo: string;
  error?: string;
  csrfToken?: string;
}): string {
  const content = `
    <div class="auth-container" style="max-width: 480px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        <div class="auth-header">
          <h1>Set New Password</h1>
          <p>Please enter your new password below.</p>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <form method="POST" action="/oidc/reset-password">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo)}"/>
          <input type="hidden" name="token" value="${escapeHtml(opts.token)}"/>

          <div class="form-group">
            <label class="form-label" for="reset-pass">New Password</label>
            <div class="input-wrapper">
              <input 
                id="reset-pass" 
                type="password" 
                name="password" 
                required 
                autocomplete="new-password" 
                placeholder="••••••••••••" 
                class="form-input"
              />
              <button 
                type="button" 
                class="input-icon-btn" 
                data-password-target="reset-pass"
                aria-label="Show password"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                  <circle cx="12" cy="12" r="3"></circle>
                </svg>
              </button>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label" for="reset-confirm">Confirm New Password</label>
            <div class="input-wrapper">
              <input 
                id="reset-confirm" 
                type="password" 
                name="confirm_password" 
                required 
                autocomplete="new-password" 
                placeholder="••••••••••••" 
                class="form-input"
              />
              <button 
                type="button" 
                class="input-icon-btn" 
                data-password-target="reset-confirm"
                aria-label="Show password"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                  <circle cx="12" cy="12" r="3"></circle>
                </svg>
              </button>
            </div>
          </div>

          <button type="submit" class="btn-submit">
            <span>Reset Password & Sign In</span>
          </button>
        </form>
      </div>
    </div>
  `;
  return renderDocument("Set New Password", content);
}

// ──────────────────────────────────────────────────────────────────────────
// 6. EMAIL VERIFICATION VIEW
// ──────────────────────────────────────────────────────────────────────────

function renderVerifyEmail(opts: {
  returnTo: string;
  status: "success" | "error" | "missing" | "resent";
  error?: string;
  message?: string;
  csrfToken?: string;
}): string {
  let inner = "";
  if (opts.status === "success") {
    inner = `
      <div style="text-align: center;">
        <div style="font-size: 3rem; margin-bottom: 12px;">🎉</div>
        <h1>Email Verified!</h1>
        <p style="color: var(--text-secondary); margin: 8px 0 24px;">Your corporate email address has been confirmed.</p>
        <a href="${escapeHtml(opts.returnTo)}" class="btn-submit" style="text-decoration: none;">Continue to Workspace →</a>
      </div>
    `;
  } else {
    inner = `
      <div class="auth-header">
        <h1>Email Verification</h1>
        <p>${opts.status === "resent" ? "A new link has been dispatched." : "Confirm your email to unlock all features."}</p>
      </div>

      ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}
      ${opts.message ? `<div class="alert-banner alert-success"><span>✓ ${escapeHtml(opts.message)}</span></div>` : ""}

      <form method="POST" action="/oidc/verify-email/resend">
        <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
        <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo)}"/>

        <div class="form-group">
          <label class="form-label" for="ver-email">Resend Verification Email</label>
          <input 
            id="ver-email" 
            type="email" 
            name="email" 
            required 
            placeholder="name@company.com" 
            class="form-input"
          />
        </div>

        <button type="submit" class="btn-submit">
          <span>Send Fresh Verification Link</span>
        </button>
      </form>
    `;
  }

  const content = `
    <div class="auth-container" style="max-width: 480px; grid-template-columns: 1fr;">
      <div class="auth-form-panel">
        ${inner}
        <div style="margin-top: 20px; text-align: center;">
          <a href="/oidc/login?return_to=${encodeURIComponent(opts.returnTo)}" class="auth-link" style="font-size: 0.8125rem;">← Back to sign in</a>
        </div>
      </div>
    </div>
  `;
  return renderDocument("Verify Email", content);
}
