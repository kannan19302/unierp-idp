import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
  Header,
} from "@nestjs/common";
import type { Request, Response } from "express";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { ApiExcludeController } from "@nestjs/swagger";
import { AuthService } from "../../auth/auth.service";
import { idpPrisma } from "@kannan19302/database";

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
function verifyCsrf(req: Request, submittedToken?: string): boolean {
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
 * Light Mode First with ultra-premium UX, responsive split layout,
 * social SSO, interactive human puzzle verification, CSRF security, and multi-modal MFA.
 */
@ApiExcludeController()
@Controller("oidc")
export class LoginController {
  constructor(private readonly auth: AuthService) {}

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
  @Header("Cache-Control", "no-store")
  loginForm(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query("return_to") returnTo?: string,
    @Query("error") error?: string,
    @Query("success") success?: string,
  ): string {
    const csrfToken = getOrSetCsrf(req, res);
    return renderLogin({
      returnTo: safeReturnTo(returnTo),
      error,
      success,
      csrfToken,
    });
  }

  @Post("login")
  @Header("Cache-Control", "no-store")
  async submitLogin(
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const returnTo = safeReturnTo(body.return_to);
    const csrfToken = getOrSetCsrf(req, res);

    // CSRF verification
    if (!verifyCsrf(req, body._csrf)) {
      res.status(403).send(
        renderLogin({
          returnTo,
          error: "Invalid or expired security token. Please try again.",
          csrfToken,
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
        }),
      );
      return;
    }

    try {
      const isProviderLogin = await this.isInternalPlatformLogin(returnTo);
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
        }),
      );
    }
  }

  // ── 2. MULTI-FACTOR AUTHENTICATION (MFA / 2FA) ──────────────────────────

  @Post("login/mfa")
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
  @Header("Cache-Control", "no-store")
  registerForm(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query("return_to") returnTo?: string,
    @Query("error") error?: string,
  ): string {
    const csrfToken = getOrSetCsrf(req, res);
    return renderRegister({
      returnTo: safeReturnTo(returnTo),
      error,
      csrfToken,
    });
  }

  @Post("register")
  @Header("Cache-Control", "no-store")
  async submitRegister(
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const returnTo = safeReturnTo(body.return_to);
    const csrfToken = getOrSetCsrf(req, res);

    if (!verifyCsrf(req, body._csrf)) {
      res.status(403).send(
        renderRegister({
          returnTo,
          error: "Invalid or expired security token. Please try again.",
          values: body,
          csrfToken,
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
        }),
      );
      return;
    }

    try {
      await this.auth.register({
        organizationName: body.organization_name ?? "",
        firstName: body.first_name ?? "",
        lastName: body.last_name ?? "",
        email: body.email ?? "",
        password: body.password ?? "",
        confirmPassword: body.confirm_password ?? body.password ?? "",
        termsAccepted: true,
      });

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
        }),
      );
    }
  }

  // ── 4. FORGOT PASSWORD & RECOVERY ────────────────────────────────────────

  @Get("forgot-password")
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
  } catch {}
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
    padding: 24px 16px;
    position: relative;
    overflow-x: hidden;
    background-image: 
      radial-gradient(at 0% 0%, var(--bg-mesh-1) 0px, transparent 50%),
      radial-gradient(at 100% 100%, var(--bg-mesh-2) 0px, transparent 50%);
  }

  /* Top Navigation Bar */
  .auth-top-bar {
    position: absolute;
    top: 16px;
    left: 24px;
    right: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    z-index: 20;
  }
  .auth-brand-logo {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    text-decoration: none;
    color: var(--text-title);
    font-weight: 700;
    font-size: 1.15rem;
    letter-spacing: -0.02em;
  }
  .auth-brand-icon {
    width: 32px;
    height: 32px;
    background: linear-gradient(135deg, #4f46e5 0%, #0ea5e9 100%);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #ffffff;
    box-shadow: 0 2px 6px rgba(79, 70, 229, 0.25);
  }
  .theme-toggle-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: var(--bg-card);
    border: 1px solid var(--border-card);
    color: var(--text-secondary);
    font-size: 0.8125rem;
    font-weight: 500;
    padding: 6px 12px;
    border-radius: 9999px;
    cursor: pointer;
    box-shadow: var(--shadow-sm);
    transition: all 0.15s ease;
  }
  .theme-toggle-btn:hover {
    border-color: var(--border-input);
    color: var(--text-title);
  }

  /* Centered Card Layout */
  .auth-container {
    width: 100%;
    max-width: 500px;
    margin: 36px auto;
    background: var(--bg-card);
    border: 1px solid var(--border-card);
    border-radius: 20px;
    box-shadow: var(--shadow-card);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    position: relative;
    z-index: 10;
  }

  /* Form Panel */
  .auth-form-panel {
    padding: 40px 36px;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }

  @media (max-width: 640px) {
    .auth-form-panel { padding: 28px 20px; }
  }

  .auth-header {
    margin-bottom: 24px;
  }
  .auth-header h1 {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--text-title);
    letter-spacing: -0.02em;
    margin-bottom: 6px;
  }
  .auth-header p {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  /* Top Mode Switcher Pill */
  .auth-switcher {
    display: grid;
    grid-template-columns: 1fr 1fr;
    background: var(--bg-pill);
    padding: 4px;
    border-radius: 10px;
    margin-bottom: 24px;
    border: 1px solid var(--border-subtle);
  }
  .auth-switcher-tab {
    text-align: center;
    padding: 8px 12px;
    font-size: 0.8125rem;
    font-weight: 600;
    color: var(--text-muted);
    text-decoration: none;
    border-radius: 8px;
    transition: all 0.15s ease;
  }
  .auth-switcher-tab.active {
    background: var(--bg-pill-active);
    color: var(--text-title);
    box-shadow: var(--shadow-sm);
  }

  /* Social SSO Grid */
  .social-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px;
    margin-bottom: 20px;
  }
  @media (max-width: 480px) {
    .social-grid { grid-template-columns: 1fr; }
  }
  .social-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    height: 40px;
    padding: 0 12px;
    background: var(--bg-btn-sec);
    border: 1px solid var(--border-btn-sec);
    border-radius: 8px;
    color: var(--text-btn-sec);
    font-size: 0.8125rem;
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
    width: 16px;
    height: 16px;
    flex-shrink: 0;
  }

  /* Separator */
  .auth-divider {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 20px 0;
    color: var(--text-muted);
    font-size: 0.75rem;
    font-weight: 500;
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
    margin-bottom: 16px;
  }
  .form-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }
  @media (max-width: 480px) {
    .form-row { grid-template-columns: 1fr; }
  }
  .form-label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 6px;
  }
  .input-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }
  .form-input {
    width: 100%;
    height: 42px;
    padding: 0 14px;
    font-size: 0.875rem;
    background: var(--bg-input);
    border: 1px solid var(--border-input);
    border-radius: 8px;
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
    box-shadow: 0 0 0 3px var(--brand-ring);
  }
  .form-input::placeholder {
    color: var(--text-placeholder);
  }
  .input-icon-btn {
    position: absolute;
    right: 8px;
    background: transparent;
    border: none;
    padding: 6px;
    border-radius: 6px;
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
    margin-bottom: 18px;
    font-size: 0.8125rem;
  }
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
  }
  .checkbox-label input[type="checkbox"] {
    accent-color: var(--brand-primary);
    width: 15px;
    height: 15px;
  }
  .auth-link {
    color: var(--brand-primary);
    text-decoration: none;
    font-weight: 500;
    transition: color 0.15s ease;
  }
  .auth-link:hover {
    color: var(--brand-primary-hover);
    text-decoration: underline;
  }

  /* Human Verification Slider (Buzzle) */
  .slider-wall-box {
    margin-bottom: 18px;
    background: var(--bg-slider-track);
    border: 1px solid var(--border-card);
    border-radius: 8px;
    padding: 3px;
    position: relative;
    user-select: none;
    overflow: hidden;
    height: 44px;
  }
  .slider-track-text {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.8125rem;
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
    border-radius: 6px 0 0 6px;
    pointer-events: none;
  }
  .slider-handle {
    position: absolute;
    top: 3px;
    left: 3px;
    width: 44px;
    height: 38px;
    background: var(--bg-slider-handle);
    border: 1px solid var(--border-input);
    border-radius: 6px;
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
    height: 44px;
    background: linear-gradient(135deg, var(--brand-primary) 0%, var(--brand-accent) 100%);
    border: none;
    border-radius: 8px;
    color: #ffffff;
    font-size: 0.9375rem;
    font-weight: 600;
    letter-spacing: -0.01em;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    box-shadow: var(--shadow-btn);
    transition: all 0.15s ease;
  }
  .btn-submit:hover {
    filter: brightness(1.05);
    transform: translateY(-1px);
  }
  .btn-submit:active {
    transform: translateY(0);
  }

  /* Password Strength Indicator */
  .strength-container {
    margin-top: 6px;
    margin-bottom: 12px;
  }
  .strength-bars {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 4px;
    height: 4px;
    margin-bottom: 4px;
  }
  .strength-bar {
    background: var(--border-card);
    border-radius: 2px;
    transition: background 0.2s ease;
  }
  .strength-label {
    font-size: 0.75rem;
    color: var(--text-muted);
  }

  /* Alerts */
  .alert-banner {
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 0.8125rem;
    margin-bottom: 18px;
    display: flex;
    align-items: center;
    gap: 10px;
    line-height: 1.4;
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
`;

function renderDocument(title: string, content: string): string {
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
      localStorage.setItem('unierp_theme', next);
      updateThemeIcon(next);
    }
    function updateThemeIcon(t) {
      const el = document.getElementById('theme-icon');
      if (el) el.textContent = t === 'dark' ? '☀️' : '🌙';
    }
    (function() {
      const saved = localStorage.getItem('unierp_theme') || 'light';
      document.documentElement.setAttribute('data-theme', saved);
    })();
  </script>
</head>
<body>
  <div class="auth-top-bar">
    <a href="http://localhost:4000" class="auth-brand-logo">
      <div class="auth-brand-icon">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
          <polyline points="2 17 12 22 22 17"></polyline>
          <polyline points="2 12 12 17 22 12"></polyline>
        </svg>
      </div>
      <span>UniERP</span>
    </a>
    <button type="button" class="theme-toggle-btn" onclick="toggleTheme()" aria-label="Toggle theme">
      <span id="theme-icon">🌙</span> Theme
    </button>
  </div>

  ${content}

  <script>
    // Eye toggle function
    function togglePassword(inputId, btn) {
      const input = document.getElementById(inputId);
      if (!input) return;
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      btn.innerHTML = isPassword
        ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>'
        : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
    }

    // Slider verification script
    (function initSlider() {
      const box = document.getElementById('slider-box');
      const handle = document.getElementById('slider-handle');
      const fill = document.getElementById('slider-fill');
      const input = document.getElementById('slider-verified');
      if (!box || !handle) return;

      let isDragging = false;
      let startX = 0;
      const maxSlide = () => box.clientWidth - handle.clientWidth - 6;

      function onStart(e) {
        isDragging = true;
        startX = (e.touches ? e.touches[0].clientX : e.clientX) - handle.offsetLeft;
      }
      function onMove(e) {
        if (!isDragging) return;
        const clientX = e.touches ? e.touches[0].clientX : e.clientX;
        let left = clientX - startX;
        const max = maxSlide();
        if (left < 3) left = 3;
        if (left > max) left = max;
        handle.style.left = left + 'px';
        fill.style.width = left + 'px';

        if (left >= max - 4) {
          isDragging = false;
          box.classList.add('verified');
          document.getElementById('slider-text').textContent = '✓ Verified Human';
          if (input) input.value = '1';
        }
      }
      function onEnd() {
        if (!isDragging) return;
        isDragging = false;
        handle.style.left = '3px';
        fill.style.width = '0px';
      }

      handle.addEventListener('mousedown', onStart);
      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onEnd);
      handle.addEventListener('touchstart', onStart, { passive: true });
      window.addEventListener('touchmove', onMove, { passive: true });
      window.addEventListener('touchend', onEnd);
    })();
  </script>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────────────────────
// 1. SIGN IN VIEW
// ──────────────────────────────────────────────────────────────────────────

function renderLogin(opts: {
  returnTo: string;
  error?: string;
  success?: string;
  email?: string;
  csrfToken?: string;
}): string {
  const returnToEnc = encodeURIComponent(opts.returnTo);
  const content = `
    <div class="auth-container">
      <!-- Form Panel -->
      <div class="auth-form-panel">
        <div class="auth-header">
          <h1>Sign in to UniERP</h1>
          <p>Enter your work credentials to access your organization.</p>
        </div>

        <div class="auth-switcher">
          <a href="/oidc/login?return_to=${returnToEnc}" class="auth-switcher-tab active">Sign In</a>
          <a href="/oidc/register?return_to=${returnToEnc}" class="auth-switcher-tab">Start Free Trial</a>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}
        ${opts.success ? `<div class="alert-banner alert-success"><span>✓ ${escapeHtml(opts.success)}</span></div>` : ""}

        <!-- Social SSO -->
        <div class="social-grid">
          <a href="/api/v1/auth/oauth/google/start?return_to=${returnToEnc}" class="social-btn" title="Sign in with Google">
            <svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/></svg>
            <span>Google</span>
          </a>
          <a href="/api/v1/auth/oauth/microsoft/start?return_to=${returnToEnc}" class="social-btn" title="Sign in with Microsoft">
            <svg viewBox="0 0 23 23"><path fill="#f35325" d="M1 1h10v10H1z"/><path fill="#81bc06" d="M12 1h10v10H12z"/><path fill="#05a6f0" d="M1 12h10v10H1z"/><path fill="#ffba08" d="M12 12h10v10H12z"/></svg>
            <span>Microsoft</span>
          </a>
          <a href="/api/v1/auth/oauth/github/start?return_to=${returnToEnc}" class="social-btn" title="Sign in with GitHub">
            <svg viewBox="0 0 24 24" fill="currentColor"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>
            <span>GitHub</span>
          </a>
        </div>

        <div class="auth-divider">or sign in with email</div>

        <form method="POST" action="/oidc/login">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo)}"/>
          <input type="text" name="hp_website" class="hp-field" tabindex="-1" autocomplete="off"/>
          <input type="hidden" name="verified_human" id="slider-verified" value="0"/>

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
                onclick="togglePassword('login-password', this)" 
                aria-label="Toggle password visibility"
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

          <!-- Human Verification Slider -->
          <div class="slider-wall-box" id="slider-box">
            <div class="slider-fill" id="slider-fill"></div>
            <div class="slider-track-text" id="slider-text">Slide to verify human »</div>
            <div class="slider-handle" id="slider-handle">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="9 18 15 12 9 6"></polyline>
              </svg>
            </div>
          </div>

          <button type="submit" class="btn-submit">
            <span>Sign In to Workspace</span>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
          </button>
        </form>
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
}): string {
  const returnToEnc = encodeURIComponent(opts.returnTo);
  const v = opts.values || {};
  const content = `
    <div class="auth-container">
      <!-- Form Panel -->
      <div class="auth-form-panel">
        <div class="auth-header">
          <h1>Start your free trial</h1>
          <p>Create your organization workspace in less than a minute.</p>
        </div>

        <div class="auth-switcher">
          <a href="/oidc/login?return_to=${returnToEnc}" class="auth-switcher-tab">Sign In</a>
          <a href="/oidc/register?return_to=${returnToEnc}" class="auth-switcher-tab active">Start Free Trial</a>
        </div>

        ${opts.error ? `<div class="alert-banner alert-error"><span>⚠️ ${escapeHtml(opts.error)}</span></div>` : ""}

        <form method="POST" action="/oidc/register">
          <input type="hidden" name="_csrf" value="${escapeHtml(opts.csrfToken || "")}"/>
          <input type="hidden" name="return_to" value="${escapeHtml(opts.returnTo)}"/>
          <input type="text" name="hp_website" class="hp-field" tabindex="-1" autocomplete="off"/>

          <div class="form-group">
            <label class="form-label" for="reg-org">Organization Name</label>
            <input 
              id="reg-org" 
              type="text" 
              name="organization_name" 
              required 
              placeholder="Acme Global Inc." 
              value="${escapeHtml(v.organization_name || "")}" 
              class="form-input"
            />
          </div>

          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="reg-first">First Name</label>
              <input 
                id="reg-first" 
                type="text" 
                name="first_name" 
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
                required 
                placeholder="Doe" 
                value="${escapeHtml(v.last_name || "")}" 
                class="form-input"
              />
            </div>
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
            />
          </div>

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
                oninput="checkPasswordStrength(this.value)"
              />
              <button 
                type="button" 
                class="input-icon-btn" 
                onclick="togglePassword('reg-password', this)" 
                aria-label="Toggle password visibility"
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

          <div class="form-group" style="margin-bottom: 20px;">
            <label class="checkbox-label" style="font-size: 0.8125rem;">
              <input type="checkbox" name="terms_accepted" required />
              <span>I agree to the <a href="#" class="auth-link">Terms of Service</a> and <a href="#" class="auth-link">Privacy Policy</a>.</span>
            </label>
          </div>

          <button type="submit" class="btn-submit">
            <span>Create Organization Workspace</span>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
          </button>
        </form>
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
                onclick="togglePassword('reset-pass', this)" 
                aria-label="Toggle password visibility"
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
                onclick="togglePassword('reset-confirm', this)" 
                aria-label="Toggle password visibility"
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

