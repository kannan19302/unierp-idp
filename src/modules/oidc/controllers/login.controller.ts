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
import { ApiExcludeController } from "@nestjs/swagger";
import { AuthService } from "../../auth/auth.service";
import { idpPrisma } from "@kannan19302/database";

const AUTH_COOKIE = "auth_token";
const REFRESH_COOKIE = "refresh_token";

/**
 * The hosted login page.
 *
 * Credentials are entered HERE, at the issuer, and nowhere else. That is the
 * point of centralising them: ten platforms plus a mobile and a desktop shell
 * previously each had their own login form, which meant ten places to get
 * password handling, MFA and lockout right — and, in practice, several that got
 * it wrong (a `setTimeout` that navigated to the dashboard; a fallback that
 * minted a superuser token when the API was unreachable). A relying party never
 * sees a password again; it only ever receives an authorization code.
 *
 * The markup is deliberately plain. W13 gives it the design system; what
 * matters now is that the flow is correct.
 */
@ApiExcludeController()
@Controller("oidc")
export class LoginController {
  constructor(private readonly auth: AuthService) {}

  /**
   * Whether this login attempt is for an INTERNAL platform (currently only
   * the Provider Admin OS, P2), determined from the client_id embedded in
   * `return_to` — the original /oidc/authorize request this login resumes.
   *
   * Provider staff and tenant users can share an email only by coincidence
   * (they are different tenants entirely), so which realm to authenticate
   * against cannot be inferred from the email alone; it comes from which
   * platform the sign-in was FOR, established before credentials are ever
   * entered, not chosen by whoever is typing them.
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

  @Get("login")
  @Header("Cache-Control", "no-store")
  loginForm(
    @Query("return_to") returnTo?: string,
    @Query("error") error?: string,
  ): string {
    return renderLogin({ returnTo: safeReturnTo(returnTo), error });
  }

  @Post("login")
  @Header("Cache-Control", "no-store")
  async submitLogin(
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const returnTo = safeReturnTo(body.return_to);

    try {
      const isProviderLogin = await this.isInternalPlatformLogin(returnTo);
      const result = (await (isProviderLogin
        ? this.auth.providerLogin(
            { email: body.email, password: body.password } as never,
            { ipAddress: req.ip, userAgent: req.headers["user-agent"] } as never,
          )
        : this.auth.login(
            {
              email: body.email,
              password: body.password,
              rememberMe: body.remember === "on",
            } as never,
            {
              ipAddress: req.ip,
              userAgent: req.headers["user-agent"],
            } as never,
          ))) as Record<string, unknown>;

      if (result.mfaRequired) {
        res
          .status(200)
          .send(
            renderMfa({
              returnTo,
              challengeToken: String(result.challengeToken ?? ""),
            }),
          );
        return;
      }

      setSessionCookies(res, result);
      res.redirect(returnTo);
    } catch {
      // One message for every failure: unknown email, wrong password, locked
      // account. Distinguishing them turns this form into an account-enumeration
      // oracle, which is how credential-stuffing lists get validated.
      res
        .status(401)
        .send(
          renderLogin({
            returnTo,
            error: "Invalid email or password.",
          }),
        );
    }
  }

  @Post("login/mfa")
  @Header("Cache-Control", "no-store")
  async submitMfa(
    @Body() body: Record<string, string>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const returnTo = safeReturnTo(body.return_to);

    try {
      const result = (await this.auth.verifyMfaLogin(
        { challengeToken: body.challenge_token, code: body.code } as never,
        { ipAddress: req.ip, userAgent: req.headers["user-agent"] } as never,
      )) as Record<string, unknown>;

      setSessionCookies(res, result);
      res.redirect(returnTo);
    } catch {
      res.status(401).send(
        renderMfa({
          returnTo,
          challengeToken: body.challenge_token ?? "",
          error: "That code was not accepted.",
        }),
      );
    }
  }
}

export function setSessionCookies(res: Response, result: Record<string, unknown>) {
  const isProd = process.env.NODE_ENV === "production";

  res.cookie(AUTH_COOKIE, String(result.token), {
    httpOnly: true,
    secure: isProd,
    // Lax, not Strict. The whole point of this cookie is to be present when the
    // browser arrives at /oidc/authorize from another platform's origin; Strict
    // withholds it on exactly that cross-site top-level navigation, so SSO
    // would silently fail and every hop would ask for a password again.
    sameSite: "lax",
    path: "/",
    maxAge: 24 * 60 * 60 * 1000,
  });

  if (result.refreshToken) {
    res.cookie(REFRESH_COOKIE, String(result.refreshToken), {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      // Scoped to the one path that consumes it, so it is not attached to every
      // request to the issuer.
      path: "/api/v1/auth",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });
  }
}

/**
 * Constrains where login may send the browser afterwards.
 *
 * `return_to` arrives in a query string, so it is attacker-controlled. Without
 * this, `/oidc/login?return_to=https://evil.test` is a credible-looking link on
 * the real login page that lands the user somewhere else the moment they
 * authenticate. Only same-origin absolute paths are accepted, and protocol-
 * relative `//host` forms are rejected because browsers treat them as absolute.
 */
export function safeReturnTo(candidate?: string): string {
  const fallback = "/oidc/authorize";
  if (!candidate) return fallback;
  if (!candidate.startsWith("/")) return fallback;
  if (candidate.startsWith("//")) return fallback;
  // Backslashes are normalised to forward slashes by some browsers, so `/\evil`
  // can escape the origin too.
  if (candidate.startsWith("/\\")) return fallback;
  return candidate;
}

/** Minimal HTML escaping for the few values echoed back into the page. */
function esc(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const PAGE_STYLE = `
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
         display: flex; align-items: center; justify-content: center;
         min-height: 100vh; margin: 0; background: #0f172a; color: #e2e8f0; }
  .card { background: #1e293b; padding: 2rem; border-radius: 12px;
          width: min(380px, 92vw); box-shadow: 0 10px 40px rgba(0,0,0,.4); }
  h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
  p.sub { margin: 0 0 1.5rem; color: #94a3b8; font-size: .875rem; }
  label { display: block; font-size: .8125rem; margin: 0 0 .375rem; color: #cbd5e1; }
  input[type=email], input[type=password], input[type=text] {
    width: 100%; padding: .625rem .75rem; margin-bottom: 1rem;
    border: 1px solid #334155; border-radius: 8px; background: #0f172a;
    color: #e2e8f0; font-size: .9375rem; box-sizing: border-box; }
  button { width: 100%; padding: .6875rem; border: 0; border-radius: 8px;
           background: #6366f1; color: #fff; font-size: .9375rem;
           font-weight: 600; cursor: pointer; }
  button:hover { background: #4f46e5; }
  .error { background: #7f1d1d; color: #fecaca; padding: .625rem .75rem;
           border-radius: 8px; font-size: .8125rem; margin-bottom: 1rem; }
  .remember { display: flex; align-items: center; gap: .5rem;
              margin-bottom: 1.25rem; font-size: .8125rem; color: #cbd5e1; }
  .remember input { margin: 0; }
`;

function renderLogin(params: { returnTo: string; error?: string }): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · UniERP</title><style>${PAGE_STYLE}</style></head>
<body><form class="card" method="post" action="/oidc/login">
  <h1>Sign in to UniERP</h1>
  <p class="sub">One account for every UniERP platform.</p>
  ${params.error ? `<div class="error">${esc(params.error)}</div>` : ""}
  <input type="hidden" name="return_to" value="${esc(params.returnTo)}">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" autocomplete="username" required autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <div class="remember">
    <input id="remember" name="remember" type="checkbox">
    <label for="remember" style="margin:0">Keep me signed in</label>
  </div>
  <button type="submit">Sign in</button>
</form></body></html>`;
}

function renderMfa(params: {
  returnTo: string;
  challengeToken: string;
  error?: string;
}): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verification · UniERP</title><style>${PAGE_STYLE}</style></head>
<body><form class="card" method="post" action="/oidc/login/mfa">
  <h1>Two-factor verification</h1>
  <p class="sub">Enter the six-digit code from your authenticator app.</p>
  ${params.error ? `<div class="error">${esc(params.error)}</div>` : ""}
  <input type="hidden" name="return_to" value="${esc(params.returnTo)}">
  <input type="hidden" name="challenge_token" value="${esc(params.challengeToken)}">
  <label for="code">Authentication code</label>
  <input id="code" name="code" type="text" inputmode="numeric"
         autocomplete="one-time-code" pattern="[0-9]*" required autofocus>
  <button type="submit">Verify</button>
</form></body></html>`;
}
