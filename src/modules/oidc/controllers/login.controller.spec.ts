import { describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    oAuthClient: { findUnique: vi.fn().mockResolvedValue(null) },
    platform: { findUnique: vi.fn().mockResolvedValue(null) },
    user: { findUnique: vi.fn().mockResolvedValue({
      firstName: "Workspace",
      lastName: "Owner",
      email: "owner@example.com",
      avatar: null,
      preferences: {},
      mfaEnabled: false,
      emailVerifiedAt: new Date(),
    }) },
    userSession: { findMany: vi.fn().mockResolvedValue([]) },
    passkey: { findMany: vi.fn().mockResolvedValue([]) },
    accountContact: { findMany: vi.fn().mockResolvedValue([{
      id: "primary-contact",
      value: "owner@example.com",
      label: "Primary email",
      isPrimary: true,
      verifiedAt: new Date(),
      createdAt: new Date(),
    }]) },
  },
  runWithTenantSession: vi.fn((_session: unknown, operation: () => unknown) => operation()),
}));
vi.mock("../../../common/guards/jwt-auth.guard", () => ({
  JwtAuthGuard: class JwtAuthGuard {},
}));

import { idpPrisma } from "@kannan19302/database";
import { LoginController } from "./login.controller";
import type { AuthService } from "../../auth/auth.service";
import type { OAuthService } from "../../auth/oauth.service";

function responseStub(): Response {
  return { cookie: vi.fn() } as unknown as Response;
}

function requestStub(): Request {
  return {
    headers: {},
    cookies: {},
  } as unknown as Request;
}

describe("hosted identity provider buttons", () => {
  it("renders only the ready Google, Microsoft and GitHub login choices", async () => {
    const oauth = {
      listProviders: vi.fn().mockResolvedValue({
        providers: ["google", "microsoft", "github"],
      }),
    } as unknown as OAuthService;
    const controller = new LoginController({} as AuthService, oauth);

    const html = await controller.loginForm(
      requestStub(),
      responseStub(),
      "/oidc/authorize?client_id=hub",
    );

    expect(html).toContain("Continue with Google");
    expect(html).toContain("Continue with Microsoft");
    expect(html).toContain("Continue with GitHub");
    expect(html).not.toContain("Continue with Apple");
    expect(html).not.toContain("Continue with LinkedIn");
    expect(html).not.toContain("Continue with Amazon");
    expect(html.match(/href="\/api\/v1\/auth\/oauth\//g)).toHaveLength(3);
    expect(html).not.toContain("auth-switcher-tab");
    expect(html).not.toContain("Slide to verify human");
    expect(html).not.toContain("initSlider");
    expect(html).toContain("Create a free-trial workspace");
    expect(html).toContain("Sign in with a passkey");
    expect(html).toContain("Secure identity");
    expect(html).toContain("auth-container--login");
    expect(html).not.toContain("Sign-in scope");
    expect(html).not.toContain('name="login_scope"');
    expect(html).not.toContain("Organization slug");
    expect(html).not.toContain('name="tenant_slug"');
    expect(html).toContain('<a class="skip-link" href="#main-content">');
    expect(html).toContain('<main id="main-content">');
    expect(html).not.toMatch(/\son(?:click|change|input)=/i);
    expect(html).toContain("replace(/\\+/g, '-').replace(/\\//g, '_')");
  });

  it("does not render an unconfigured provider", async () => {
    const oauth = {
      listProviders: vi.fn().mockResolvedValue({ providers: ["google"] }),
    } as unknown as OAuthService;
    const controller = new LoginController({} as AuthService, oauth);

    const html = await controller.loginForm(
      requestStub(),
      responseStub(),
      "/",
    );

    expect(html).toContain("Continue with Google");
    expect(html).not.toContain("Continue with Microsoft");
    expect(html).not.toContain("Continue with GitHub");
  });

  it("derives provider scope from the internal relying party", async () => {
    const auth = {
      providerLogin: vi.fn().mockResolvedValue({ token: "access", refreshToken: "refresh" }),
      login: vi.fn(),
    } as unknown as AuthService;
    const oauth = {
      listProviders: vi.fn().mockResolvedValue({ providers: [] }),
    } as unknown as OAuthService;
    const controller = new LoginController(auth, oauth);
    vi.mocked(idpPrisma.oAuthClient.findUnique).mockResolvedValueOnce({
      platformCode: "P2",
    } as never);
    vi.mocked(idpPrisma.platform.findUnique).mockResolvedValueOnce({
      audience: "INTERNAL",
    } as never);
    const csrf = "a".repeat(32);
    const res = {
      cookie: vi.fn(),
      redirect: vi.fn(),
      status: vi.fn().mockReturnThis(),
      send: vi.fn(),
    } as unknown as Response;

    await controller.submitLogin(
      {
        _csrf: csrf,
        return_to: "/oidc/authorize?client_id=provider-admin",
        email: "operator@example.test",
        password: "secret",
        login_scope: "tenant",
      },
      {
        ...requestStub(),
        headers: { cookie: `oidc_csrf=${csrf}` },
        cookies: { oidc_csrf: csrf },
        socket: { remoteAddress: "127.0.0.1" },
      } as Request,
      res,
    );

    expect(auth.providerLogin).toHaveBeenCalledOnce();
    expect(auth.login).not.toHaveBeenCalled();
    expect(res.redirect).toHaveBeenCalledWith(
      302,
      "/oidc/authorize?client_id=provider-admin",
    );
  });

  it("ignores hostile scope and organization fields for tenant sign-in", async () => {
    const auth = {
      providerLogin: vi.fn(),
      login: vi.fn().mockResolvedValue({ token: "access", refreshToken: "refresh" }),
    } as unknown as AuthService;
    const oauth = {
      listProviders: vi.fn().mockResolvedValue({ providers: [] }),
    } as unknown as OAuthService;
    const controller = new LoginController(auth, oauth);
    const csrf = "b".repeat(32);
    const res = {
      cookie: vi.fn(),
      redirect: vi.fn(),
      status: vi.fn().mockReturnThis(),
      send: vi.fn(),
    } as unknown as Response;

    await controller.submitLogin(
      {
        _csrf: csrf,
        return_to: "/",
        email: "owner@example.com",
        password: "secret",
        login_scope: "provider",
        tenant_slug: "another-organization",
      },
      {
        ...requestStub(),
        headers: { cookie: `oidc_csrf=${csrf}` },
        cookies: { oidc_csrf: csrf },
        socket: { remoteAddress: "127.0.0.1" },
      } as Request,
      res,
    );

    expect(auth.providerLogin).not.toHaveBeenCalled();
    expect(auth.login).toHaveBeenCalledWith(
      {
        email: "owner@example.com",
        password: "secret",
        rememberMe: false,
      },
      expect.any(Object),
    );
    expect(res.redirect).toHaveBeenCalledWith(302, "/");
  });

  it("resumes social registration without asking for a UniERP password", async () => {
    const oauth = {
      listProviders: vi.fn().mockResolvedValue({
        providers: ["google", "microsoft", "github"],
      }),
      getRegistrationProfile: vi.fn().mockResolvedValue({
        provider: "google",
        subject: "subject",
        email: "verified@example.com",
        emailVerified: true,
        firstName: "Verified",
        lastName: "Owner",
        returnTo: "/",
      }),
    } as unknown as OAuthService;
    const controller = new LoginController({} as AuthService, oauth);

    const html = await controller.registerForm(
      requestStub(),
      responseStub(),
      "/",
      undefined,
      "registration-ticket",
    );

    expect(html).toContain("Google account verified");
    expect(html).toContain("auth-container--register");
    expect(html).toContain("Create your UniERP workspace");
    expect(html).toContain('value="verified@example.com"');
    expect(html).toContain('name="external_auth"');
    expect(html).not.toContain('name="password"');
  });

  it("renders server-versioned legal documents instead of placeholder links", async () => {
    const oauth = {
      listProviders: vi.fn().mockResolvedValue({ providers: [] }),
    } as unknown as OAuthService;
    const controller = new LoginController({} as AuthService, oauth);

    const html = await controller.registerForm(
      requestStub(),
      responseStub(),
      "/",
    );

    expect(html).toContain('href="http://localhost:4001/terms"');
    expect(html).toContain('href="http://localhost:4001/privacy"');
    expect(html).toContain("Terms 2026-07-development");
    expect(html).toContain("Privacy 2026-07-development");
    expect(html).not.toContain('href="#"');
  });

  it("renders connected-account controls in the central Account Center", async () => {
    const oauth = {
      listProviders: vi.fn().mockResolvedValue({
        providers: ["google", "microsoft", "github"],
      }),
      getConnectedProviders: vi.fn().mockResolvedValue(["google"]),
    } as unknown as OAuthService;
    const controller = new LoginController({} as AuthService, oauth);

    const html = await controller.accountCenter(
      {
        ...requestStub(),
        user: {
          userId: "user-1",
          tenantId: "tenant-1",
          sid: "session-1",
          email: "owner@example.com",
        },
      } as Request & { user: any },
      responseStub(),
    );

    expect(html).toContain("Account Center");
    expect(html).toContain("owner@example.com");
    expect(html).toContain("Disconnect");
    expect(html).toContain("Connect");
    expect(html).toContain("Sessions & devices");
    expect(html).toContain("Passkeys");
    expect(html).toContain("Add passkey");
    expect(html).toContain("Contact methods");
    expect(html).toContain("Add recovery email");
    expect(html).toContain("Appearance & accessibility");
    expect(html).toContain("Privacy & data");
    expect(html).toContain("Plans & billing");
    expect(html).toContain('href="http://localhost:4000"');
    expect(html).toContain('href="http://localhost:4003/auth/security"');
    expect(html).toContain(
      'href="http://localhost:4003/notifications/preferences"',
    );
    expect(html).toContain('href="http://localhost:4003/privacy"');
    expect(html).toContain('href="http://localhost:4003/saas/portal"');
    expect(html).toContain(
      'href="http://localhost:4003/communication/helpdesk"',
    );
  });
});
