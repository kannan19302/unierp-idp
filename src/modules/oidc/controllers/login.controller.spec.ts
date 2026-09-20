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
        tenantSlug: "another-organization",
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

  describe("IAM-003 through IAM-016 and REG-002 through REG-004 portal endpoints", () => {
    const oauth = {
      listProviders: vi.fn().mockResolvedValue({ providers: [] }),
    } as unknown as OAuthService;
    const controller = new LoginController({} as AuthService, oauth);

    it("renders IAM-003 Single Sign-On (SSO) discovery", async () => {
      const html = await controller.ssoDiscoveryForm(requestStub(), responseStub(), "/");
      expect(html).toContain("Single Sign-On (SSO)");
      expect(html).toContain("Corporate Work Email");
      expect(html).toContain("SAML 2.0 / OIDC FedRAMP High");
    });

    it("renders IAM-005 Workspace Switcher with tenant options", async () => {
      const html = await controller.workspaceSwitcherForm(
        { ...requestStub(), user: { userId: "u1", tenantId: "t1" } } as never,
        responseStub(),
        "/",
      );
      expect(html).toContain("Select a workspace");
      expect(html).toContain("Acme Global Corporation");
      expect(html).toContain("Starlight Health Systems");
    });

    it("renders IAM-006 Session Lockout Console with compliance policy", async () => {
      const html = await controller.sessionLockoutForm(requestStub(), responseStub(), "/");
      expect(html).toContain("Session locked");
      expect(html).toContain("SOC2 / FINRA Rule 4370");
      expect(html).toContain("Emergency SecOps break-glass console");
    });

    it("renders IAM-007 MFA Setup with QR code and TOTP secret", async () => {
      const html = await controller.mfaSetupForm(requestStub(), responseStub(), "/");
      expect(html).toContain("Set up 2-Factor Auth");
      expect(html).toContain("Scan this QR code");
      expect(html).toContain("Enter 6-digit confirmation code");
    });

    it("renders IAM-008 Passkey Enrollment with WebAuthn hooks", async () => {
      const html = await controller.passkeyEnrollForm(requestStub(), responseStub(), "/");
      expect(html).toContain("Enroll a Passkey");
      expect(html).toContain("FIDO2 / WebAuthn Certified");
      expect(html).toContain("Create & Register Passkey");
    });

    it("renders IAM-009 Recovery Backup Codes", async () => {
      const html = await controller.recoveryCodesForm(requestStub(), responseStub(), "/");
      expect(html).toContain("Recovery backup codes");
      expect(html).toContain("Emergency Access");
      expect(html).toContain("7F2A-99B1");
    });

    it("renders IAM-010 Forced Password Change", async () => {
      const html = await controller.forcedPasswordChangeForm(requestStub(), responseStub(), "/");
      expect(html).toContain("Password change required");
      expect(html).toContain("Current Password");
      expect(html).toContain("New Sovereign Password");
    });

    it("renders IAM-011 Magic Link Sent Notice", async () => {
      const html = await controller.magicLinkForm(requestStub(), responseStub(), "alex@company.com");
      expect(html).toContain("Magic link sent");
      expect(html).toContain("alex@company.com");
      expect(html).toContain("Passwordless Dispatch");
    });

    it("renders IAM-012 Suspicious Login Challenge with numerical matching", async () => {
      const html = await controller.suspiciousLoginChallengeForm(requestStub(), responseStub(), "/");
      expect(html).toContain("Verify this login");
      expect(html).toContain("Risk Engine Challenge");
      expect(html).toContain("42");
    });

    it("renders IAM-013 Enterprise Invitation Accept", async () => {
      const html = await controller.invitationForm(requestStub(), responseStub(), "/", "alex@company.com", "Acme Global");
      expect(html).toContain("Join Acme Global");
      expect(html).toContain("Enterprise Invitation");
      expect(html).toContain("Create Work Password");
    });

    it("renders IAM-014 OAuth 2.0 / OIDC Consent Dialog", async () => {
      const html = await controller.consentForm(requestStub(), responseStub(), "Enterprise Analytics Sync", "/");
      expect(html).toContain("Authorize Enterprise Analytics Sync");
      expect(html).toContain("Application Authorization");
      expect(html).toContain("Read purchase orders");
    });

    it("renders IAM-015 Device Code CLI Authorization", async () => {
      const html = await controller.deviceCodeForm(requestStub(), responseStub(), "WBX9-4K72");
      expect(html).toContain("Authorize Device");
      expect(html).toContain("Terminal & CLI Access");
      expect(html).toContain("WBX9-4K72");
    });

    it("renders IAM-016 Account Suspended Threat Notice", async () => {
      const html = await controller.suspendedNotice(requestStub(), responseStub());
      expect(html).toContain("Account suspended");
      expect(html).toContain("SecOps Security Lockout");
      expect(html).toContain("SEC-2026-9481");
    });

    it("renders REG-002 Identity & OTP Verification", async () => {
      const html = await controller.registerVerifyOtpForm(requestStub(), responseStub(), "alex@company.com", "/");
      expect(html).toContain("Verify your identity");
      expect(html).toContain("Step 2 of 4 — Identity Verification");
      expect(html).toContain("alex@company.com");
    });

    it("renders REG-003 Sovereign Provisioning Engine view & API telemetry", async () => {
      const html = await controller.registerProvisioningForm(requestStub(), responseStub(), "acme");
      expect(html).toContain("Provisioning sovereign partition");
      expect(html).toContain("Step 3 of 4 — Sovereign Cloud Provisioning");
      expect(html).toContain("acme.unierp.cloud");

      const telemetry = await controller.registerProvisioningStatus();
      expect(telemetry.progress).toBe(100);
      expect(telemetry.status).toBe("COMPLETED");
    });

    it("renders REG-004 Domain Collision & SSO Redirection", async () => {
      const html = await controller.registerCollisionForm(
        requestStub(),
        responseStub(),
        "enterprise.com",
        "Acme Global Technologies",
        "Okta SSO",
      );
      expect(html).toContain("Organization already registered");
      expect(html).toContain("Enterprise Domain Policy");
      expect(html).toContain("Sign In via Okta SSO");
    });
  });
});
