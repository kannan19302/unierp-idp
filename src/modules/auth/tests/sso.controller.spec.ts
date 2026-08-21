import { describe, it, expect, vi } from "vitest";
import { UnauthorizedException } from "@nestjs/common";
import { SsoController } from "../sso.controller";

// Regression cover for the unsigned-assertion bypass, updated for W12's real
// federation: the callbacks are no longer disabled outright, but they must
// still be unreachable by an unauthenticated caller who only knows a tenant
// slug and a colleague's email — that guarantee now comes from
// SsoService.handleSamlCallback/handleOidcCallback actually verifying a
// signature/exchanging a code (@node-saml/node-saml, and a direct
// server-to-server token-endpoint call) before any session is issued, rather
// than the controller refusing every request outright.
//
// These tests exercise the controller's plumbing (it calls the service and
// forwards the result) with a fake service standing in for that
// verification — SsoService's own real verification logic is covered by
// sso.service.spec.ts.

describe("SsoController — federation requires the service to verify first", () => {
  it("propagates a rejected SAML assertion rather than minting a session", async () => {
    const service = {
      handleSamlCallback: vi.fn(async () => {
        throw new UnauthorizedException(
          "Your identity provider's response could not be verified.",
        );
      }),
      getSsoConfigByTenantSlug: vi.fn(),
    };
    const controller = new SsoController(service as never);

    await expect(
      controller.samlCallback("acme", { SAMLResponse: "forged" }, { headers: {} } as never, {
        redirect: vi.fn(),
      } as never),
    ).rejects.toThrow(UnauthorizedException);
  });

  it("propagates a rejected OIDC state/code rather than minting a session", async () => {
    const service = {
      handleOidcCallback: vi.fn(async () => {
        throw new UnauthorizedException("Invalid or expired sign-in state.");
      }),
      getSsoConfigByTenantSlug: vi.fn(),
    };
    const controller = new SsoController(service as never);

    await expect(
      controller.oidcCallback("acme", "code", "bad-state", { headers: {} } as never, {
        redirect: vi.fn(),
      } as never),
    ).rejects.toThrow(UnauthorizedException);
  });

  it("sets session cookies and redirects only once the service confirms a verified session", async () => {
    const redirect = vi.fn();
    const res = { cookie: vi.fn(), redirect } as never;
    const service = {
      handleSamlCallback: vi.fn(async () => ({
        session: { token: "t", user: {}, tenant: {} },
        returnTo: "/apps",
      })),
      getSsoConfigByTenantSlug: vi.fn(),
    };
    const controller = new SsoController(service as never);

    await controller.samlCallback("acme", { SAMLResponse: "valid" }, { headers: {} } as never, res);

    expect(service.handleSamlCallback).toHaveBeenCalled();
    expect(redirect).toHaveBeenCalledWith("/apps");
  });

  it("advertises a configured tenant's SSO entry points without exposing secrets", async () => {
    const service = {
      getSsoConfigByTenantSlug: vi.fn(async (slug: string) =>
        slug === "acme"
          ? {
              configured: true,
              samlEntryPoint: "https://idp.acme.test/sso",
              oidcAuthorizationUrl: null,
              oidcClientId: null,
            }
          : { configured: false },
      ),
    };
    const controller = new SsoController(service as never);

    await expect(controller.getSsoConfig("acme")).resolves.toMatchObject({
      configured: true,
      samlEntryPoint: "https://idp.acme.test/sso",
    });
    await expect(controller.getSsoConfig("nope")).resolves.toEqual({
      configured: false,
    });
  });
});
