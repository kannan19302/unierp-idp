import type { NextFunction, Request, Response } from "express";
import { describe, expect, it, vi } from "vitest";
import { csrfMiddleware } from "./csrf.middleware";

function invoke(options: {
  method: string;
  path: string;
  cookieToken?: string;
  headerToken?: string;
  authorization?: string;
}) {
  const next = vi.fn<NextFunction>();
  const cookie = vi.fn();
  const json = vi.fn();
  const status = vi.fn(() => ({ json }));
  const req = {
    method: options.method,
    path: options.path,
    url: options.path,
    cookies: options.cookieToken
      ? { csrf_token: options.cookieToken }
      : {},
    headers: {
      ...(options.headerToken ? { "x-csrf-token": options.headerToken } : {}),
      ...(options.authorization ? { authorization: options.authorization } : {}),
    },
  } as unknown as Request;
  const res = { cookie, status } as unknown as Response;

  csrfMiddleware(req, res, next);
  return { next, cookie, json, status };
}

describe("csrfMiddleware", () => {
  it("allows safe methods and issues the API CSRF cookie", () => {
    const result = invoke({ method: "GET", path: "/api/v1/auth/me" });

    expect(result.cookie).toHaveBeenCalledOnce();
    expect(result.next).toHaveBeenCalledOnce();
  });

  it("rejects ordinary state-changing API requests without the header token", () => {
    const result = invoke({
      method: "POST",
      path: "/api/v1/auth/logout",
      cookieToken: "cookie-token",
    });

    expect(result.next).not.toHaveBeenCalled();
    expect(result.status).toHaveBeenCalledWith(403);
    expect(result.json).toHaveBeenCalledWith({
      message: "Invalid or missing CSRF token",
    });
  });

  it("allows ordinary API requests with matching cookie and header tokens", () => {
    const result = invoke({
      method: "POST",
      path: "/api/v1/auth/logout",
      cookieToken: "same-token",
      headerToken: "same-token",
    });

    expect(result.next).toHaveBeenCalledOnce();
  });

  it("delegates explicit Bearer-token writes to the authentication guard", () => {
    const result = invoke({
      method: "PATCH",
      path: "/api/v1/auth/me",
      authorization: "Bearer access-token",
    });

    expect(result.next).toHaveBeenCalledOnce();
    expect(result.status).not.toHaveBeenCalled();
  });

  it.each(["Bearer", "Basic credentials", "Bearer   "])(
    "does not exempt malformed or non-Bearer authorization: %s",
    (authorization) => {
      const result = invoke({
        method: "PATCH",
        path: "/api/v1/auth/me",
        authorization,
        cookieToken: "cookie-token",
      });

      expect(result.next).not.toHaveBeenCalled();
      expect(result.status).toHaveBeenCalledWith(403);
    },
  );

  it.each([
    "/oidc/account/unlink",
    "/oidc/login",
    "/oidc/login/mfa",
    "/oidc/register",
    "/oidc/forgot-password",
    "/oidc/reset-password",
    "/oidc/verify-email/resend",
    "/oidc/passkeys/registration/options",
    "/oidc/passkeys/registration/verify",
    "/oidc/passkeys/authentication/options",
    "/oidc/passkeys/authentication/verify",
    "/oidc/passkeys/delete",
    "/oidc/account/governance/organization/switch",
    "/oidc/account/governance/organization/leave",
    "/oidc/account/governance/privacy/export",
    "/oidc/account/governance/privacy/deletion/request",
    "/oidc/account/governance/privacy/deletion/cancel",
    "/oidc/account/contact/add",
    "/oidc/account/contact/resend",
    "/oidc/account/contact/remove",
  ])("delegates %s to its controller synchronizer-token check", (path) => {
    const result = invoke({ method: "POST", path });

    expect(result.next).toHaveBeenCalledOnce();
    expect(result.status).not.toHaveBeenCalled();
  });

  it("does not exempt paths that merely share a hosted-form prefix", () => {
    const result = invoke({
      method: "POST",
      path: "/oidc/register/unreviewed-route",
      cookieToken: "cookie-token",
    });

    expect(result.next).not.toHaveBeenCalled();
    expect(result.status).toHaveBeenCalledWith(403);
  });
});
