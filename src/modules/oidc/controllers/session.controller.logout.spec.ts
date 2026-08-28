import { beforeEach, describe, expect, it, vi } from "vitest";

const verifyBearerToken = vi.hoisted(() => vi.fn());
const updateMany = vi.hoisted(() => vi.fn());
const runWithTenantSession = vi.hoisted(() => vi.fn());

vi.mock("jose", () => ({ createRemoteJWKSet: vi.fn(() => vi.fn()), jwtVerify: vi.fn() }));
vi.mock("../../../common/guards/verify-bearer-token", () => ({ verifyBearerToken }));
vi.mock("@kannan19302/database", () => ({
  idpPrisma: { userSession: { updateMany } },
  runWithTenantSession,
}));

import { SessionController } from "./session.controller";

describe("SessionController RP-initiated logout", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    runWithTenantSession.mockImplementation(async (_context, operation) => operation());
  });

  it("does not revoke a server-side session from forged cookie claims", async () => {
    verifyBearerToken.mockResolvedValue(null);
    const authorization = { revokeGrantsForSession: vi.fn() } as any;
    const controller = new SessionController({} as any, {} as any, authorization);
    const response = { clearCookie: vi.fn(), redirect: vi.fn() } as any;

    await controller.endSession(
      undefined,
      undefined,
      { cookies: { auth_token: "forged.cookie.value" } } as any,
      response,
    );

    expect(verifyBearerToken).toHaveBeenCalledWith("forged.cookie.value");
    expect(runWithTenantSession).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
    expect(authorization.revokeGrantsForSession).not.toHaveBeenCalled();
    expect(response.clearCookie).toHaveBeenCalledTimes(2);
    expect(response.redirect).toHaveBeenCalledWith("/oidc/login");
  });

  it("revokes only the verified session in its verified tenant context", async () => {
    verifyBearerToken.mockResolvedValue({ sid: "session-a", tenantId: "tenant-a", userId: "user-a" });
    updateMany.mockResolvedValue({ count: 1 });
    const authorization = { revokeGrantsForSession: vi.fn().mockResolvedValue(undefined) } as any;
    const controller = new SessionController({} as any, {} as any, authorization);
    const response = { clearCookie: vi.fn(), redirect: vi.fn() } as any;

    await controller.endSession(
      undefined,
      undefined,
      { cookies: { auth_token: "verified.session.token" } } as any,
      response,
    );

    expect(runWithTenantSession).toHaveBeenCalledWith(
      { tenantId: "tenant-a", userId: "user-a" },
      expect.any(Function),
    );
    expect(updateMany).toHaveBeenCalledWith({ where: { id: "session-a" }, data: { isActive: false } });
    expect(authorization.revokeGrantsForSession).toHaveBeenCalledWith("session-a");
  });
});
