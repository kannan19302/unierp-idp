import { beforeEach, describe, expect, it, vi } from "vitest";

const emitAuthAudit = vi.hoisted(() => vi.fn());

vi.mock("jose", () => ({ createRemoteJWKSet: vi.fn(() => vi.fn()), jwtVerify: vi.fn() }));
vi.mock("@kannan19302/database", () => ({ idpPrisma: {}, runWithTenantSession: vi.fn() }));
vi.mock("../../../common/audit/emit-auth-audit", () => ({ emitAuthAudit }));

import { ConsentController } from "./session.controller";

describe("ConsentController", () => {
  beforeEach(() => vi.resetAllMocks());

  it("records consent only for the verified request principal", async () => {
    const clients = { recordConsent: vi.fn().mockResolvedValue(undefined) } as any;
    const controller = new ConsentController(clients);
    const res = { redirect: vi.fn() } as any;

    await controller.submitConsent(
      { client_id: "client-a", scope: "openid profile", decision: "allow", return_to: "/done" },
      { user: { userId: "user-a", tenantId: "tenant-a" } } as any,
      res,
    );

    expect(clients.recordConsent).toHaveBeenCalledWith({
      clientId: "client-a",
      userId: "user-a",
      tenantId: "tenant-a",
      scopes: ["openid", "profile"],
    });
    expect(emitAuthAudit).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant-a", userId: "user-a" }));
  });

  it("does not honor a cookie-shaped request with no verified principal", async () => {
    const clients = { recordConsent: vi.fn() } as any;
    const controller = new ConsentController(clients);
    const res = { redirect: vi.fn() } as any;

    await controller.submitConsent(
      { client_id: "client-a", scope: "openid", decision: "allow", return_to: "/done" },
      { cookies: { auth_token: "forged" } } as any,
      res,
    );

    expect(clients.recordConsent).not.toHaveBeenCalled();
    expect(emitAuthAudit).not.toHaveBeenCalled();
    expect(res.redirect).toHaveBeenCalledWith("/oidc/login?return_to=%2Fdone");
  });
});
