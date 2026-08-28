import { describe, expect, it, vi } from "vitest";
import { UnauthorizedException } from "@nestjs/common";

const { jwtVerify, verifyTypedToken } = vi.hoisted(() => ({ jwtVerify: vi.fn(), verifyTypedToken: vi.fn() }));
vi.mock("jose", () => ({
  createRemoteJWKSet: vi.fn(() => vi.fn()),
  jwtVerify,
}));
vi.mock("@kannan19302/auth", () => ({
  verifyTypedToken,
  TOKEN_TYPE: { SESSION: "SESSION" },
}));

import { PlatformsController } from "./platforms.controller";
import type { PlatformEntitlementService } from "../services/platform-entitlement.service";

describe("PlatformsController", () => {
  it("requires a bearer token", async () => {
    const controller = new PlatformsController({} as PlatformEntitlementService);
    await expect(controller.listPlatforms()).rejects.toThrow(UnauthorizedException);
  });

  it("passes subject and assurance context into the shared policy decision", async () => {
    jwtVerify.mockResolvedValue({
      payload: {
        sub: "user-1",
        tenantId: "tenant-1",
        realm: "provider",
        roles: ["platform.admin"],
        permissions: ["system.tenant.read"],
        acr: "aal2",
      },
    });
    const entitlement = {
      listEntitledPlatforms: vi.fn().mockResolvedValue([{ code: "P2" }]),
    } as unknown as PlatformEntitlementService;
    const controller = new PlatformsController(entitlement);

    const result = await controller.listPlatforms("Bearer token", "request-1");

    expect(entitlement.listEntitledPlatforms).toHaveBeenCalledWith({
      userId: "user-1",
      tenantId: "tenant-1",
      realm: "provider",
      roles: ["platform.admin"],
      permissions: ["system.tenant.read"],
      assurance: "aal2",
    });
    expect(result).toMatchObject({
      policyVersion: "platform-policy/2026-08-24",
      requestId: "request-1",
      platforms: [{ code: "P2" }],
    });
  });

  it("never evaluates entitlement from an unverified JWT payload", async () => {
    jwtVerify.mockRejectedValueOnce(new Error("signature invalid"));
    verifyTypedToken.mockReturnValueOnce(null);
    const entitlement = {
      listEntitledPlatforms: vi.fn(),
    } as unknown as PlatformEntitlementService;
    const controller = new PlatformsController(entitlement);

    await expect(controller.listPlatforms("Bearer forged.token.value")).rejects.toThrow("Invalid access token");
    expect(entitlement.listEntitledPlatforms).not.toHaveBeenCalled();
  });
});
