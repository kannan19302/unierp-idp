import "reflect-metadata";
import { GUARDS_METADATA } from "@nestjs/common/constants";
import { describe, expect, it, vi } from "vitest";

vi.mock("../auth.service", () => ({ AuthService: class AuthService {} }));
vi.mock("../../../common/guards/jwt-auth.guard", () => ({
  JwtAuthGuard: class JwtAuthGuard {},
}));
vi.mock("../../../common/guards/rbac.guard", () => ({
  RbacGuard: class RbacGuard {},
}));
import { PERMISSIONS_KEY } from "../../../common/decorators/permissions.decorator";
import { JwtAuthGuard } from "../../../common/guards/jwt-auth.guard";
import { RbacGuard } from "../../../common/guards/rbac.guard";
import { AuthController } from "../auth.controller";

describe("AuthController self-profile authorization", () => {
  it.each(["getProfile", "updateProfile"] as const)(
    "%s derives self-service authority from the authenticated subject",
    (methodName) => {
      const handler = AuthController.prototype[methodName];
      const guards = Reflect.getMetadata(GUARDS_METADATA, handler) as unknown[];

      expect(guards).toContain(JwtAuthGuard);
      expect(guards).not.toContain(RbacGuard);
      expect(Reflect.getMetadata(PERMISSIONS_KEY, handler)).toBeUndefined();
    },
  );
});
