import { describe, it, expect, vi, beforeEach } from "vitest";
import { ExecutionContext, ForbiddenException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { RbacGuard } from "../rbac.guard";

// Mock database package — proves RbacGuard's *actual* enforcement logic,
// not just decorator presence (the exact gap the enterprise hardening plan
// flagged: "RBAC that is actually enforced, not decorator-presence").
vi.mock("@unerp/database", () => {
  // Identity models (user, role, userSession, ...) are read through
  // `idpPrisma`, not `prisma` — this spec predates that split and stubs
  // them under `prisma`. Exporting the same stub object under both names
  // keeps every `vi.mocked(prisma.user.*)` setup pointing at exactly the
  // function the service calls.
  const mocked = {
    prisma: {
      userRole: {
        findMany: vi.fn(),
      },
    },
    runWithTenantSession: vi.fn((_session: unknown, fn: () => unknown) => fn()),
  };
  return { ...mocked, idpPrisma: mocked.prisma };
});

import { idpPrisma, prisma } from "@unerp/database";

function buildContext(user: unknown): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ user }),
    }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as unknown as ExecutionContext;
}

function buildReflector(requiredPermissions: string[] | undefined): Reflector {
  return {
    getAllAndOverride: vi.fn().mockReturnValue(requiredPermissions),
  } as unknown as Reflector;
}

function roleWithPermissions(permissions: string[]) {
  return { role: { permissions: JSON.stringify(permissions) } };
}

describe("RbacGuard — permission matrix (deny-by-default enforcement)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("allows the request through when the handler requires no permissions", async () => {
    const guard = new RbacGuard(buildReflector(undefined));
    const result = await guard.canActivate(buildContext({ userId: "u1" }));
    expect(result).toBe(true);
    expect(idpPrisma.userRole.findMany).not.toHaveBeenCalled();
  });

  it("throws if there is no authenticated user on the request", async () => {
    const guard = new RbacGuard(buildReflector(["finance.invoice.read"]));
    await expect(guard.canActivate(buildContext(undefined))).rejects.toThrow(
      ForbiddenException,
    );
  });

  it("denies by default when the user has no roles at all", async () => {
    (idpPrisma.userRole.findMany as ReturnType<typeof vi.fn>).mockResolvedValue(
      [],
    );
    const guard = new RbacGuard(buildReflector(["finance.invoice.read"]));
    await expect(
      guard.canActivate(buildContext({ userId: "u1" })),
    ).rejects.toThrow(ForbiddenException);
  });

  it("denies when the user has roles but none grant the required permission", async () => {
    (idpPrisma.userRole.findMany as ReturnType<typeof vi.fn>).mockResolvedValue(
      [roleWithPermissions(["hr.employee.read"])],
    );
    const guard = new RbacGuard(buildReflector(["finance.invoice.create"]));
    await expect(
      guard.canActivate(buildContext({ userId: "u1" })),
    ).rejects.toThrow(ForbiddenException);
  });

  it("allows when a role grants the exact required permission", async () => {
    (idpPrisma.userRole.findMany as ReturnType<typeof vi.fn>).mockResolvedValue(
      [roleWithPermissions(["finance.invoice.create"])],
    );
    const guard = new RbacGuard(buildReflector(["finance.invoice.create"]));
    await expect(
      guard.canActivate(buildContext({ userId: "u1" })),
    ).resolves.toBe(true);
  });

  it("allows via a module wildcard role", async () => {
    (idpPrisma.userRole.findMany as ReturnType<typeof vi.fn>).mockResolvedValue(
      [roleWithPermissions(["finance.*"])],
    );
    const guard = new RbacGuard(buildReflector(["finance.invoice.void"]));
    await expect(
      guard.canActivate(buildContext({ userId: "u1" })),
    ).resolves.toBe(true);
  });

  it("requires ALL listed permissions when a handler declares more than one", async () => {
    (idpPrisma.userRole.findMany as ReturnType<typeof vi.fn>).mockResolvedValue(
      [roleWithPermissions(["finance.invoice.read"])],
    );
    const guard = new RbacGuard(
      buildReflector(["finance.invoice.read", "finance.invoice.create"]),
    );
    await expect(
      guard.canActivate(buildContext({ userId: "u1" })),
    ).rejects.toThrow(ForbiddenException);
  });

  it("aggregates permissions across multiple assigned roles", async () => {
    (idpPrisma.userRole.findMany as ReturnType<typeof vi.fn>).mockResolvedValue(
      [
        roleWithPermissions(["finance.invoice.read"]),
        roleWithPermissions(["finance.invoice.create"]),
      ],
    );
    const guard = new RbacGuard(
      buildReflector(["finance.invoice.read", "finance.invoice.create"]),
    );
    await expect(
      guard.canActivate(buildContext({ userId: "u1" })),
    ).resolves.toBe(true);
  });

  it("ignores a role with malformed (non-JSON) permissions instead of granting access", async () => {
    (idpPrisma.userRole.findMany as ReturnType<typeof vi.fn>).mockResolvedValue(
      [{ role: { permissions: "not-valid-json{{{" } }],
    );
    const guard = new RbacGuard(buildReflector(["finance.invoice.read"]));
    await expect(
      guard.canActivate(buildContext({ userId: "u1" })),
    ).rejects.toThrow(ForbiddenException);
  });

  it("does not let a same-prefix module wildcard leak into an unrelated module (regression)", async () => {
    (idpPrisma.userRole.findMany as ReturnType<typeof vi.fn>).mockResolvedValue(
      [roleWithPermissions(["finance.*"])],
    );
    const guard = new RbacGuard(buildReflector(["financial.report.read"]));
    await expect(
      guard.canActivate(buildContext({ userId: "u1" })),
    ).rejects.toThrow(ForbiddenException);
  });
});
