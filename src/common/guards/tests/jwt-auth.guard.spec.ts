import { describe, it, expect, vi, beforeEach } from "vitest";
import { ExecutionContext, UnauthorizedException } from "@nestjs/common";

// Regression cover for the `sid`-less token bypass.
//
// A checked-in server action (provider-admin-os/src/lib/dev-token.ts, now
// deleted) minted provider-realm tokens carrying ["*", "system.*"] and no
// `sid` claim, precisely because this guard used to skip the session lookup
// when `sid` was absent. Such a token could not be revoked by any means.
// These tests pin the fix: no `sid`, no access — regardless of how valid the
// signature is.

vi.mock("@kannan19302/auth", () => ({
  verifyTypedToken: vi.fn(),
  TOKEN_TYPE: { SESSION: "session" },
}));

vi.mock("@kannan19302/database", () => {
  const mocked = {
    prisma: {},
    idpPrisma: {
      userSession: { findUnique: vi.fn(), update: vi.fn() },
    },
    runWithTenantSession: vi.fn((_s: unknown, fn: () => unknown) => fn()),
  };
  return mocked;
});

import { verifyTypedToken } from "@kannan19302/auth";
import { idpPrisma } from "@kannan19302/database";
import { JwtAuthGuard } from "../jwt-auth.guard";

function contextWithToken(token: string | undefined): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({
        cookies: token ? { auth_token: token } : {},
        headers: {},
      }),
    }),
  } as unknown as ExecutionContext;
}

const activeSession = {
  id: "sess-1",
  isActive: true,
  expiresAt: new Date(Date.now() + 60_000),
  lastActivityAt: new Date(),
};

describe("JwtAuthGuard — session id is mandatory", () => {
  let guard: JwtAuthGuard;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(idpPrisma.userSession.update).mockResolvedValue({} as never);
    guard = new JwtAuthGuard();
  });

  it("rejects a validly-signed session token that carries no sid", async () => {
    // This is exactly the dev-token payload shape.
    vi.mocked(verifyTypedToken).mockReturnValue({
      userId: "admin-provider-1",
      email: "admin@kannan19302.dev",
      tenantId: "00000000-0000-0000-0000-000000000000",
      realm: "provider",
      permissions: ["*", "system.*"],
      mfaVerified: true,
    } as never);

    await expect(guard.canActivate(contextWithToken("forged"))).rejects.toThrow(
      UnauthorizedException,
    );
    // It must be refused before any session lookup is attempted.
    expect(idpPrisma.userSession.findUnique).not.toHaveBeenCalled();
  });

  it("rejects when sid is present but the session was revoked", async () => {
    vi.mocked(verifyTypedToken).mockReturnValue({
      userId: "u1",
      tenantId: "t1",
      sid: "sess-1",
    } as never);
    vi.mocked(idpPrisma.userSession.findUnique).mockResolvedValue({
      ...activeSession,
      isActive: false,
    } as never);

    await expect(guard.canActivate(contextWithToken("tok"))).rejects.toThrow(
      "Session has been revoked or expired",
    );
  });

  it("rejects when sid refers to a session that no longer exists", async () => {
    vi.mocked(verifyTypedToken).mockReturnValue({
      userId: "u1",
      tenantId: "t1",
      sid: "gone",
    } as never);
    vi.mocked(idpPrisma.userSession.findUnique).mockResolvedValue(null as never);

    await expect(guard.canActivate(contextWithToken("tok"))).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it("admits a token with an active, unexpired session", async () => {
    vi.mocked(verifyTypedToken).mockReturnValue({
      userId: "u1",
      tenantId: "t1",
      sid: "sess-1",
    } as never);
    vi.mocked(idpPrisma.userSession.findUnique).mockResolvedValue(
      activeSession as never,
    );

    await expect(guard.canActivate(contextWithToken("tok"))).resolves.toBe(true);
  });

  it("rejects a request with no token at all", async () => {
    await expect(guard.canActivate(contextWithToken(undefined))).rejects.toThrow(
      "Missing authentication credentials",
    );
  });

  it("rejects a token whose purpose is not a session", async () => {
    // e.g. a password-reset or mfa-challenge token replayed as a session
    vi.mocked(verifyTypedToken).mockReturnValue(null as never);

    await expect(guard.canActivate(contextWithToken("reset"))).rejects.toThrow(
      "Invalid or expired authentication token",
    );
  });
});
