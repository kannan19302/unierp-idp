/**
 * Live integration test against the dev Postgres. Not part of the default unit
 * run (`.itest.ts` + separate config) because it needs a real database.
 *
 * Verifies the hardening actually behaves at the DB boundary: lockout after N
 * failures, single-use password reset, and the MFA challenge/verify handshake.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { idpPrisma, prisma } from "@kannan19302/database";
import { hashPassword, verifyTypedToken, TOKEN_TYPE } from "@kannan19302/auth";
import { authenticator } from "otplib";
import { AuthService } from "../auth.service";
import { JwtAuthGuard } from "../../../common/guards/jwt-auth.guard";
import { generateTotpSecret, generateRecoveryCodes } from "../auth-crypto";

/** Minimal ExecutionContext exposing a request with a bearer token. */
function ctxWithToken(token: string) {
  const req = { headers: { authorization: `Bearer ${token}` }, cookies: {} };
  return { switchToHttp: () => ({ getRequest: () => req }) } as never;
}

const svc = new AuthService();
const SLUG = `itest-${Date.now()}`;
const EMAIL = `itest-${Date.now()}@example.com`;
const PASSWORD = "Sup3rStr0ng!Pass";

let tenantId = "";
let userId = "";

beforeAll(async () => {
  const tenant = await prisma.tenant.create({
    data: { name: "ITest", slug: SLUG, plan: "free", status: "ACTIVE" },
  });
  tenantId = tenant.id;
  const role = await idpPrisma.role.create({
    data: {
      tenantId,
      name: "Admin",
      isSystem: true,
      permissions: JSON.stringify(["*"]),
    },
  });
  const user = await idpPrisma.user.create({
    data: {
      tenantId,
      email: EMAIL,
      passwordHash: await hashPassword(PASSWORD),
      passwordChangedAt: new Date(),
      firstName: "I",
      lastName: "Test",
      status: "ACTIVE",
    },
  });
  userId = user.id;
  await idpPrisma.userRole.create({ data: { userId, roleId: role.id } });
});

afterAll(async () => {
  await prisma.loginHistory.deleteMany({ where: { userId } });
  await idpPrisma.passwordResetToken.deleteMany({ where: { userId } });
  await idpPrisma.userRole.deleteMany({ where: { userId } });
  await idpPrisma.user.deleteMany({ where: { id: userId } });
  await idpPrisma.role.deleteMany({ where: { tenantId } });
  await prisma.tenant.deleteMany({ where: { id: tenantId } });
});

describe("auth integration (live DB)", () => {
  it("issues a purpose-scoped session token on success", async () => {
    const res = (await svc.login({
      email: EMAIL,
      password: PASSWORD,
      tenantSlug: SLUG,
    })) as { token: string };
    expect(res.token).toBeTruthy();
    // The issued token is a SESSION token and must not pass as a reset token.
    expect(verifyTypedToken(res.token, TOKEN_TYPE.SESSION)).toBeTruthy();
    expect(verifyTypedToken(res.token, TOKEN_TYPE.PASSWORD_RESET)).toBeNull();
  });

  it("locks the account after repeated failures, then reports locked", async () => {
    await idpPrisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });
    for (let i = 0; i < 5; i++) {
      await expect(
        svc.login({ email: EMAIL, password: "wrong", tenantSlug: SLUG }),
      ).rejects.toThrow(/Invalid credentials/);
    }
    // 6th attempt — even with the CORRECT password — is refused while locked.
    await expect(
      svc.login({ email: EMAIL, password: PASSWORD, tenantSlug: SLUG }),
    ).rejects.toThrow(/locked/i);

    const locked = await idpPrisma.user.findUnique({ where: { id: userId } });
    expect(locked?.lockedUntil).toBeTruthy();

    // Clear the lock for later tests.
    await idpPrisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });
  });

  it("password reset token is single-use", async () => {
    const fp = (await svc.forgotPassword({ email: EMAIL })) as {
      developerResetLink?: string;
    };
    const token = new URL(fp.developerResetLink!).searchParams.get("token")!;
    expect(token).toMatch(/^[a-f0-9]{64}$/);

    const NEW = "An0ther!Str0ngPwd";
    const first = await svc.resetPassword({
      token,
      password: NEW,
      confirmPassword: NEW,
    });
    expect(first.message).toMatch(/successfully/i);

    // Reusing the same token must fail.
    await expect(
      svc.resetPassword({ token, password: NEW, confirmPassword: NEW }),
    ).rejects.toThrow(/Invalid or expired/);

    // Restore the original password for subsequent tests.
    await idpPrisma.user.update({
      where: { id: userId },
      data: { passwordHash: await hashPassword(PASSWORD) },
    });
  });

  it("MFA login requires a valid challenge token AND a valid TOTP code", async () => {
    const secret = generateTotpSecret();
    const { hashes } = await generateRecoveryCodes(3);
    await idpPrisma.user.update({
      where: { id: userId },
      data: { mfaEnabled: true, mfaSecret: secret, mfaRecoveryCodes: hashes },
    });

    // Step 1: password login now returns a challenge, not a session.
    const step1 = (await svc.login({
      email: EMAIL,
      password: PASSWORD,
      tenantSlug: SLUG,
    })) as { mfaRequired?: boolean; challengeToken?: string };
    expect(step1.mfaRequired).toBe(true);
    expect(step1.challengeToken).toBeTruthy();

    // Wrong code is rejected.
    await expect(
      svc.verifyMfaLogin(step1.challengeToken!, "000000"),
    ).rejects.toThrow(/Invalid verification code/);

    // A forged/garbage challenge token is rejected.
    await expect(
      svc.verifyMfaLogin("garbage", authenticator.generate(secret)),
    ).rejects.toThrow(/expired/i);

    // Correct challenge + live TOTP code issues a session.
    const good = (await svc.verifyMfaLogin(
      step1.challengeToken!,
      authenticator.generate(secret),
    )) as { token: string };
    expect(good.token).toBeTruthy();

    await idpPrisma.user.update({
      where: { id: userId },
      data: { mfaEnabled: false, mfaSecret: null, mfaRecoveryCodes: [] },
    });
  });

  it("session is revocable: guard accepts then rejects after revoke", async () => {
    const guard = new JwtAuthGuard();
    const res = (await svc.login({
      email: EMAIL,
      password: PASSWORD,
      tenantSlug: SLUG,
    })) as { token: string };

    // Token is accepted while the session is active.
    await expect(guard.canActivate(ctxWithToken(res.token))).resolves.toBe(
      true,
    );

    // Revoke, then the very same token is rejected.
    const decoded = (await import("@kannan19302/auth")).verifyToken(res.token) as {
      sid: string;
    };
    await svc.revokeSessionById(decoded.sid);
    await expect(guard.canActivate(ctxWithToken(res.token))).rejects.toThrow(
      /revoked|expired/i,
    );
  });

  it("stores an encrypted MFA secret (not plaintext) on enrollment", async () => {
    const setup = await svc.generateMfaSecret(userId);
    const row = await idpPrisma.user.findUnique({ where: { id: userId } });
    expect(row?.mfaSecret).toMatch(/^v1:/); // encrypted-at-rest marker
    expect(row?.mfaSecret).not.toContain(setup.secret);
    await idpPrisma.user.update({
      where: { id: userId },
      data: { mfaSecret: null, mfaPending: false },
    });
  });

  it("records successful and failed login attempts in login history", async () => {
    // Clear any previous history
    await prisma.loginHistory.deleteMany({ where: { userId } });

    // 1. Success login
    const context = {
      ipAddress: "127.0.0.1",
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    };
    await svc.login(
      { email: EMAIL, password: PASSWORD, tenantSlug: SLUG },
      context,
    );

    // 2. Failed login
    await expect(
      svc.login(
        { email: EMAIL, password: "wrong-password", tenantSlug: SLUG },
        context,
      ),
    ).rejects.toThrow();

    // 3. Query history
    const history = await svc.listLoginHistory(userId, tenantId);
    expect(history.length).toBe(2);

    const successRecord = history.find((h) => h.status === "SUCCESS");
    expect(successRecord).toBeDefined();
    expect(successRecord?.ipAddress).toBe("127.0.0.1");
    expect(successRecord?.browser).toBe("Chrome");
    expect(successRecord?.device).toBe("Windows");
    expect(successRecord?.location).toBe("Local Network");

    const failedRecord = history.find((h) => h.status === "FAILED");
    expect(failedRecord).toBeDefined();
    expect(failedRecord?.ipAddress).toBe("127.0.0.1");
    expect(failedRecord?.failureReason).toBe("INVALID_CREDENTIALS");
  });
});
