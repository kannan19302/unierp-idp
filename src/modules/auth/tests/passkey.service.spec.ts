import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  session: vi.fn(),
  userFindUnique: vi.fn(),
  userFindFirst: vi.fn(),
  passkeyFindMany: vi.fn(),
  passkeyCreate: vi.fn(),
  passkeyCount: vi.fn(),
  passkeyUpdateMany: vi.fn(),
  passkeyDeleteMany: vi.fn(),
  identityCount: vi.fn(),
  sessionUpdateMany: vi.fn(),
  queryRaw: vi.fn(),
}));

const webauthn = vi.hoisted(() => ({
  generateRegistrationOptions: vi.fn(),
  generateAuthenticationOptions: vi.fn(),
  verifyRegistrationResponse: vi.fn(),
  verifyAuthenticationResponse: vi.fn(),
}));

const audit = vi.hoisted(() => vi.fn());

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    userSession: {
      findUnique: db.session,
      updateMany: db.sessionUpdateMany,
    },
    user: {
      findUnique: db.userFindUnique,
      findFirst: db.userFindFirst,
    },
    passkey: {
      findMany: db.passkeyFindMany,
      create: db.passkeyCreate,
      count: db.passkeyCount,
      updateMany: db.passkeyUpdateMany,
      deleteMany: db.passkeyDeleteMany,
    },
    userIdentity: { count: db.identityCount },
  },
  prisma: { $queryRaw: db.queryRaw },
  runWithTenantSession: vi.fn((_session: unknown, operation: () => unknown) => operation()),
}));

vi.mock("@simplewebauthn/server", () => webauthn);
vi.mock("../../../common/audit/emit-auth-audit", () => ({ emitAuthAudit: audit }));

import { BadRequestException, UnauthorizedException } from "@nestjs/common";
import { PasskeyService } from "../passkey.service";
import type { AuthService } from "../auth.service";
import type { ExternalAuthStore, PasskeyCeremony } from "../external-auth.store";

const USER_ID = "user-1";
const TENANT_ID = "tenant-1";
const SESSION_ID = "session-1";
const CREDENTIAL_ID = "credential_1234567890";

function activeSession() {
  return {
    id: SESSION_ID,
    userId: USER_ID,
    tenantId: TENANT_ID,
    isActive: true,
    startedAt: new Date(),
  };
}

function authResponse() {
  return {
    id: CREDENTIAL_ID,
    rawId: CREDENTIAL_ID,
    type: "public-key" as const,
    clientExtensionResults: {},
    response: {
      authenticatorData: "authenticator-data",
      clientDataJSON: "client-data",
      signature: "signature",
      userHandle: USER_ID,
    },
  };
}

function ceremony(purpose: PasskeyCeremony["purpose"]): PasskeyCeremony {
  return {
    purpose,
    challenge: "challenge",
    rpId: "localhost",
    expectedOrigins: ["http://localhost:3005"],
    userId: purpose === "registration" ? USER_ID : undefined,
    tenantId: purpose === "registration" ? TENANT_ID : undefined,
    returnTo: purpose === "authentication" ? "/platforms" : undefined,
  };
}

function setup() {
  const auth = {
    issueSession: vi.fn().mockResolvedValue({ token: "access", refreshToken: "refresh" }),
  } as unknown as AuthService;
  const store = {
    createPasskeyCeremony: vi.fn().mockResolvedValue("h".repeat(43)),
    consumePasskeyCeremony: vi.fn(),
  } as unknown as ExternalAuthStore;
  return { auth, store, service: new PasskeyService(auth, store) };
}

beforeEach(() => {
  vi.clearAllMocks();
  db.session.mockResolvedValue(activeSession());
  db.userFindUnique.mockResolvedValue({
    id: USER_ID,
    email: "owner@example.com",
    firstName: "Workspace",
    lastName: "Owner",
    status: "ACTIVE",
    passwordHash: "hash",
  });
  db.passkeyFindMany.mockResolvedValue([]);
  db.passkeyUpdateMany.mockResolvedValue({ count: 1 });
  db.passkeyDeleteMany.mockResolvedValue({ count: 1 });
  db.sessionUpdateMany.mockResolvedValue({ count: 1 });
  db.passkeyCount.mockResolvedValue(1);
  db.identityCount.mockResolvedValue(0);
  audit.mockResolvedValue(undefined);
});

describe("PasskeyService", () => {
  it("generates discoverable, user-verified registration options and binds the challenge to the session user", async () => {
    webauthn.generateRegistrationOptions.mockResolvedValue({ challenge: "registration-challenge" });
    const { service, store } = setup();

    await service.registrationOptions(USER_ID, TENANT_ID, SESSION_ID);

    expect(webauthn.generateRegistrationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        rpID: "localhost",
        attestationType: "none",
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required",
        },
        supportedAlgorithmIDs: [-7, -257],
      }),
    );
    expect(store.createPasskeyCeremony).toHaveBeenCalledWith(
      expect.objectContaining({
        purpose: "registration",
        challenge: "registration-challenge",
        userId: USER_ID,
        tenantId: TENANT_ID,
      }),
    );
  });

  it("rejects enrollment when the authenticated session is no longer recent", async () => {
    db.session.mockResolvedValue({
      ...activeSession(),
      startedAt: new Date(Date.now() - 11 * 60 * 1000),
    });
    const { service } = setup();

    await expect(
      service.registrationOptions(USER_ID, TENANT_ID, SESSION_ID),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(webauthn.generateRegistrationOptions).not.toHaveBeenCalled();
  });

  it("rejects an expired or replayed authentication ceremony before credential lookup", async () => {
    const { service, store } = setup();
    vi.mocked(store.consumePasskeyCeremony).mockResolvedValue(null);

    await expect(
      service.verifyAuthentication({ handle: "h".repeat(43), response: authResponse() }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(db.queryRaw).not.toHaveBeenCalled();
    expect(webauthn.verifyAuthenticationResponse).not.toHaveBeenCalled();
  });

  it("verifies the exact RP context, advances the counter, and issues an AAL2 WebAuthn session", async () => {
    const { service, store, auth } = setup();
    vi.mocked(store.consumePasskeyCeremony).mockResolvedValue(ceremony("authentication"));
    db.queryRaw.mockResolvedValue([{
      id: "passkey-1",
      tenant_id: TENANT_ID,
      user_id: USER_ID,
      credential_id: CREDENTIAL_ID,
      public_key: Buffer.from([1, 2, 3]).toString("base64url"),
      counter: 4n,
      transports: "internal,hybrid",
      device_type: "multiDevice",
      backup_eligible: true,
      backed_up: true,
    }]);
    db.userFindFirst.mockResolvedValue({ id: USER_ID, tenantId: TENANT_ID, status: "ACTIVE" });
    webauthn.verifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: {
        userVerified: true,
        newCounter: 5,
        credentialDeviceType: "multiDevice",
        credentialBackedUp: true,
      },
    });

    const result = await service.verifyAuthentication({
      handle: "h".repeat(43),
      response: authResponse(),
      context: { ipAddress: "127.0.0.1", userAgent: "test" },
    });

    expect(webauthn.verifyAuthenticationResponse).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedChallenge: "challenge",
        expectedOrigin: ["http://localhost:3005"],
        expectedRPID: "localhost",
        requireUserVerification: true,
        credential: expect.objectContaining({ id: CREDENTIAL_ID, counter: 4 }),
      }),
    );
    expect(db.passkeyUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: "passkey-1", counter: 4n }),
      data: expect.objectContaining({ counter: 5n }),
    }));
    expect(auth.issueSession).toHaveBeenCalledWith(
      expect.objectContaining({ authMethods: [{ type: "WEBAUTHN" }] }),
      expect.anything(),
      { mfaVerified: true },
    );
    expect(result.returnTo).toBe("/platforms");
  });

  it("fails closed if another authentication races the stored counter update", async () => {
    const { service, store, auth } = setup();
    vi.mocked(store.consumePasskeyCeremony).mockResolvedValue(ceremony("authentication"));
    db.queryRaw.mockResolvedValue([{
      id: "passkey-1", tenant_id: TENANT_ID, user_id: USER_ID,
      credential_id: CREDENTIAL_ID, public_key: "AQID", counter: 0n,
      transports: null, device_type: "singleDevice", backup_eligible: false, backed_up: false,
    }]);
    db.userFindFirst.mockResolvedValue({ id: USER_ID, status: "ACTIVE" });
    db.passkeyUpdateMany.mockResolvedValue({ count: 0 });
    webauthn.verifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: {
        userVerified: true,
        newCounter: 1,
        credentialDeviceType: "singleDevice",
        credentialBackedUp: false,
      },
    });

    await expect(
      service.verifyAuthentication({ handle: "h".repeat(43), response: authResponse() }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(auth.issueSession).not.toHaveBeenCalled();
  });

  it("prevents removal of the user's last remaining sign-in method", async () => {
    const { service } = setup();
    db.userFindUnique.mockResolvedValue({ id: USER_ID, passwordHash: null });

    await expect(service.deletePasskey({
      userId: USER_ID,
      tenantId: TENANT_ID,
      sid: SESSION_ID,
      passkeyId: "passkey-1",
    })).rejects.toBeInstanceOf(BadRequestException);
    expect(db.passkeyDeleteMany).not.toHaveBeenCalled();
  });

  it("removes an owned passkey and revokes the user's other sessions", async () => {
    const { service } = setup();

    await service.deletePasskey({
      userId: USER_ID,
      tenantId: TENANT_ID,
      sid: SESSION_ID,
      passkeyId: "passkey-1",
    });

    expect(db.passkeyDeleteMany).toHaveBeenCalledWith({
      where: { id: "passkey-1", userId: USER_ID },
    });
    expect(db.sessionUpdateMany).toHaveBeenCalledWith({
      where: { userId: USER_ID, id: { not: SESSION_ID }, isActive: true },
      data: { isActive: false },
    });
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({ action: "PASSKEY_REMOVED" }));
  });
});
