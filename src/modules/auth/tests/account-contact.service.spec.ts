import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  sessionFindUnique: vi.fn(),
  userFindUnique: vi.fn(),
  contactCount: vi.fn(),
  contactCreate: vi.fn(),
  contactFindFirst: vi.fn(),
  contactFindMany: vi.fn(),
  contactDeleteMany: vi.fn(),
  verificationCreate: vi.fn(),
  verificationDeleteMany: vi.fn(),
  queryRaw: vi.fn(),
}));
const audit = vi.hoisted(() => vi.fn());

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    userSession: { findUnique: db.sessionFindUnique },
    user: { findUnique: db.userFindUnique },
    accountContact: {
      count: db.contactCount,
      create: db.contactCreate,
      findFirst: db.contactFindFirst,
      findMany: db.contactFindMany,
      deleteMany: db.contactDeleteMany,
    },
    accountContactVerification: {
      create: db.verificationCreate,
      deleteMany: db.verificationDeleteMany,
    },
  },
  prisma: { $queryRaw: db.queryRaw },
  runWithTenantSession: vi.fn((_session: unknown, operation: () => unknown) => operation()),
}));
vi.mock("../../../common/audit/emit-auth-audit", () => ({ emitAuthAudit: audit }));

import { BadRequestException, UnauthorizedException } from "@nestjs/common";
import { AccountContactService } from "../account-contact.service";
import type { AuthService } from "../auth.service";

const USER_ID = "user-1";
const TENANT_ID = "tenant-1";
const SESSION_ID = "session-1";
const CONTACT_ID = "contact-1";

function setup() {
  const auth = { queueAccountEmail: vi.fn().mockResolvedValue(undefined) } as unknown as AuthService;
  return { auth, service: new AccountContactService(auth) };
}

beforeEach(() => {
  vi.clearAllMocks();
  db.sessionFindUnique.mockResolvedValue({
    id: SESSION_ID,
    userId: USER_ID,
    tenantId: TENANT_ID,
    isActive: true,
    startedAt: new Date(),
  });
  db.userFindUnique.mockResolvedValue({ id: USER_ID, email: "owner@example.com" });
  db.contactCount.mockResolvedValue(1);
  db.contactCreate.mockResolvedValue({
    id: CONTACT_ID,
    type: "EMAIL",
    value: "recovery@example.com",
    label: "Recovery email",
    isPrimary: false,
    verifiedAt: null,
  });
  db.verificationCreate.mockResolvedValue({ id: "verification-1" });
  db.verificationDeleteMany.mockResolvedValue({ count: 1 });
  db.contactDeleteMany.mockResolvedValue({ count: 1 });
  db.queryRaw.mockResolvedValue([]);
  audit.mockResolvedValue(undefined);
});

describe("AccountContactService", () => {
  it("stores only a token hash and queues a time-limited verification link", async () => {
    const { service, auth } = setup();

    await service.addRecoveryEmail({
      userId: USER_ID,
      tenantId: TENANT_ID,
      sid: SESSION_ID,
      email: " Recovery@Example.com ",
      label: "  Backup   inbox ",
    });

    expect(db.contactCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ normalizedValue: "recovery@example.com", label: "Backup inbox" }),
    }));
    const storedHash = db.verificationCreate.mock.calls[0][0].data.tokenHash as string;
    expect(storedHash).toMatch(/^[a-f0-9]{64}$/);
    expect(auth.queueAccountEmail).toHaveBeenCalledWith(expect.objectContaining({
      to: "recovery@example.com",
      subject: "Verify your UniERP recovery email",
      body: expect.stringMatching(/\/oidc\/account\/contact\/verify\?token=[A-Za-z0-9_-]{40,64}/),
    }));
    expect(vi.mocked(auth.queueAccountEmail).mock.calls[0][0].body).not.toContain(storedHash);
  });

  it("rejects the primary address and organization-level duplicate addresses", async () => {
    const { service } = setup();
    await expect(service.addRecoveryEmail({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID, email: "OWNER@example.com",
    })).rejects.toBeInstanceOf(BadRequestException);

    db.contactCreate.mockRejectedValueOnce({ code: "P2002" });
    await expect(service.addRecoveryEmail({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID, email: "taken@example.com",
    })).rejects.toThrow("already registered");
  });

  it("invalidates old links before resending an unverified contact", async () => {
    db.contactFindFirst.mockResolvedValue({
      id: CONTACT_ID, value: "recovery@example.com", verifiedAt: null, isPrimary: false,
    });
    const { service, auth } = setup();

    await service.resendVerification({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID, contactId: CONTACT_ID,
    });

    expect(db.verificationDeleteMany).toHaveBeenCalledWith({
      where: { contactId: CONTACT_ID, usedAt: null },
    });
    expect(db.verificationCreate).toHaveBeenCalledOnce();
    expect(auth.queueAccountEmail).toHaveBeenCalledOnce();
  });

  it("rejects malformed and replayed verification links without entering tenant data", async () => {
    const { service } = setup();
    await expect(service.verify("invalid")).rejects.toBeInstanceOf(BadRequestException);
    expect(db.queryRaw).not.toHaveBeenCalled();

    await expect(service.verify("a".repeat(43))).rejects.toBeInstanceOf(BadRequestException);
    expect(db.queryRaw).toHaveBeenCalledOnce();
    expect(db.contactFindFirst).not.toHaveBeenCalled();
  });

  it("consumes one exact token through the pre-auth function and audits the verified contact", async () => {
    db.queryRaw.mockResolvedValue([{ tenant_id: TENANT_ID, user_id: USER_ID, contact_id: CONTACT_ID }]);
    db.contactFindFirst.mockResolvedValue({
      id: CONTACT_ID, type: "EMAIL", label: "Recovery email", verifiedAt: new Date(),
    });
    const { service } = setup();

    const result = await service.verify("b".repeat(43));

    expect(result.id).toBe(CONTACT_ID);
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({
      action: "ACCOUNT_CONTACT_VERIFIED", entityId: CONTACT_ID,
    }));
  });

  it("never removes the primary contact", async () => {
    db.contactDeleteMany.mockResolvedValue({ count: 0 });
    const { service } = setup();

    await expect(service.remove({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID, contactId: "primary-contact",
    })).rejects.toThrow("primary email cannot be removed");
  });

  it("requires recent authentication for contact mutations", async () => {
    db.sessionFindUnique.mockResolvedValue({
      id: SESSION_ID,
      userId: USER_ID,
      tenantId: TENANT_ID,
      isActive: true,
      startedAt: new Date(Date.now() - 11 * 60 * 1000),
    });
    const { service } = setup();

    await expect(service.addRecoveryEmail({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID, email: "recovery@example.com",
    })).rejects.toBeInstanceOf(UnauthorizedException);
    expect(db.contactCreate).not.toHaveBeenCalled();
  });
});
