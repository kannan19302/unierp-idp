import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  queryRaw: vi.fn(),
  sessionFindUnique: vi.fn(),
  userFindFirst: vi.fn(),
  userFindUnique: vi.fn(),
  userUpdateMany: vi.fn(),
  profileFindUnique: vi.fn(),
  identityFindMany: vi.fn(),
  roleFindMany: vi.fn(),
  sessionFindMany: vi.fn(),
  sessionUpdateMany: vi.fn(),
  passkeyFindMany: vi.fn(),
  contactFindMany: vi.fn(),
  subjectFindMany: vi.fn(),
  tenantFindUnique: vi.fn(),
  exportCreate: vi.fn(),
  exportUpdate: vi.fn(),
  exportFindMany: vi.fn(),
  erasureFindFirst: vi.fn(),
  erasureFindMany: vi.fn(),
  erasureCreate: vi.fn(),
  erasureUpdateMany: vi.fn(),
}));
const audit = vi.hoisted(() => vi.fn());

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    userSession: { findUnique: db.sessionFindUnique, findMany: db.sessionFindMany, updateMany: db.sessionUpdateMany },
    user: { findUnique: db.userFindUnique, findFirst: db.userFindFirst, updateMany: db.userUpdateMany },
    userProfile: { findUnique: db.profileFindUnique },
    userIdentity: { findMany: db.identityFindMany },
    userRole: { findMany: db.roleFindMany },
    passkey: { findMany: db.passkeyFindMany },
    accountContact: { findMany: db.contactFindMany },
  },
  prisma: {
    $queryRaw: db.queryRaw,
    tenant: { findUnique: db.tenantFindUnique },
    dataExportJob: {
      create: db.exportCreate,
      update: db.exportUpdate,
      findMany: db.exportFindMany,
    },
    dataErasureRequest: {
      findFirst: db.erasureFindFirst,
      findMany: db.erasureFindMany,
      create: db.erasureCreate,
      updateMany: db.erasureUpdateMany,
    },
    customer: { findMany: db.subjectFindMany },
    vendor: { findMany: db.subjectFindMany },
    contact: { findMany: db.subjectFindMany },
    lead: { findMany: db.subjectFindMany },
    employee: { findMany: db.subjectFindMany },
    applicant: { findMany: db.subjectFindMany },
    customerPortalUser: { findMany: db.subjectFindMany },
    vendorPortalUser: { findMany: db.subjectFindMany },
    pOSLoyaltyMember: { findMany: db.subjectFindMany },
  },
  runWithTenantSession: vi.fn((_session: unknown, operation: () => unknown) => operation()),
}));
vi.mock("../../../common/audit/emit-auth-audit", () => ({ emitAuthAudit: audit }));

import { BadRequestException, UnauthorizedException } from "@nestjs/common";
import { AccountGovernanceService } from "../account-governance.service";
import type { AuthService } from "../auth.service";

const USER_ID = "user-1";
const TENANT_ID = "tenant-1";
const SESSION_ID = "session-1";

function setup() {
  const auth = {
    issueSession: vi.fn().mockResolvedValue({ token: "access", refreshToken: "refresh" }),
  } as unknown as AuthService;
  return { auth, service: new AccountGovernanceService(auth) };
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
  db.userFindUnique.mockResolvedValue({
    id: USER_ID,
    tenantId: TENANT_ID,
    email: "owner@example.com",
    firstName: "Workspace",
    lastName: "Owner",
  });
  db.userFindFirst.mockResolvedValue({ id: "user-2", tenantId: "tenant-2", status: "ACTIVE" });
  db.userUpdateMany.mockResolvedValue({ count: 1 });
  db.sessionUpdateMany.mockResolvedValue({ count: 2 });
  db.profileFindUnique.mockResolvedValue(null);
  db.identityFindMany.mockResolvedValue([]);
  db.roleFindMany.mockResolvedValue([]);
  db.sessionFindMany.mockResolvedValue([]);
  db.passkeyFindMany.mockResolvedValue([]);
  db.contactFindMany.mockResolvedValue([]);
  db.subjectFindMany.mockResolvedValue([]);
  db.tenantFindUnique.mockResolvedValue({ id: TENANT_ID, name: "Acme" });
  db.exportCreate.mockResolvedValue({ id: "export-1", createdAt: new Date() });
  db.exportUpdate.mockResolvedValue({ id: "export-1" });
  db.exportFindMany.mockResolvedValue([]);
  db.erasureFindFirst.mockResolvedValue(null);
  db.erasureFindMany.mockResolvedValue([]);
  db.erasureCreate.mockResolvedValue({
    id: "erase-1", status: "PENDING", createdAt: new Date(), eligibleAt: new Date(),
  });
  db.erasureUpdateMany.mockResolvedValue({ count: 1 });
  audit.mockResolvedValue(undefined);
});

describe("AccountGovernanceService", () => {
  it("returns only organizations resolved by the verified-identity database function", async () => {
    db.queryRaw.mockResolvedValue([{ target_user_id: USER_ID, tenant_id: TENANT_ID }]);
    const { service } = setup();

    const result = await service.listOrganizations(USER_ID, TENANT_ID);

    expect(result).toEqual([{ target_user_id: USER_ID, tenant_id: TENANT_ID }]);
    expect(db.queryRaw).toHaveBeenCalledOnce();
  });

  it("switches only to a function-authorized verified membership and issues a new tenant session", async () => {
    db.queryRaw.mockResolvedValue([{
      target_user_id: "user-2", tenant_id: "tenant-2", tenant_name: "Other", tenant_slug: "other", is_current: false,
    }]);
    db.userFindFirst.mockResolvedValue({ id: "user-2", tenantId: "tenant-2", status: "ACTIVE" });
    const { service, auth } = setup();

    await service.switchOrganization({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID, targetTenantId: "tenant-2",
    });

    expect(auth.issueSession).toHaveBeenCalledWith(
      expect.objectContaining({ id: "user-2", tenantId: "tenant-2" }),
      undefined,
    );
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({
      action: "ACCOUNT_ORGANIZATION_SWITCHED", tenantId: "tenant-2",
    }));
  });

  it("rejects an organization not returned by the verified membership resolver", async () => {
    db.queryRaw.mockResolvedValue([]);
    const { service, auth } = setup();

    await expect(service.switchOrganization({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID, targetTenantId: "tenant-2",
    })).rejects.toBeInstanceOf(UnauthorizedException);
    expect(auth.issueSession).not.toHaveBeenCalled();
  });

  it("leaves a verified non-current membership and revokes its active sessions", async () => {
    db.queryRaw.mockResolvedValue([{
      target_user_id: "user-2", tenant_id: "tenant-2", tenant_name: "Other", tenant_slug: "other", is_current: false,
    }]);
    db.roleFindMany.mockResolvedValue([]);
    const { service } = setup();

    const result = await service.leaveOrganization({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID, targetTenantId: "tenant-2",
    });

    expect(result).toEqual({ removed: true, tenantId: "tenant-2" });
    expect(db.userUpdateMany).toHaveBeenCalledWith({
      where: { id: "user-2", tenantId: "tenant-2", status: "ACTIVE" },
      data: { status: "INACTIVE" },
    });
    expect(db.sessionUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ userId: "user-2", tenantId: "tenant-2", isActive: true }),
    }));
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({
      action: "ACCOUNT_ORGANIZATION_MEMBERSHIP_LEFT", tenantId: "tenant-2", userId: "user-2",
    }));
  });

  it("blocks leaving a target organization as its last owner", async () => {
    db.queryRaw.mockResolvedValue([{
      target_user_id: "user-2", tenant_id: "tenant-2", tenant_name: "Other", tenant_slug: "other", is_current: false,
    }]);
    db.roleFindMany.mockResolvedValue([{ userId: "user-2" }]);
    const { service } = setup();

    await expect(service.leaveOrganization({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID, targetTenantId: "tenant-2",
    })).rejects.toThrow("last owner");
    expect(db.userUpdateMany).not.toHaveBeenCalled();
  });

  it("creates a self-owned expiring export and omits credential secrets from its package", async () => {
    const { service } = setup();

    const result = await service.createSubjectExport({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID,
    });

    expect(db.exportCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        type: "SUBJECT_EXPORT", requestedBy: USER_ID, status: "PROCESSING",
      }),
    }));
    expect(JSON.stringify(result.data)).not.toContain("passwordHash");
    expect(JSON.stringify(result.data)).not.toContain("publicKey");
    expect(db.exportUpdate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: "COMPLETE" }),
    }));
  });

  it("blocks deletion of the organization's last owner", async () => {
    db.roleFindMany.mockResolvedValue([{ userId: USER_ID, role: { name: "owner" } }]);
    const { service } = setup();

    await expect(service.requestAccountDeletion({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID,
    })).rejects.toBeInstanceOf(BadRequestException);
    expect(db.erasureCreate).not.toHaveBeenCalled();
  });

  it("records a cooling-off deletion request and permits its owner to cancel it", async () => {
    const { service } = setup();

    const requested = await service.requestAccountDeletion({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID, reason: "No longer needed",
    });
    const cancelled = await service.cancelAccountDeletion({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID, requestId: requested.id,
    });

    expect(db.erasureCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        requestedBy: USER_ID,
        status: "PENDING",
        requestReason: "No longer needed",
        eligibleAt: expect.any(Date),
      }),
    }));
    expect(db.erasureUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: "erase-1", requestedBy: USER_ID, status: "PENDING" }),
      data: expect.objectContaining({ status: "CANCELLED", cancelledAt: expect.any(Date) }),
    }));
    expect(cancelled.status).toBe("CANCELLED");
  });

  it("requires recent authentication for export and deletion actions", async () => {
    db.sessionFindUnique.mockResolvedValue({
      id: SESSION_ID, userId: USER_ID, tenantId: TENANT_ID, isActive: true,
      startedAt: new Date(Date.now() - 11 * 60 * 1000),
    });
    const { service } = setup();

    await expect(service.createSubjectExport({
      userId: USER_ID, tenantId: TENANT_ID, sid: SESSION_ID,
    })).rejects.toBeInstanceOf(UnauthorizedException);
  });
});
