import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { emitAuthAudit } from "../../common/audit/emit-auth-audit";
import { AuthService, type SessionContext } from "./auth.service";

const RECENT_AUTH_MS = 10 * 60 * 1000;
const EXPORT_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const ERASURE_COOLING_OFF_MS = 14 * 24 * 60 * 60 * 1000;
const OWNER_ROLE_NAMES = ["owner", "tenant-owner", "organization-owner"];

export type AccountOrganization = {
  target_user_id: string;
  tenant_id: string;
  tenant_name: string;
  tenant_slug: string;
  is_current: boolean;
};

@Injectable()
export class AccountGovernanceService {
  constructor(private readonly auth: AuthService) {}

  async listOrganizations(userId: string, tenantId: string) {
    if (!userId || !tenantId) return [];
    return prisma.$queryRaw<AccountOrganization[]>`
      SELECT * FROM auth_list_account_organizations(${userId}, ${tenantId})
    `;
  }

  async switchOrganization(params: {
    userId: string;
    tenantId: string;
    sid: string;
    targetTenantId: string;
    context?: SessionContext;
  }) {
    await this.requireFreshSession(params.userId, params.tenantId, params.sid);
    if (!params.targetTenantId || params.targetTenantId === params.tenantId) {
      throw new BadRequestException("Choose another active organization.");
    }
    const organizations = await this.listOrganizations(params.userId, params.tenantId);
    const target = organizations.find((item) => item.tenant_id === params.targetTenantId);
    if (!target) throw new UnauthorizedException("Organization membership is not available.");

    const user = await runWithTenantSession(
      { tenantId: target.tenant_id, userId: target.target_user_id },
      () => idpPrisma.user.findFirst({
        where: {
          id: target.target_user_id,
          tenantId: target.tenant_id,
          status: "ACTIVE",
          deletedAt: null,
          emailVerifiedAt: { not: null },
        },
      }),
    );
    if (!user) throw new UnauthorizedException("Organization membership is not available.");

    const session = await this.auth.issueSession(user, params.context);
    await emitAuthAudit({
      tenantId: target.tenant_id,
      userId: target.target_user_id,
      action: "ACCOUNT_ORGANIZATION_SWITCHED",
      entityType: "Tenant",
      entityId: target.tenant_id,
      changes: { fromTenantId: params.tenantId },
    });
    return session;
  }

  async leaveOrganization(params: {
    userId: string;
    tenantId: string;
    sid: string;
    targetTenantId: string;
  }) {
    await this.requireFreshSession(params.userId, params.tenantId, params.sid);
    if (!params.targetTenantId || params.targetTenantId === params.tenantId) {
      throw new BadRequestException(
        "Switch to another workspace before leaving the current organization.",
      );
    }
    const organizations = await this.listOrganizations(params.userId, params.tenantId);
    const target = organizations.find((item) => item.tenant_id === params.targetTenantId);
    if (!target) throw new UnauthorizedException("Organization membership is not available.");

    await runWithTenantSession(
      { tenantId: target.tenant_id, userId: target.target_user_id },
      async () => {
        const [user, ownerMemberships] = await Promise.all([
          idpPrisma.user.findFirst({
            where: {
              id: target.target_user_id,
              tenantId: target.tenant_id,
              status: "ACTIVE",
              deletedAt: null,
              emailVerifiedAt: { not: null },
            },
            select: { id: true },
          }),
          idpPrisma.userRole.findMany({
            where: {
              role: { tenantId: target.tenant_id, name: { in: OWNER_ROLE_NAMES } },
            },
            select: { userId: true },
          }),
        ]);
        if (!user) throw new UnauthorizedException("Organization membership is not available.");
        const ownerIds = new Set(ownerMemberships.map((membership) => membership.userId));
        if (ownerIds.has(target.target_user_id) && ownerIds.size <= 1) {
          throw new BadRequestException(
            "Transfer organization ownership before leaving as its last owner.",
          );
        }
        const deactivated = await idpPrisma.user.updateMany({
          where: { id: target.target_user_id, tenantId: target.tenant_id, status: "ACTIVE" },
          data: { status: "INACTIVE" },
        });
        if (deactivated.count !== 1) {
          throw new BadRequestException("Organization membership could not be removed.");
        }
        await idpPrisma.userSession.updateMany({
          where: { userId: target.target_user_id, tenantId: target.tenant_id, isActive: true },
          data: { isActive: false },
        });
      },
    );
    await emitAuthAudit({
      tenantId: target.tenant_id,
      userId: target.target_user_id,
      action: "ACCOUNT_ORGANIZATION_MEMBERSHIP_LEFT",
      entityType: "Tenant",
      entityId: target.tenant_id,
      changes: { requestedFromTenantId: params.tenantId, membershipStatus: "INACTIVE" },
    });
    return { removed: true, tenantId: target.tenant_id };
  }

  async privacyState(userId: string, tenantId: string) {
    return runWithTenantSession({ tenantId, userId }, async () => {
      const [exports, erasures] = await Promise.all([
        prisma.dataExportJob.findMany({
          where: { tenantId, requestedBy: userId, type: "SUBJECT_EXPORT" },
          orderBy: { createdAt: "desc" },
          take: 5,
          select: {
            id: true,
            status: true,
            createdAt: true,
            completedAt: true,
            expiresAt: true,
          },
        }),
        prisma.dataErasureRequest.findMany({
          where: { tenantId, requestedBy: userId },
          orderBy: { createdAt: "desc" },
          take: 5,
          select: {
            id: true,
            status: true,
            createdAt: true,
            eligibleAt: true,
            cancelledAt: true,
            erasedAt: true,
          },
        }),
      ]);
      return { exports, erasures };
    });
  }

  async createSubjectExport(params: {
    userId: string;
    tenantId: string;
    sid: string;
  }) {
    await this.requireFreshSession(params.userId, params.tenantId, params.sid);
    const expiresAt = new Date(Date.now() + EXPORT_RETENTION_MS);
    const result = await runWithTenantSession(
      { tenantId: params.tenantId, userId: params.userId },
      async () => {
        const job = await prisma.dataExportJob.create({
          data: {
            tenantId: params.tenantId,
            type: "SUBJECT_EXPORT",
            format: "JSON",
            scope: { subject: "self", domains: ["identity", "security", "preferences"] },
            status: "PROCESSING",
            requestedBy: params.userId,
            expiresAt,
          },
          select: { id: true, createdAt: true },
        });
        const subject = await idpPrisma.user.findUnique({
          where: { id: params.userId },
          select: { email: true },
        });
        if (!subject) throw new UnauthorizedException("Account not found.");
        const [tenant, user, profile, identities, roles, sessions, passkeys, contacts, subjectRecords] = await Promise.all([
          prisma.tenant.findUnique({
            where: { id: params.tenantId },
            select: { id: true, name: true, slug: true, plan: true, status: true, createdAt: true },
          }),
          idpPrisma.user.findUnique({
            where: { id: params.userId },
            select: {
              id: true, email: true, firstName: true, lastName: true, avatar: true,
              status: true, emailVerifiedAt: true, lastLoginAt: true, createdAt: true,
              updatedAt: true, preferences: true, mfaEnabled: true,
            },
          }),
          idpPrisma.userProfile.findUnique({ where: { userId: params.userId } }),
          idpPrisma.userIdentity.findMany({
            where: { userId: params.userId },
            select: { provider: true, email: true, createdAt: true },
          }),
          idpPrisma.userRole.findMany({
            where: { userId: params.userId },
            include: { role: { select: { name: true, description: true } } },
          }),
          idpPrisma.userSession.findMany({
            where: { userId: params.userId },
            select: {
              id: true, device: true, browser: true, ipAddress: true, location: true,
              isActive: true, startedAt: true, lastActivityAt: true, expiresAt: true,
              platform: true, appVersion: true,
            },
            orderBy: { startedAt: "desc" },
          }),
          idpPrisma.passkey.findMany({
            where: { userId: params.userId },
            select: {
              id: true, name: true, transports: true, deviceType: true,
              backupEligible: true, backedUp: true, createdAt: true, lastUsedAt: true,
            },
          }),
          idpPrisma.accountContact.findMany({
            where: { userId: params.userId },
            select: {
              type: true, value: true, label: true, isPrimary: true,
              verifiedAt: true, createdAt: true,
            },
          }),
          Promise.all([
            prisma.customer.findMany({ where: { tenantId: params.tenantId, email: subject.email } }),
            prisma.vendor.findMany({ where: { tenantId: params.tenantId, email: subject.email } }),
            prisma.contact.findMany({ where: { tenantId: params.tenantId, email: subject.email } }),
            prisma.lead.findMany({ where: { tenantId: params.tenantId, email: subject.email } }),
            prisma.employee.findMany({ where: { tenantId: params.tenantId, email: subject.email } }),
            prisma.applicant.findMany({ where: { tenantId: params.tenantId, email: subject.email } }),
            prisma.customerPortalUser.findMany({ where: { tenantId: params.tenantId, email: subject.email } }),
            prisma.vendorPortalUser.findMany({ where: { tenantId: params.tenantId, email: subject.email } }),
            prisma.pOSLoyaltyMember.findMany({ where: { tenantId: params.tenantId, email: subject.email } }),
          ]),
        ]);
        const [customers, vendors, businessContacts, leads, employees, applicants, customerPortalUsers, vendorPortalUsers, loyaltyMembers] = subjectRecords;
        const data = {
          schemaVersion: "unierp.subject-export.v1",
          generatedAt: new Date().toISOString(),
          exportId: job.id,
          tenant,
          account: user,
          profile,
          connectedIdentities: identities,
          roles: roles.map((membership) => ({
            name: membership.role.name,
            description: membership.role.description,
            assignedAt: membership.assignedAt,
          })),
          sessions,
          passkeys,
          verifiedContacts: contacts,
          businessSubjectRecords: {
            customers,
            vendors,
            contacts: businessContacts,
            leads,
            employees,
            applicants,
            customerPortalUsers,
            vendorPortalUsers,
            loyaltyMembers,
          },
        };
        const businessRecordCount = subjectRecords.reduce((total, records) => total + records.length, 0);
        const recordCount = identities.length + roles.length + sessions.length + passkeys.length + contacts.length + businessRecordCount + 2;
        await prisma.dataExportJob.update({
          where: { id: job.id },
          data: { status: "COMPLETE", completedAt: new Date(), recordCount },
        });
        return { job, data };
      },
    );
    await emitAuthAudit({
      tenantId: params.tenantId,
      userId: params.userId,
      action: "SUBJECT_DATA_EXPORTED",
      entityType: "DataExportJob",
      entityId: result.job.id,
      changes: { format: "JSON", expiresAt: expiresAt.toISOString() },
    });
    return { jobId: result.job.id, expiresAt, data: result.data };
  }

  async requestAccountDeletion(params: {
    userId: string;
    tenantId: string;
    sid: string;
    reason?: string;
  }) {
    await this.requireFreshSession(params.userId, params.tenantId, params.sid);
    const eligibleAt = new Date(Date.now() + ERASURE_COOLING_OFF_MS);
    const request = await runWithTenantSession(
      { tenantId: params.tenantId, userId: params.userId },
      async () => {
        const [user, existing, memberships] = await Promise.all([
          idpPrisma.user.findUnique({ where: { id: params.userId } }),
          prisma.dataErasureRequest.findFirst({
            where: { tenantId: params.tenantId, requestedBy: params.userId, status: "PENDING" },
          }),
          idpPrisma.userRole.findMany({
            where: { role: { tenantId: params.tenantId, name: { in: OWNER_ROLE_NAMES } } },
            select: { userId: true, role: { select: { name: true } } },
          }),
        ]);
        if (!user) throw new UnauthorizedException("Account not found.");
        if (existing) throw new BadRequestException("An account-deletion request is already pending.");
        const ownerIds = new Set(memberships.map((membership) => membership.userId));
        if (ownerIds.has(params.userId) && ownerIds.size <= 1) {
          throw new BadRequestException(
            "Transfer organization ownership before requesting deletion of the last owner account.",
          );
        }
        return prisma.dataErasureRequest.create({
          data: {
            tenantId: params.tenantId,
            requestedBy: params.userId,
            subjectEmail: user.email,
            subjectName: `${user.firstName} ${user.lastName}`.trim() || null,
            status: "PENDING",
            entityTypes: [
              "User", "Customer", "Vendor", "Contact", "Lead", "Employee",
              "Applicant", "CustomerPortalUser", "VendorPortalUser", "POSLoyaltyMember",
            ],
            eligibleAt,
            requestReason: params.reason?.trim().slice(0, 500) || null,
          },
          select: { id: true, status: true, createdAt: true, eligibleAt: true },
        });
      },
    );
    await emitAuthAudit({
      tenantId: params.tenantId,
      userId: params.userId,
      action: "ACCOUNT_DELETION_REQUESTED",
      entityType: "DataErasureRequest",
      entityId: request.id,
      changes: { eligibleAt: request.eligibleAt?.toISOString() },
    });
    return request;
  }

  async cancelAccountDeletion(params: {
    userId: string;
    tenantId: string;
    sid: string;
    requestId: string;
  }) {
    await this.requireFreshSession(params.userId, params.tenantId, params.sid);
    const cancelledAt = new Date();
    const updated = await runWithTenantSession(
      { tenantId: params.tenantId, userId: params.userId },
      () => prisma.dataErasureRequest.updateMany({
        where: {
          id: params.requestId,
          tenantId: params.tenantId,
          requestedBy: params.userId,
          status: "PENDING",
          erasedAt: null,
        },
        data: {
          status: "CANCELLED",
          cancelledAt,
          cancellationReason: "Cancelled by the account holder during the cooling-off period.",
        },
      }),
    );
    if (updated.count !== 1) throw new BadRequestException("Pending deletion request not found.");
    await emitAuthAudit({
      tenantId: params.tenantId,
      userId: params.userId,
      action: "ACCOUNT_DELETION_CANCELLED",
      entityType: "DataErasureRequest",
      entityId: params.requestId,
    });
    return { id: params.requestId, status: "CANCELLED", cancelledAt };
  }

  private async requireFreshSession(userId: string, tenantId: string, sid: string) {
    const session = await runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.userSession.findUnique({ where: { id: sid } }),
    );
    if (
      !session || !session.isActive || session.userId !== userId ||
      session.tenantId !== tenantId ||
      session.startedAt.getTime() < Date.now() - RECENT_AUTH_MS
    ) {
      throw new UnauthorizedException("Recent authentication is required for this account action.");
    }
  }
}
