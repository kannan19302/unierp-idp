import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { emitAuthAudit } from "../../common/audit/emit-auth-audit";
import { AuthService } from "./auth.service";

const RECENT_AUTH_MS = 10 * 60 * 1000;
const VERIFY_TTL_MS = 30 * 60 * 1000;
const MAX_CONTACTS = 5;
const emailSchema = z.string().trim().email().max(254);

type ConsumedContact = {
  tenant_id: string;
  user_id: string;
  contact_id: string;
};

@Injectable()
export class AccountContactService {
  constructor(private readonly auth: AuthService) {}

  async list(userId: string, tenantId: string) {
    return runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.accountContact.findMany({
        where: { userId },
        orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
        select: {
          id: true,
          type: true,
          value: true,
          label: true,
          isPrimary: true,
          verifiedAt: true,
          createdAt: true,
        },
      }),
    );
  }

  async addRecoveryEmail(params: {
    userId: string;
    tenantId: string;
    sid: string;
    email: string;
    label?: string;
  }) {
    await this.requireFreshSession(params.userId, params.tenantId, params.sid);
    const email = parseEmail(params.email);
    const label = sanitizeLabel(params.label);
    const { contact, token } = await runWithTenantSession(
      { tenantId: params.tenantId, userId: params.userId },
      async () => {
        const [user, count] = await Promise.all([
          idpPrisma.user.findUnique({ where: { id: params.userId } }),
          idpPrisma.accountContact.count({ where: { userId: params.userId } }),
        ]);
        if (!user) throw new UnauthorizedException("Account not found.");
        if (user.email.trim().toLowerCase() === email) {
          throw new BadRequestException("This is already your primary email.");
        }
        if (count >= MAX_CONTACTS) {
          throw new BadRequestException(`A maximum of ${MAX_CONTACTS} contact methods is allowed.`);
        }
        const contact = await idpPrisma.accountContact.create({
          data: {
            tenantId: params.tenantId,
            userId: params.userId,
            type: "EMAIL",
            value: email,
            normalizedValue: email,
            label,
            isPrimary: false,
          },
          select: { id: true, type: true, value: true, label: true, isPrimary: true, verifiedAt: true },
        }).catch((error: unknown) => {
          if (isUniqueConstraint(error)) {
            throw new BadRequestException("This contact email is already registered in the organization.");
          }
          throw error;
        });
        const token = await this.createVerification(params.userId, params.tenantId, contact.id);
        return { contact, token };
      },
    );
    await this.sendVerification(contact.value, params.tenantId, token);
    await emitAuthAudit({
      tenantId: params.tenantId,
      userId: params.userId,
      action: "ACCOUNT_CONTACT_ADDED",
      entityType: "AccountContact",
      entityId: contact.id,
      changes: { type: "EMAIL", label: contact.label, verified: false },
    });
    return contact;
  }

  async resendVerification(params: {
    userId: string;
    tenantId: string;
    sid: string;
    contactId: string;
  }) {
    await this.requireFreshSession(params.userId, params.tenantId, params.sid);
    const { contact, token } = await runWithTenantSession(
      { tenantId: params.tenantId, userId: params.userId },
      async () => {
        const contact = await idpPrisma.accountContact.findFirst({
          where: {
            id: params.contactId,
            userId: params.userId,
            isPrimary: false,
            verifiedAt: null,
          },
        });
        if (!contact) throw new BadRequestException("Unverified recovery email not found.");
        await idpPrisma.accountContactVerification.deleteMany({
          where: { contactId: contact.id, usedAt: null },
        });
        const token = await this.createVerification(params.userId, params.tenantId, contact.id);
        return { contact, token };
      },
    );
    await this.sendVerification(contact.value, params.tenantId, token);
    return { sent: true };
  }

  async verify(rawToken: string) {
    if (!/^[A-Za-z0-9_-]{40,64}$/.test(rawToken)) {
      throw new BadRequestException("Verification link is invalid or expired.");
    }
    const tokenHash = hashToken(rawToken);
    const rows = await prisma.$queryRaw<ConsumedContact[]>`
      SELECT * FROM auth_consume_account_contact_verification(${tokenHash})
    `;
    const consumed = rows[0];
    if (!consumed) throw new BadRequestException("Verification link is invalid or expired.");
    const contact = await runWithTenantSession(
      { tenantId: consumed.tenant_id, userId: consumed.user_id },
      () => idpPrisma.accountContact.findFirst({
        where: { id: consumed.contact_id, userId: consumed.user_id },
        select: { id: true, type: true, label: true, verifiedAt: true },
      }),
    );
    if (!contact?.verifiedAt) throw new BadRequestException("Contact verification could not be completed.");
    await emitAuthAudit({
      tenantId: consumed.tenant_id,
      userId: consumed.user_id,
      action: "ACCOUNT_CONTACT_VERIFIED",
      entityType: "AccountContact",
      entityId: consumed.contact_id,
      changes: { type: contact.type, label: contact.label },
    });
    return contact;
  }

  async remove(params: {
    userId: string;
    tenantId: string;
    sid: string;
    contactId: string;
  }) {
    await this.requireFreshSession(params.userId, params.tenantId, params.sid);
    const deleted = await runWithTenantSession(
      { tenantId: params.tenantId, userId: params.userId },
      () => idpPrisma.accountContact.deleteMany({
        where: { id: params.contactId, userId: params.userId, isPrimary: false },
      }),
    );
    if (deleted.count !== 1) {
      throw new BadRequestException("Recovery contact not found; the primary email cannot be removed here.");
    }
    await emitAuthAudit({
      tenantId: params.tenantId,
      userId: params.userId,
      action: "ACCOUNT_CONTACT_REMOVED",
      entityType: "AccountContact",
      entityId: params.contactId,
    });
    return { deleted: true };
  }

  private async createVerification(userId: string, tenantId: string, contactId: string) {
    const token = randomBytes(32).toString("base64url");
    await idpPrisma.accountContactVerification.create({
      data: {
        tenantId,
        userId,
        contactId,
        tokenHash: hashToken(token),
        expiresAt: new Date(Date.now() + VERIFY_TTL_MS),
      },
    });
    return token;
  }

  private async sendVerification(email: string, tenantId: string, token: string) {
    const issuer = (process.env.NEXTAUTH_URL || "http://localhost:3005").replace(/\/$/, "");
    const url = `${issuer}/oidc/account/contact/verify?token=${encodeURIComponent(token)}`;
    await this.auth.queueAccountEmail({
      to: email,
      tenantId,
      subject: "Verify your UniERP recovery email",
      body: `Verify this recovery email for your UniERP account. This link expires in 30 minutes:\n\n${url}\n\nIf you did not add this address, you can ignore this message.`,
    });
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
      throw new UnauthorizedException("Recent authentication is required to change contact methods.");
    }
  }
}

function parseEmail(value: string) {
  const result = emailSchema.safeParse(value);
  if (!result.success) throw new BadRequestException("Enter a valid recovery email address.");
  return result.data.toLowerCase();
}

function sanitizeLabel(value?: string) {
  const label = value?.trim().replace(/\s+/g, " ") || "Recovery email";
  if (label.length > 40) throw new BadRequestException("Contact label must be 40 characters or fewer.");
  return label;
}

function hashToken(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function isUniqueConstraint(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "P2002";
}
