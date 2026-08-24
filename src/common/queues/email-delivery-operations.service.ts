import { createHmac, randomUUID } from "crypto";
import { Injectable } from "@nestjs/common";
import { idpPrisma, runWithTenantSession } from "@kannan19302/database";

export type EmailProvider = "resend" | "brevo" | "smtp";
export type EmailReservation = "ALLOWED" | "SUPPRESSED" | "QUOTA";

export interface DeliveryEventInput {
  provider: Exclude<EmailProvider, "smtp">;
  providerEventId: string;
  providerMessageId: string;
  type: string;
  status: string;
  occurredAt: Date;
  reason?: string;
  suppressReason?: string;
}

/** Durable, tenant-isolated control plane for transactional-email delivery. */
@Injectable()
export class EmailDeliveryOperationsService {
  hashRecipient(address: string): string {
    const key = process.env.EMAIL_RECIPIENT_HASH_KEY || process.env.PII_ENCRYPTION_KEY;
    if (!key) throw new Error("EMAIL_RECIPIENT_HASH_KEY is not configured");
    return createHmac("sha256", key).update(address.trim().toLowerCase()).digest("hex");
  }

  async reserve(tenantId: string, address: string, queueJobId: string): Promise<EmailReservation> {
    const quota = positiveInteger(process.env.EMAIL_DAILY_TENANT_QUOTA, 1000);
    const recipientHash = this.hashRecipient(address);
    const rows = await idpPrisma.$queryRaw<Array<{ result: EmailReservation }>>`
      SELECT email_reserve_send(${tenantId}, ${recipientHash}, ${queueJobId}, CAST(${quota} AS INTEGER)) AS result
    `;
    return rows[0]?.result ?? "QUOTA";
  }

  async recordAccepted(input: {
    tenantId: string;
    queueJobId: string;
    provider: EmailProvider;
    providerMessageId: string;
    recipient: string;
    template?: string;
    isCanary?: boolean;
    attemptedProviders: EmailProvider[];
  }): Promise<void> {
    await runWithTenantSession(
      { tenantId: input.tenantId, userId: "identity-email-worker" },
      () => idpPrisma.emailDelivery.upsert({
        where: {
          provider_providerMessageId: {
            provider: input.provider,
            providerMessageId: input.providerMessageId,
          },
        },
        create: {
          id: randomUUID(),
          tenantId: input.tenantId,
          queueJobId: input.queueJobId,
          provider: input.provider,
          providerMessageId: input.providerMessageId,
          recipientHash: this.hashRecipient(input.recipient),
          template: input.template,
          isCanary: input.isCanary ?? false,
          attemptedProviders: input.attemptedProviders,
        },
        update: {
          attemptedProviders: input.attemptedProviders,
        },
      }),
    );
  }

  async ingest(input: DeliveryEventInput): Promise<"RECORDED" | "DUPLICATE" | "UNKNOWN_DELIVERY"> {
    const matches = await idpPrisma.$queryRaw<Array<{ tenant_id: string; delivery_id: string }>>`
      SELECT * FROM email_lookup_delivery(${input.provider}, ${input.providerMessageId})
    `;
    const match = matches[0];
    if (!match) return "UNKNOWN_DELIVERY";

    return runWithTenantSession(
      { tenantId: match.tenant_id, userId: `email-webhook:${input.provider}` },
      async () => {
        const existing = await idpPrisma.emailDeliveryEvent.findUnique({
          where: {
            provider_providerEventId: {
              provider: input.provider,
              providerEventId: input.providerEventId,
            },
          },
          select: { id: true },
        });
        if (existing) return "DUPLICATE" as const;

        const reason = sanitiseReason(input.reason);
        await idpPrisma.$transaction(async (tx) => {
          await tx.$executeRaw`SELECT set_config('app.current_tenant_id', ${match.tenant_id}, true)`;
          await tx.emailDeliveryEvent.create({
            data: {
              id: randomUUID(),
              tenantId: match.tenant_id,
              deliveryId: match.delivery_id,
              provider: input.provider,
              providerEventId: input.providerEventId,
              providerMessageId: input.providerMessageId,
              type: input.type,
              reason,
              occurredAt: input.occurredAt,
            },
          });

          const delivery = await tx.emailDelivery.findUnique({
            where: { id: match.delivery_id },
            select: { lastEventAt: true, recipientHash: true },
          });
          if (delivery && (!delivery.lastEventAt || delivery.lastEventAt <= input.occurredAt)) {
            await tx.emailDelivery.update({
              where: { id: match.delivery_id },
              data: { status: input.status, lastEventAt: input.occurredAt },
            });
          }

          if (delivery && input.suppressReason) {
            await tx.emailSuppression.upsert({
              where: {
                tenantId_recipientHash: {
                  tenantId: match.tenant_id,
                  recipientHash: delivery.recipientHash,
                },
              },
              create: {
                id: randomUUID(),
                tenantId: match.tenant_id,
                recipientHash: delivery.recipientHash,
                reason: input.suppressReason,
                sourceProvider: input.provider,
                sourceEventId: input.providerEventId,
              },
              update: {
                active: true,
                expiresAt: null,
                reason: input.suppressReason,
                sourceProvider: input.provider,
                sourceEventId: input.providerEventId,
              },
            });
          }
        });
        return "RECORDED" as const;
      },
    );
  }

  async canaryReadiness(): Promise<{ status: "up" | "down" | "disabled"; detail: string }> {
    const tenantId = process.env.EMAIL_CANARY_TENANT_ID;
    const recipient = process.env.EMAIL_CANARY_RECIPIENT;
    if (!tenantId || !recipient) {
      return { status: "disabled", detail: "email canary is not configured" };
    }

    return runWithTenantSession(
      { tenantId, userId: "identity-email-readiness" },
      async () => {
        const latest = await idpPrisma.emailDelivery.findFirst({
          where: { tenantId, isCanary: true },
          orderBy: { createdAt: "desc" },
          select: { status: true, createdAt: true, lastEventAt: true },
        });
        if (!latest) return { status: "down" as const, detail: "no canary delivery recorded" };
        const ageMs = Date.now() - latest.createdAt.getTime();
        const maxAgeMs = positiveInteger(process.env.EMAIL_CANARY_MAX_AGE_MINUTES, 480) * 60_000;
        if (ageMs > maxAgeMs) return { status: "down" as const, detail: "email canary is stale" };
        if (!["DELIVERED", "OPENED", "CLICKED"].includes(latest.status)) {
          const graceMs = positiveInteger(process.env.EMAIL_CANARY_GRACE_MINUTES, 15) * 60_000;
          return ageMs <= graceMs
            ? { status: "up" as const, detail: `canary awaiting callback (${latest.status})` }
            : { status: "down" as const, detail: `canary not delivered (${latest.status})` };
        }
        return { status: "up" as const, detail: `delivered ${latest.lastEventAt?.toISOString()}` };
      },
    );
  }
}

function positiveInteger(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function sanitiseReason(value?: string): string | undefined {
  if (!value) return undefined;
  return value
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[recipient]")
    .replace(/[\r\n\t]+/g, " ")
    .slice(0, 500);
}
