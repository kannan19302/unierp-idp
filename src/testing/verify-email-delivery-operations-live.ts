import { randomUUID } from "crypto";
import { idpPrisma, runWithTenantSession } from "@kannan19302/database";
import { EmailDeliveryOperationsService } from "../common/queues/email-delivery-operations.service";

async function main() {
  const tenantId = `email-proof-${randomUUID()}`;
  const recipient = `proof-${randomUUID()}@example.invalid`;
  const operations = new EmailDeliveryOperationsService();
  process.env.EMAIL_RECIPIENT_HASH_KEY ||= "live-proof-recipient-hmac-key-32-bytes-minimum";
  process.env.EMAIL_DAILY_TENANT_QUOTA = "1";
  process.env.EMAIL_CANARY_TENANT_ID = tenantId;
  process.env.EMAIL_CANARY_RECIPIENT = recipient;

  const firstJob = `job-${randomUUID()}`;
  const secondJob = `job-${randomUUID()}`;
  const deliveredMessage = `resend-${randomUUID()}`;
  const bouncedMessage = `resend-${randomUUID()}`;

  try {
    const firstReservation = await operations.reserve(tenantId, recipient, firstJob);
    const retryReservation = await operations.reserve(tenantId, recipient, firstJob);
    const quotaReservation = await operations.reserve(tenantId, recipient, secondJob);

    await operations.recordAccepted({
      tenantId,
      queueJobId: firstJob,
      provider: "resend",
      providerMessageId: deliveredMessage,
      recipient,
      template: "delivery-canary",
      isCanary: true,
      attemptedProviders: ["resend"],
    });
    const delivered = await operations.ingest({
      provider: "resend",
      providerEventId: `event-${randomUUID()}`,
      providerMessageId: deliveredMessage,
      type: "email.delivered",
      status: "DELIVERED",
      occurredAt: new Date(),
    });
    const replayEventId = `event-${randomUUID()}`;
    const replayInput = {
      provider: "resend" as const,
      providerEventId: replayEventId,
      providerMessageId: deliveredMessage,
      type: "email.opened",
      status: "OPENED",
      occurredAt: new Date(),
    };
    const replayFirst = await operations.ingest(replayInput);
    const replaySecond = await operations.ingest(replayInput);

    await operations.recordAccepted({
      tenantId,
      queueJobId: `bounce-${randomUUID()}`,
      provider: "resend",
      providerMessageId: bouncedMessage,
      recipient,
      attemptedProviders: ["resend"],
    });
    const suppressedEvent = await operations.ingest({
      provider: "resend",
      providerEventId: `event-${randomUUID()}`,
      providerMessageId: bouncedMessage,
      type: "email.bounced",
      status: "BOUNCED",
      suppressReason: "HARD_BOUNCE",
      occurredAt: new Date(),
    });
    const suppressedReservation = await operations.reserve(
      tenantId,
      recipient,
      `suppressed-${randomUUID()}`,
    );
    const readiness = await operations.canaryReadiness();

    const proof = await runWithTenantSession(
      { tenantId, userId: "email-live-proof" },
      async () => ({
        deliveryEvents: await idpPrisma.emailDeliveryEvent.count({ where: { tenantId } }),
        suppressions: await idpPrisma.emailSuppression.count({ where: { tenantId, active: true } }),
        usage: await idpPrisma.emailUsageDaily.findFirst({
          where: { tenantId },
          select: { reservedCount: true },
        }),
      }),
    );

    console.log(JSON.stringify({
      atomicReservation: firstReservation === "ALLOWED" && retryReservation === "ALLOWED",
      retryDidNotConsumeQuota: proof.usage?.reservedCount === 1,
      quotaEnforced: quotaReservation === "QUOTA",
      deliveryRecorded: delivered === "RECORDED",
      replayDeduplicated: replayFirst === "RECORDED" && replaySecond === "DUPLICATE",
      suppressionRecorded: suppressedEvent === "RECORDED" && proof.suppressions === 1,
      suppressedBeforeSend: suppressedReservation === "SUPPRESSED",
      canaryDelivered: readiness.status === "up",
      deliveryEvents: proof.deliveryEvents,
    }));
  } finally {
    await runWithTenantSession(
      { tenantId, userId: "email-live-proof-cleanup" },
      async () => {
        await idpPrisma.emailDeliveryEvent.deleteMany({ where: { tenantId } });
        await idpPrisma.emailDelivery.deleteMany({ where: { tenantId } });
        await idpPrisma.emailSuppression.deleteMany({ where: { tenantId } });
        await idpPrisma.emailSendReservation.deleteMany({ where: { tenantId } });
        await idpPrisma.emailUsageDaily.deleteMany({ where: { tenantId } });
      },
    );
    await idpPrisma.$disconnect();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
