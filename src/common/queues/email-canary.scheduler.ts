import { InjectQueue } from "@nestjs/bullmq";
import { Injectable, OnModuleInit } from "@nestjs/common";
import type { Queue } from "bullmq";
import { IDENTITY_EMAIL_QUEUE } from "./queue.constants";

/** A real low-volume delivery probe, disabled until a dedicated inbox exists. */
@Injectable()
export class EmailCanaryScheduler implements OnModuleInit {
  constructor(@InjectQueue(IDENTITY_EMAIL_QUEUE) private readonly queue: Queue) {}

  async onModuleInit(): Promise<void> {
    const to = process.env.EMAIL_CANARY_RECIPIENT;
    const tenantId = process.env.EMAIL_CANARY_TENANT_ID;
    if (!to || !tenantId) return;
    const every = positiveInteger(process.env.EMAIL_CANARY_INTERVAL_MINUTES, 360) * 60_000;
    await this.queue.add(
      "delivery-canary",
      {
        to,
        tenantId,
        subject: "UniERP transactional email delivery canary",
        body: "<p>Automated delivery probe. No action is required.</p>",
        template: "delivery-canary",
        isCanary: true,
      },
      {
        jobId: "identity-email-delivery-canary",
        repeat: { every },
        removeOnComplete: 20,
        removeOnFail: 50,
      },
    );
  }
}

function positiveInteger(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}
