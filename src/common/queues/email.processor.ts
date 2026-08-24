import { InjectQueue, Processor, WorkerHost, OnWorkerEvent } from "@nestjs/bullmq";
import { Optional } from "@nestjs/common";
import { Job, Queue } from "bullmq";
import nodemailer from "nodemailer";
import { pinoLogger } from "../services/logger.service";
import { syncBackgroundJobStatus } from "./job-tracking.util";
import { PlatformCredentialsService } from "../platform-credentials/platform-credentials.service";
import { IDENTITY_EMAIL_DLQ, IDENTITY_EMAIL_QUEUE } from "./queue.constants";
import { EmailDeliveryOperationsService } from "./email-delivery-operations.service";
import { emailPolicyDecisions, emailProviderAttempts } from "./email.metrics";

export interface EmailJobData {
  to: string;
  subject: string;
  body: string;
  tenantId: string;
  template?: string;
  variables?: Record<string, string>;
  isCanary?: boolean;
}

type DeliveryProvider = "resend" | "brevo" | "smtp";

interface ProviderConfig {
  provider: DeliveryProvider;
  values: Record<string, string>;
}

/** Transactional email with API-first delivery, SMTP fallback and real failure semantics. */
@Processor(IDENTITY_EMAIL_QUEUE)
export class EmailProcessor extends WorkerHost {
  constructor(
    private readonly platformCredentialsService?: PlatformCredentialsService,
    @Optional()
    @InjectQueue(IDENTITY_EMAIL_DLQ)
    private readonly deadLetterQueue?: Queue,
    @Optional()
    private readonly deliveryOperations?: EmailDeliveryOperationsService,
  ) {
    super();
  }

  async process(job: Job<EmailJobData>): Promise<void> {
    const { to, subject, body, tenantId } = job.data;
    const recipient = maskRecipient(to);
    const providers = await this.configuredProviders();

    pinoLogger.info(
      { jobId: job.id, recipient, tenantId, queue: IDENTITY_EMAIL_QUEUE, providers: providers.map((item) => item.provider) },
      "Processing transactional email",
    );

    if (providers.length === 0) {
      // Throwing is intentional: BullMQ now retries and ultimately marks the
      // tracked job FAILED instead of recording a skipped email as completed.
      throw new Error(
        "Outbound email is not configured. Configure Resend, Brevo, or SMTP in Platform Credentials.",
      );
    }

    if (this.deliveryOperations) {
      const reservation = await this.deliveryOperations.reserve(tenantId, to, String(job.id));
      emailPolicyDecisions.inc({ decision: reservation.toLowerCase() });
      if (reservation === "SUPPRESSED") {
        throw new Error("Recipient is suppressed after a permanent delivery failure or complaint");
      }
      if (reservation === "QUOTA") {
        throw new Error("Tenant transactional-email daily quota exceeded");
      }
    }

    const failures: string[] = [];
    const attemptedProviders: DeliveryProvider[] = [];
    for (const config of providers) {
      attemptedProviders.push(config.provider);
      let messageId: string;
      try {
        messageId = await this.deliver(config, job);
        emailProviderAttempts.inc({ provider: config.provider, outcome: "accepted" });
      } catch (error) {
        emailProviderAttempts.inc({ provider: config.provider, outcome: "failed" });
        const message = error instanceof Error ? error.message : String(error);
        failures.push(`${config.provider}: ${message}`);
        pinoLogger.warn(
          { jobId: job.id, recipient, provider: config.provider, error: message },
          "Email provider failed; trying fallback",
        );
        continue;
      }
      // Once a provider accepted the message, never attempt a second provider.
      // If ledger persistence fails BullMQ retries this job with the same
      // provider idempotency key and the same quota reservation.
      await this.deliveryOperations?.recordAccepted({
        tenantId,
        queueJobId: String(job.id),
        provider: config.provider,
        providerMessageId: messageId,
        recipient: to,
        template: job.data.template,
        isCanary: job.data.isCanary,
        attemptedProviders,
      });
      pinoLogger.info(
        { jobId: job.id, recipient, provider: config.provider, messageId },
        "Transactional email accepted by provider",
      );
      return;
    }

    throw new Error(`Every configured email provider failed (${failures.join("; ")})`);
  }

  private async configuredProviders(): Promise<ProviderConfig[]> {
    const credentials = async (provider: string): Promise<Record<string, string>> =>
      this.platformCredentialsService
        ? this.platformCredentialsService.get(provider)
        : {};
    const [resend, brevo, smtp] = await Promise.all([
      credentials("resend"),
      credentials("brevo"),
      credentials("smtp"),
    ]);

    const candidates: ProviderConfig[] = [];
    const resendKey = resend["apiKey"] || process.env.RESEND_API_KEY;
    if (resendKey) candidates.push({ provider: "resend", values: { ...resend, apiKey: resendKey } });
    const brevoKey = brevo["apiKey"] || process.env.BREVO_API_KEY;
    if (brevoKey) candidates.push({ provider: "brevo", values: { ...brevo, apiKey: brevoKey } });
    const smtpValues = {
      ...smtp,
      host: smtp["host"] || process.env.SMTP_HOST || "",
      user: smtp["user"] || process.env.SMTP_USER || "",
      password: smtp["password"] || process.env.SMTP_PASSWORD || "",
      port: smtp["port"] || process.env.SMTP_PORT || "587",
    };
    const smtpAuthConfigured = Boolean(smtpValues.user && smtpValues.password);
    const localUnauthenticatedSmtp =
      process.env.NODE_ENV !== "production" && smtpValues.host === "mailpit";
    if (smtpValues.host && (smtpAuthConfigured || localUnauthenticatedSmtp)) {
      candidates.push({ provider: "smtp", values: smtpValues });
    }

    const preferred = process.env.EMAIL_PROVIDER?.toLowerCase();
    if (preferred && preferred !== "auto") {
      candidates.sort((left, right) =>
        left.provider === preferred ? -1 : right.provider === preferred ? 1 : 0,
      );
    }
    return candidates;
  }

  private async deliver(config: ProviderConfig, job: Job<EmailJobData>): Promise<string> {
    if (config.provider === "resend") return this.sendWithResend(config.values, job);
    if (config.provider === "brevo") return this.sendWithBrevo(config.values, job);
    return this.sendWithSmtp(config.values, job);
  }

  private async sendWithResend(values: Record<string, string>, job: Job<EmailJobData>): Promise<string> {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        authorization: `Bearer ${values["apiKey"] ?? ""}`,
        "content-type": "application/json",
        "idempotency-key": `unierp-email-${job.id}`,
      },
      body: JSON.stringify({
        from: sender(values.from),
        to: [job.data.to],
        subject: job.data.subject,
        html: job.data.body,
      }),
      signal: AbortSignal.timeout(15_000),
    });
    const result = await response.json().catch(() => ({})) as { id?: string; message?: string };
    if (!response.ok) throw new Error(`${response.status} ${result.message || response.statusText}`);
    return result.id || `resend-${job.id}`;
  }

  private async sendWithBrevo(values: Record<string, string>, job: Job<EmailJobData>): Promise<string> {
    const from = parseSender(sender(values.from));
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "api-key": values["apiKey"] ?? "",
        "content-type": "application/json",
        "idempotency-key": `unierp-email-${job.id}`,
      },
      body: JSON.stringify({
        sender: from,
        to: [{ email: job.data.to }],
        subject: job.data.subject,
        htmlContent: job.data.body,
      }),
      signal: AbortSignal.timeout(15_000),
    });
    const result = await response.json().catch(() => ({})) as { messageId?: string; message?: string };
    if (!response.ok) throw new Error(`${response.status} ${result.message || response.statusText}`);
    return result.messageId || `brevo-${job.id}`;
  }

  private async sendWithSmtp(values: Record<string, string>, job: Job<EmailJobData>): Promise<string> {
    const port = Number(values.port) || 587;
    const transporter = nodemailer.createTransport({
      host: values["host"],
      port,
      secure: port === 465,
      ...(values["user"] && values["password"]
        ? { auth: { user: values["user"], pass: values["password"] } }
        : {}),
    });
    const result = await transporter.sendMail({
      from: sender(values["from"] || values["user"]),
      to: job.data.to,
      subject: job.data.subject,
      html: job.data.body,
    });
    return result.messageId;
  }

  @OnWorkerEvent("active")
  async onActive(job: Job<EmailJobData>) {
    await syncBackgroundJobStatus(IDENTITY_EMAIL_QUEUE, String(job.id), { status: "ACTIVE" });
  }

  @OnWorkerEvent("completed")
  async onCompleted(job: Job<EmailJobData>) {
    await syncBackgroundJobStatus(IDENTITY_EMAIL_QUEUE, String(job.id), { status: "COMPLETED" });
  }

  @OnWorkerEvent("failed")
  async onFailed(job: Job<EmailJobData> | undefined, error: Error) {
    if (!job) return;
    const errorMessage = error?.message ?? "Unknown error";
    await syncBackgroundJobStatus(IDENTITY_EMAIL_QUEUE, String(job.id), {
      status: "FAILED",
      error: errorMessage,
    });

    const maximumAttempts = job.opts.attempts ?? 1;
    if (job.attemptsMade < maximumAttempts) return;

    const recipient = maskRecipient(job.data.to);
    try {
      await this.deadLetterQueue?.add(
        "identity-email-delivery-failed",
        {
          ...job.data,
          sourceJobId: String(job.id),
          sourceQueue: IDENTITY_EMAIL_QUEUE,
          failedAt: new Date().toISOString(),
          attemptsMade: job.attemptsMade,
          error: errorMessage,
        },
        {
          // Worker failure events can be redelivered during Redis/network
          // recovery. A stable id prevents duplicate operator incidents.
          jobId: `failed-${String(job.id).replace(/[^a-zA-Z0-9_-]/g, "-")}`,
          removeOnComplete: false,
          removeOnFail: false,
        },
      );
      pinoLogger.error(
        {
          event: "IDENTITY_EMAIL_DLQ_ENQUEUED",
          sourceJobId: job.id,
          tenantId: job.data.tenantId,
          recipient,
          attemptsMade: job.attemptsMade,
          error: errorMessage,
        },
        "Transactional email exhausted retries and entered the dead-letter queue",
      );
    } catch (deadLetterError) {
      pinoLogger.error(
        {
          event: "IDENTITY_EMAIL_DLQ_ENQUEUE_FAILED",
          sourceJobId: job.id,
          tenantId: job.data.tenantId,
          recipient,
          error: deadLetterError instanceof Error ? deadLetterError.message : String(deadLetterError),
        },
        "Could not retain exhausted transactional email in the dead-letter queue",
      );
    }
  }
}

function sender(configured?: string): string {
  return configured || process.env.EMAIL_FROM || process.env.SMTP_FROM || "UniERP <noreply@kannan19302.dev>";
}

function parseSender(value: string): { email: string; name?: string } {
  const match = value.match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
  return match
    ? { name: match[1] || "UniERP", email: match[2]! }
    : { name: "UniERP", email: value };
}

function maskRecipient(value: string): string {
  const [local, domain] = value.split("@");
  return domain ? `${local?.slice(0, 2) || "**"}***@${domain}` : "invalid-recipient";
}
