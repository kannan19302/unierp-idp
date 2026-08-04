import { Processor, WorkerHost, OnWorkerEvent } from "@nestjs/bullmq";
import { Job } from "bullmq";
import nodemailer, { type Transporter } from "nodemailer";
import { pinoLogger } from "../services/logger.service";
import { syncBackgroundJobStatus } from "./job-tracking.util";
import { PlatformCredentialsService } from "../platform-credentials/platform-credentials.service";

interface EmailJobData {
  to: string;
  subject: string;
  body: string;
  tenantId: string;
  template?: string;
  variables?: Record<string, string>;
}

@Processor("email")
export class EmailProcessor extends WorkerHost {
  constructor(
    private readonly platformCredentialsService?: PlatformCredentialsService,
  ) {
    super();
  }

  // Rebuilt on every call (not cached on the instance) — PlatformCredentialsService
  // has its own ~15s cache, so this stays cheap while letting an SMTP credential
  // saved from the SaaS Portal Settings UI take effect without a worker restart.
  private async getTransporter(): Promise<Transporter | null> {
    const creds = this.platformCredentialsService
      ? await this.platformCredentialsService.get("smtp")
      : {};

    const host = creds.host || process.env.SMTP_HOST;
    const user = creds.user || process.env.SMTP_USER;
    const pass = creds.password || process.env.SMTP_PASSWORD;
    if (!host || !user || !pass) {
      return null;
    }

    const port = Number(creds.port || process.env.SMTP_PORT) || 587;
    return nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: { user, pass },
    });
  }

  async process(job: Job<EmailJobData>): Promise<void> {
    const { to, subject, body, tenantId } = job.data;

    pinoLogger.info(
      { jobId: job.id, to, subject, tenantId, queue: "email" },
      "Processing email job",
    );

    const transporter = await this.getTransporter();
    if (!transporter) {
      pinoLogger.warn(
        { jobId: job.id },
        "SMTP not configured — email job skipped",
      );
      return;
    }

    const creds = this.platformCredentialsService
      ? await this.platformCredentialsService.get("smtp")
      : {};

    await transporter.sendMail({
      from:
        creds.from ||
        process.env.SMTP_FROM ||
        creds.user ||
        process.env.SMTP_USER,
      to,
      subject,
      html: body,
    });

    pinoLogger.info({ jobId: job.id, to, subject }, "Email sent successfully");
  }

  /**
   * Keeps the `BackgroundJob` Prisma row (surfaced by the admin Background Jobs UI) in sync
   * with real BullMQ lifecycle events, correlated by `bullJobId`. See P1-1 in
   * .ai/ADMIN_MODULE_COMPLETION_REQUIREMENTS.md — previously these were unconnected systems.
   */
  @OnWorkerEvent("active")
  async onActive(job: Job<EmailJobData>) {
    await syncBackgroundJobStatus("email", String(job.id), {
      status: "ACTIVE",
    });
  }

  @OnWorkerEvent("completed")
  async onCompleted(job: Job<EmailJobData>) {
    await syncBackgroundJobStatus("email", String(job.id), {
      status: "COMPLETED",
    });
  }

  @OnWorkerEvent("failed")
  async onFailed(job: Job<EmailJobData> | undefined, error: Error) {
    if (!job) return;
    await syncBackgroundJobStatus("email", String(job.id), {
      status: "FAILED",
      error: error?.message ?? "Unknown error",
    });
  }
}
