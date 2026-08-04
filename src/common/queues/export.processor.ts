import { Processor, WorkerHost, OnWorkerEvent } from "@nestjs/bullmq";
import { Job } from "bullmq";
import { pinoLogger } from "../services/logger.service";
import { syncBackgroundJobStatus } from "./job-tracking.util";

interface ExportJobData {
  tenantId: string;
  userId: string;
  entity: string;
  format: "csv" | "xlsx" | "pdf";
  filters?: Record<string, unknown>;
  callbackUrl?: string;
}

@Processor("export")
export class ExportProcessor extends WorkerHost {
  async process(job: Job<ExportJobData>): Promise<{ fileUrl: string }> {
    const { tenantId, entity, format, userId } = job.data;

    pinoLogger.info(
      { jobId: job.id, tenantId, entity, format, queue: "export" },
      "Processing export job",
    );

    await job.updateProgress(10);

    // In production: query the database, generate the file, upload to S3
    // For now, generate a placeholder URL
    const timestamp = Date.now();
    const filename = `${entity}_export_${timestamp}.${format}`;
    const fileUrl = `/api/v1/storage/downloads/${filename}`;

    await job.updateProgress(50);

    // Simulate processing time proportional to data size
    await new Promise((resolve) => setTimeout(resolve, 100));

    await job.updateProgress(100);

    pinoLogger.info({ jobId: job.id, fileUrl, userId }, "Export completed");

    return { fileUrl };
  }

  /**
   * Keeps the `BackgroundJob` Prisma row (surfaced by the admin Background Jobs UI) in sync
   * with real BullMQ lifecycle events, correlated by `bullJobId`. See P1-1 in
   * .ai/ADMIN_MODULE_COMPLETION_REQUIREMENTS.md — previously these were unconnected systems.
   */
  @OnWorkerEvent("active")
  async onActive(job: Job<ExportJobData>) {
    await syncBackgroundJobStatus("export", String(job.id), {
      status: "ACTIVE",
    });
  }

  @OnWorkerEvent("completed")
  async onCompleted(job: Job<ExportJobData>, result: { fileUrl: string }) {
    await syncBackgroundJobStatus("export", String(job.id), {
      status: "COMPLETED",
      result,
    });
  }

  @OnWorkerEvent("failed")
  async onFailed(job: Job<ExportJobData> | undefined, error: Error) {
    if (!job) return;
    await syncBackgroundJobStatus("export", String(job.id), {
      status: "FAILED",
      error: error?.message ?? "Unknown error",
    });
  }
}
