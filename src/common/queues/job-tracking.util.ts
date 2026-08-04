import { Queue } from "bullmq";
import { idpPrisma, prisma } from "@unerp/database";

/**
 * Connects the admin "Background Jobs" UI (which reads the `BackgroundJob` Prisma table)
 * to real BullMQ queue state. Previously these were two unconnected systems: `admin/operations
 * .service.ts` only read/wrote `BackgroundJob` rows and nothing in `common/queues/*` ever
 * referenced that table (see .ai/ADMIN_MODULE_COMPLETION_REQUIREMENTS.md P1-1).
 *
 * `enqueueTrackedJob` adds a job to the given BullMQ queue AND creates a `BackgroundJob` row
 * with `bullJobId` set to the real `Job.id`, so the admin UI reflects real queue state and
 * `OperationsService.retryJobs` can re-enqueue by `queueName` using this same row.
 */
export async function enqueueTrackedJob(
  queue: Queue,
  params: {
    tenantId: string;
    jobType: string;
    payload: Record<string, unknown>;
    priority?: number;
  },
): Promise<{ bullJobId: string; backgroundJobId: string }> {
  const job = await queue.add(params.jobType, params.payload, {
    priority: params.priority,
  });

  const bullJobId = String(job.id);

  const backgroundJob = await prisma.backgroundJob.create({
    data: {
      tenantId: params.tenantId,
      queueName: queue.name,
      jobType: params.jobType,
      bullJobId,
      payload: params.payload as any,
      status: "PENDING",
      priority: params.priority ?? 0,
    },
  });

  return { bullJobId, backgroundJobId: backgroundJob.id };
}

/**
 * Updates the `BackgroundJob` row correlated with a real BullMQ job (by `bullJobId` +
 * `queueName`) when the processor's lifecycle hooks fire. No-op (does not throw) if no
 * matching row exists — legacy/unlinked jobs are tolerated by design.
 */
export async function syncBackgroundJobStatus(
  queueName: string,
  bullJobId: string,
  update: {
    status: "ACTIVE" | "COMPLETED" | "FAILED";
    result?: unknown;
    error?: string;
  },
): Promise<void> {
  const existing = await prisma.backgroundJob.findFirst({
    where: { queueName, bullJobId },
  });
  if (!existing) return;

  const now = new Date();
  await prisma.backgroundJob.update({
    where: { id: existing.id },
    data: {
      status: update.status,
      result: update.result !== undefined ? (update.result as any) : undefined,
      error: update.error,
      startedAt:
        update.status === "ACTIVE"
          ? (existing.startedAt ?? now)
          : existing.startedAt,
      completedAt:
        update.status === "COMPLETED" || update.status === "FAILED"
          ? now
          : existing.completedAt,
      attempts: { increment: update.status === "FAILED" ? 1 : 0 },
    },
  });
}
