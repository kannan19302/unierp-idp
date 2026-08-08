import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  enqueueTrackedJob,
  syncBackgroundJobStatus,
} from "../job-tracking.util";

const { mockBackgroundJob } = vi.hoisted(() => ({
  mockBackgroundJob: {
    create: vi.fn(),
    findFirst: vi.fn(),
    update: vi.fn(),
  },
}));

vi.mock("@kannan19302/database", () => ({
  prisma: {
    backgroundJob: mockBackgroundJob,
  },
}));

describe("job-tracking.util (P1-1: BackgroundJob <-> real BullMQ correlation)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("enqueueTrackedJob", () => {
    it("adds the job to the real BullMQ queue and creates a correlated BackgroundJob row with bullJobId set", async () => {
      const fakeQueue = {
        add: vi.fn().mockResolvedValue({ id: "bull-123" }),
        name: "email",
      } as any;
      mockBackgroundJob.create.mockResolvedValue({ id: "bg-1" });

      const result = await enqueueTrackedJob(fakeQueue, {
        tenantId: "tenant-a",
        jobType: "send-invoice-email",
        payload: { to: "x@y.com" },
        priority: 3,
      });

      expect(fakeQueue.add).toHaveBeenCalledWith(
        "send-invoice-email",
        { to: "x@y.com" },
        { priority: 3 },
      );
      expect(mockBackgroundJob.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          tenantId: "tenant-a",
          queueName: "email",
          jobType: "send-invoice-email",
          bullJobId: "bull-123",
          status: "PENDING",
        }),
      });
      expect(result).toEqual({
        bullJobId: "bull-123",
        backgroundJobId: "bg-1",
      });
    });
  });

  describe("syncBackgroundJobStatus", () => {
    it("updates the correlated row by queueName + bullJobId when the processor reports completion", async () => {
      mockBackgroundJob.findFirst.mockResolvedValue({
        id: "bg-1",
        startedAt: null,
        completedAt: null,
      });
      mockBackgroundJob.update.mockResolvedValue({});

      await syncBackgroundJobStatus("email", "bull-123", {
        status: "COMPLETED",
        result: { ok: true },
      });

      expect(mockBackgroundJob.findFirst).toHaveBeenCalledWith({
        where: { queueName: "email", bullJobId: "bull-123" },
      });
      expect(mockBackgroundJob.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: "bg-1" },
          data: expect.objectContaining({ status: "COMPLETED" }),
        }),
      );
    });

    it("is a safe no-op when no BackgroundJob row correlates to the given bullJobId (legacy/unlinked jobs)", async () => {
      mockBackgroundJob.findFirst.mockResolvedValue(null);

      await expect(
        syncBackgroundJobStatus("export", "unknown-job", {
          status: "FAILED",
          error: "boom",
        }),
      ).resolves.toBeUndefined();

      expect(mockBackgroundJob.update).not.toHaveBeenCalled();
    });

    it("records the error message on FAILED status", async () => {
      mockBackgroundJob.findFirst.mockResolvedValue({
        id: "bg-2",
        startedAt: new Date(),
        completedAt: null,
      });
      mockBackgroundJob.update.mockResolvedValue({});

      await syncBackgroundJobStatus("export", "bull-999", {
        status: "FAILED",
        error: "disk full",
      });

      expect(mockBackgroundJob.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            status: "FAILED",
            error: "disk full",
          }),
        }),
      );
    });
  });
});
