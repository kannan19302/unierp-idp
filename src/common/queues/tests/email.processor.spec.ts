import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Job } from "bullmq";

const { sendMail, createTransport } = vi.hoisted(() => {
  const send = vi.fn();
  return {
    sendMail: send,
    createTransport: vi.fn(() => ({ sendMail: send })),
  };
});
vi.mock("nodemailer", () => ({
  default: { createTransport },
}));
vi.mock("../../services/logger.service", () => ({
  pinoLogger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));
vi.mock("../job-tracking.util", () => ({
  syncBackgroundJobStatus: vi.fn(),
}));

import { EmailProcessor } from "../email.processor";
import type { PlatformCredentialsService } from "../../platform-credentials/platform-credentials.service";

const deadLetterQueue = {
  add: vi.fn().mockResolvedValue(undefined),
};

function job(): Job<any> {
  return {
    id: "job-1",
    data: {
      to: "owner@example.com",
      tenantId: "tenant-1",
      subject: "Reset your password",
      body: "<p>Reset</p>",
    },
  } as Job<any>;
}

function credentials(values: Record<string, Record<string, string>>) {
  return {
    get: vi.fn(async (provider: string) => values[provider] ?? {}),
  } as unknown as PlatformCredentialsService;
}

describe("EmailProcessor", () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    sendMail.mockReset();
    createTransport.mockClear();
    deadLetterQueue.add.mockClear();
  });
  afterEach(() => vi.unstubAllGlobals());

  it("fails the job when delivery is not configured", async () => {
    const processor = new EmailProcessor(credentials({}));
    await expect(processor.process(job())).rejects.toThrow(/not configured/i);
  });

  it("uses Resend idempotently when configured", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue({ id: "resend-1" }),
    });
    vi.stubGlobal("fetch", fetchMock);
    const processor = new EmailProcessor(credentials({
      resend: { apiKey: "re_test", from: "UniERP <noreply@example.com>" },
    }));

    await expect(processor.process(job())).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.resend.com/emails",
      expect.objectContaining({
        headers: expect.objectContaining({ "idempotency-key": "unierp-email-job-1" }),
      }),
    );
  });

  it("falls back to Brevo when Resend rejects the message", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: "Too Many Requests",
        json: vi.fn().mockResolvedValue({ message: "provider quota exhausted" }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: vi.fn().mockResolvedValue({ messageId: "brevo-1" }),
      });
    vi.stubGlobal("fetch", fetchMock);
    const processor = new EmailProcessor(credentials({
      resend: { apiKey: "re_test", from: "noreply@example.com" },
      brevo: { apiKey: "brevo-test", from: "noreply@example.com" },
    }));

    await expect(processor.process(job())).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1]?.[0]).toBe("https://api.brevo.com/v3/smtp/email");
  });

  it("refuses a suppressed recipient before any provider call", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const operations = {
      reserve: vi.fn().mockResolvedValue("SUPPRESSED"),
      recordAccepted: vi.fn(),
    };
    const processor = new EmailProcessor(credentials({
      resend: { apiKey: "re_test", from: "noreply@example.com" },
    }), undefined, operations as any);

    await expect(processor.process(job())).rejects.toThrow(/suppressed/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("enforces the atomic tenant quota before any provider call", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const operations = {
      reserve: vi.fn().mockResolvedValue("QUOTA"),
      recordAccepted: vi.fn(),
    };
    const processor = new EmailProcessor(credentials({
      resend: { apiKey: "re_test", from: "noreply@example.com" },
    }), undefined, operations as any);

    await expect(processor.process(job())).rejects.toThrow(/quota exceeded/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not double-send when the provider accepted but ledger persistence fails", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue({ id: "resend-accepted" }),
    });
    vi.stubGlobal("fetch", fetchMock);
    const operations = {
      reserve: vi.fn().mockResolvedValue("ALLOWED"),
      recordAccepted: vi.fn().mockRejectedValue(new Error("database unavailable")),
    };
    const processor = new EmailProcessor(credentials({
      resend: { apiKey: "re_test", from: "noreply@example.com" },
      brevo: { apiKey: "brevo-test", from: "noreply@example.com" },
    }), undefined, operations as any);

    await expect(processor.process(job())).rejects.toThrow(/database unavailable/i);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("uses SMTP as the final fallback", async () => {
    sendMail.mockResolvedValue({ messageId: "smtp-1" });
    const processor = new EmailProcessor(credentials({
      smtp: { host: "smtp.example.com", port: "587", user: "user", password: "pass", from: "noreply@example.com" },
    }));

    await expect(processor.process(job())).resolves.toBeUndefined();
    expect(sendMail).toHaveBeenCalledWith(expect.objectContaining({ to: "owner@example.com" }));
  });

  it("allows unauthenticated Mailpit only outside production", async () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("SMTP_HOST", "mailpit");
    vi.stubEnv("SMTP_PORT", "1025");
    sendMail.mockResolvedValue({ messageId: "mailpit-1" });

    const processor = new EmailProcessor(credentials({}));
    await expect(processor.process(job())).resolves.toBeUndefined();
    expect(createTransport).toHaveBeenCalledWith(
      expect.objectContaining({ host: "mailpit", port: 1025 }),
    );
    expect(createTransport.mock.calls[0]?.[0]).not.toHaveProperty("auth");
  });

  it("retains only an exhausted job in the idempotent dead-letter queue", async () => {
    const processor = new EmailProcessor(credentials({}), deadLetterQueue as any);
    const failedJob = {
      ...job(),
      attemptsMade: 3,
      opts: { attempts: 3 },
    } as Job<any>;

    await processor.onFailed(failedJob, new Error("all providers unavailable"));

    expect(deadLetterQueue.add).toHaveBeenCalledWith(
      "identity-email-delivery-failed",
      expect.objectContaining({
        sourceJobId: "job-1",
        attemptsMade: 3,
        error: "all providers unavailable",
      }),
      expect.objectContaining({ jobId: "failed-job-1" }),
    );
  });

  it("does not dead-letter a job while retry attempts remain", async () => {
    const processor = new EmailProcessor(credentials({}), deadLetterQueue as any);
    const retryingJob = {
      ...job(),
      attemptsMade: 1,
      opts: { attempts: 3 },
    } as Job<any>;

    await processor.onFailed(retryingJob, new Error("temporary failure"));
    expect(deadLetterQueue.add).not.toHaveBeenCalled();
  });
});
