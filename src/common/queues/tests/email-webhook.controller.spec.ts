import { createHmac } from "crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EmailWebhookController } from "../email-webhook.controller";

describe("EmailWebhookController", () => {
  const operations = { ingest: vi.fn() };
  let controller: EmailWebhookController;

  beforeEach(() => {
    vi.unstubAllEnvs();
    operations.ingest.mockReset().mockResolvedValue("RECORDED");
    controller = new EmailWebhookController(operations as any);
  });
  afterEach(() => vi.unstubAllEnvs());

  it("verifies a Resend/Svix signature and maps a hard bounce to suppression", async () => {
    const key = Buffer.from("01234567890123456789012345678901");
    vi.stubEnv("RESEND_WEBHOOK_SECRET", `whsec_${key.toString("base64")}`);
    const eventId = "evt_resend_1";
    const timestamp = String(Math.floor(Date.now() / 1000));
    const rawBody = Buffer.from(JSON.stringify({
      type: "email.bounced",
      created_at: new Date().toISOString(),
      data: { email_id: "email_resend_1", bounce: { message: "Mailbox unavailable" } },
    }));
    const digest = createHmac("sha256", key)
      .update(`${eventId}.${timestamp}.${rawBody.toString("utf8")}`)
      .digest("base64");

    await expect(controller.resend({ rawBody } as any, eventId, timestamp, `v1,${digest}`))
      .resolves.toEqual({ accepted: true, result: "RECORDED" });
    expect(operations.ingest).toHaveBeenCalledWith(expect.objectContaining({
      provider: "resend",
      providerEventId: eventId,
      providerMessageId: "email_resend_1",
      status: "BOUNCED",
      suppressReason: "HARD_BOUNCE",
    }));
  });

  it("rejects an expired Resend replay even when its signature is valid", async () => {
    const key = Buffer.from("01234567890123456789012345678901");
    vi.stubEnv("RESEND_WEBHOOK_SECRET", `whsec_${key.toString("base64")}`);
    const eventId = "evt_old";
    const timestamp = String(Math.floor(Date.now() / 1000) - 301);
    const rawBody = Buffer.from('{"type":"email.delivered","data":{"email_id":"email_1"}}');
    const digest = createHmac("sha256", key)
      .update(`${eventId}.${timestamp}.${rawBody.toString("utf8")}`)
      .digest("base64");

    await expect(controller.resend({ rawBody } as any, eventId, timestamp, `v1,${digest}`))
      .rejects.toThrow(/expired/i);
    expect(operations.ingest).not.toHaveBeenCalled();
  });

  it("authenticates and deterministically deduplicates Brevo callbacks", async () => {
    vi.stubEnv("BREVO_WEBHOOK_SECRET", "brevo-webhook-secret");
    operations.ingest.mockResolvedValue("DUPLICATE");
    const rawBody = Buffer.from(JSON.stringify({
      event: "spam",
      "message-id": "brevo-message-1",
      ts_event: Math.floor(Date.now() / 1000),
    }));
    const authorization = `Basic ${Buffer.from("unierp:brevo-webhook-secret").toString("base64")}`;

    await expect(controller.brevo({ rawBody } as any, authorization))
      .resolves.toEqual({ accepted: true, result: "DUPLICATE" });
    expect(operations.ingest).toHaveBeenCalledWith(expect.objectContaining({
      provider: "brevo",
      providerMessageId: "brevo-message-1",
      status: "COMPLAINED",
      suppressReason: "COMPLAINT",
    }));
  });

  it("rejects unauthenticated Brevo callbacks", async () => {
    vi.stubEnv("BREVO_WEBHOOK_SECRET", "brevo-webhook-secret");
    await expect(controller.brevo({ rawBody: Buffer.from("{}") } as any, "Basic invalid"))
      .rejects.toThrow(/invalid/i);
    expect(operations.ingest).not.toHaveBeenCalled();
  });
});
