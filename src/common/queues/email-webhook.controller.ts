import { createHash, createHmac, timingSafeEqual } from "crypto";
import { BadRequestException, Controller, Headers, Post, Req, UnauthorizedException } from "@nestjs/common";
import type { Request } from "express";
import { EmailDeliveryOperationsService } from "./email-delivery-operations.service";
import { emailWebhookEvents } from "./email.metrics";
import { Public } from "../decorators/public.decorator";

type RawRequest = Request & { rawBody?: Buffer };

@Public("Email provider webhooks verify a timestamped signature or shared-secret authentication before ingestion")
@Controller("email/webhooks")
export class EmailWebhookController {
  constructor(private readonly operations: EmailDeliveryOperationsService) {}

  @Post("resend")
  async resend(
    @Req() request: RawRequest,
    @Headers("svix-id") eventId?: string,
    @Headers("svix-timestamp") timestamp?: string,
    @Headers("svix-signature") signature?: string,
  ) {
    const raw = requireRawBody(request);
    verifyResend(raw, { eventId, timestamp, signature });
    const payload = parseJson(raw);
    const type = stringField(payload.type);
    const data = objectField(payload.data);
    const providerMessageId = stringField(data.email_id || data.id);
    if (!type || !providerMessageId || !eventId) throw new BadRequestException("Invalid Resend event");

    const mapped = mapResend(type);
    const result = await this.operations.ingest({
      provider: "resend",
      providerEventId: eventId,
      providerMessageId,
      type,
      status: mapped.status,
      suppressReason: mapped.suppressReason,
      reason: stringField(objectField(data.bounce).message || data.reason || data.error),
      occurredAt: parseDate(payload.created_at),
    });
    emailWebhookEvents.inc({ provider: "resend", result: result.toLowerCase(), type });
    return { accepted: true, result };
  }

  @Post("brevo")
  async brevo(@Req() request: RawRequest, @Headers("authorization") authorization?: string) {
    const raw = requireRawBody(request);
    verifyBrevo(authorization);
    const payload = parseJson(raw);
    const event = stringField(payload.event);
    const providerMessageId = stringField(payload["message-id"] || payload.messageId);
    if (!event || !providerMessageId) throw new BadRequestException("Invalid Brevo event");

    const mapped = mapBrevo(event);
    const providerEventId = createHash("sha256").update(raw).digest("hex");
    const result = await this.operations.ingest({
      provider: "brevo",
      providerEventId,
      providerMessageId,
      type: event,
      status: mapped.status,
      suppressReason: mapped.suppressReason,
      reason: stringField(payload.reason || payload.description),
      occurredAt: parseUnixDate(payload.ts_event || payload.ts_epoch || payload.ts),
    });
    emailWebhookEvents.inc({ provider: "brevo", result: result.toLowerCase(), type: event });
    return { accepted: true, result };
  }
}

function verifyResend(
  raw: Buffer,
  headers: { eventId?: string; timestamp?: string; signature?: string },
): void {
  const secret = process.env.RESEND_WEBHOOK_SECRET;
  if (!secret || !headers.eventId || !headers.timestamp || !headers.signature) {
    throw new UnauthorizedException("Missing Resend webhook authentication");
  }
  const epoch = Number(headers.timestamp);
  if (!Number.isFinite(epoch) || Math.abs(Date.now() / 1000 - epoch) > 300) {
    throw new UnauthorizedException("Expired Resend webhook timestamp");
  }
  const keyText = secret.startsWith("whsec_") ? secret.slice(6) : secret;
  let key: Buffer;
  try {
    key = Buffer.from(keyText, "base64");
  } catch {
    throw new UnauthorizedException("Invalid Resend webhook secret");
  }
  const expected = createHmac("sha256", key)
    .update(`${headers.eventId}.${headers.timestamp}.${raw.toString("utf8")}`)
    .digest();
  const valid = headers.signature.split(" ").some((candidate) => {
    const encoded = candidate.startsWith("v1,") ? candidate.slice(3) : "";
    const supplied = Buffer.from(encoded, "base64");
    return supplied.length === expected.length && timingSafeEqual(supplied, expected);
  });
  if (!valid) throw new UnauthorizedException("Invalid Resend webhook signature");
}

function verifyBrevo(authorization?: string): void {
  const secret = process.env.BREVO_WEBHOOK_SECRET;
  if (!secret || !authorization) throw new UnauthorizedException("Missing Brevo webhook authentication");
  const expected = Buffer.from(`Basic ${Buffer.from(`unierp:${secret}`).toString("base64")}`);
  const supplied = Buffer.from(authorization);
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new UnauthorizedException("Invalid Brevo webhook authentication");
  }
}

function requireRawBody(request: RawRequest): Buffer {
  if (!request.rawBody) throw new BadRequestException("Raw webhook body unavailable");
  return request.rawBody;
}

function parseJson(raw: Buffer): Record<string, unknown> {
  try {
    const parsed = JSON.parse(raw.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new BadRequestException("Invalid webhook JSON");
  }
}

function objectField(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function stringField(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function parseDate(value: unknown): Date {
  const parsed = typeof value === "string" ? new Date(value) : new Date();
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
}

function parseUnixDate(value: unknown): Date {
  const number = Number(value);
  if (!Number.isFinite(number)) return new Date();
  return new Date(number > 10_000_000_000 ? number : number * 1000);
}

function mapResend(type: string): { status: string; suppressReason?: string } {
  switch (type) {
    case "email.delivered": return { status: "DELIVERED" };
    case "email.bounced": return { status: "BOUNCED", suppressReason: "HARD_BOUNCE" };
    case "email.complained": return { status: "COMPLAINED", suppressReason: "COMPLAINT" };
    case "email.suppressed": return { status: "SUPPRESSED", suppressReason: "PROVIDER_SUPPRESSION" };
    case "email.failed": return { status: "FAILED" };
    case "email.delivery_delayed": return { status: "DELAYED" };
    case "email.opened": return { status: "OPENED" };
    case "email.clicked": return { status: "CLICKED" };
    default: return { status: "SENT" };
  }
}

function mapBrevo(type: string): { status: string; suppressReason?: string } {
  switch (type.toLowerCase()) {
    case "delivered": return { status: "DELIVERED" };
    case "hard_bounce": return { status: "BOUNCED", suppressReason: "HARD_BOUNCE" };
    case "spam":
    case "complaint": return { status: "COMPLAINED", suppressReason: "COMPLAINT" };
    case "invalid_email": return { status: "BOUNCED", suppressReason: "INVALID_ADDRESS" };
    case "blocked": return { status: "SUPPRESSED", suppressReason: "PROVIDER_BLOCK" };
    case "unsubscribed": return { status: "SUPPRESSED", suppressReason: "UNSUBSCRIBED" };
    case "soft_bounce":
    case "deferred": return { status: "DELAYED" };
    case "error": return { status: "FAILED" };
    case "opened": return { status: "OPENED" };
    case "click":
    case "clicked": return { status: "CLICKED" };
    default: return { status: "SENT" };
  }
}
