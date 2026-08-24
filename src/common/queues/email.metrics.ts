import { Counter } from "prom-client";
import { metricsRegistry } from "../middleware/metrics.middleware";

export const emailProviderAttempts = new Counter({
  name: "identity_email_provider_attempts_total",
  help: "Transactional email provider attempts by outcome",
  labelNames: ["provider", "outcome"] as const,
  registers: [metricsRegistry],
});

export const emailPolicyDecisions = new Counter({
  name: "identity_email_policy_decisions_total",
  help: "Transactional email send reservation decisions",
  labelNames: ["decision"] as const,
  registers: [metricsRegistry],
});

export const emailWebhookEvents = new Counter({
  name: "identity_email_webhook_events_total",
  help: "Authenticated provider callback outcomes",
  labelNames: ["provider", "result", "type"] as const,
  registers: [metricsRegistry],
});
