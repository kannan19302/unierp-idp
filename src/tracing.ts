/**
 * OpenTelemetry distributed tracing bootstrap.
 *
 * MUST be imported first in `main.ts` (before any instrumented library) so the
 * auto-instrumentations can patch http/express/nestjs/prisma/ioredis as they
 * load. Tracing is opt-in: it only starts when `OTEL_EXPORTER_OTLP_ENDPOINT`
 * is set (the orchestrator injects it in staging/prod), so local/dev and tests
 * pay no overhead.
 */
import { NodeSDK } from "@opentelemetry/sdk-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { getNodeAutoInstrumentations } from "@opentelemetry/auto-instrumentations-node";
import { resourceFromAttributes } from "@opentelemetry/resources";
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
} from "@opentelemetry/semantic-conventions";

const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;

let sdk: NodeSDK | undefined;

if (endpoint) {
  sdk = new NodeSDK({
    resource: resourceFromAttributes({
      [ATTR_SERVICE_NAME]: "unerp-api",
      [ATTR_SERVICE_VERSION]: "0.0.1",
    }),
    traceExporter: new OTLPTraceExporter({
      url: `${endpoint.replace(/\/$/, "")}/v1/traces`,
    }),
    instrumentations: [
      getNodeAutoInstrumentations({
        // Filesystem spans are noisy and rarely useful.
        "@opentelemetry/instrumentation-fs": { enabled: false },
      }),
    ],
  });

  sdk.start();

  const shutdown = () => {
    void sdk?.shutdown().finally(() => process.exit(0));
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

export { sdk };
