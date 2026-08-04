import { Request, Response, NextFunction } from "express";
import {
  Registry,
  Counter,
  Histogram,
  collectDefaultMetrics,
} from "prom-client";

export const metricsRegistry = new Registry();

collectDefaultMetrics({ register: metricsRegistry });

const httpRequestsTotal = new Counter({
  name: "http_requests_total",
  help: "Total HTTP requests",
  labelNames: ["method", "route", "status_code", "tenant_id"] as const,
  registers: [metricsRegistry],
});

const httpRequestDuration = new Histogram({
  name: "http_request_duration_seconds",
  help: "HTTP request duration in seconds",
  labelNames: ["method", "route", "status_code"] as const,
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [metricsRegistry],
});

function normalizeRoute(url: string): string {
  return (
    url
      .replace(/\/api\/v1/, "")
      .replace(
        /\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
        "/:id",
      )
      .replace(/\/\d+/g, "/:id")
      .split("?")[0] || "/"
  );
}

export function metricsMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const start = process.hrtime.bigint();

  res.on("finish", () => {
    const durationNs = Number(process.hrtime.bigint() - start);
    const durationSec = durationNs / 1e9;
    const route = normalizeRoute(req.originalUrl || req.url);
    const tenantId = (req as any).user?.tenantId || "anon";

    httpRequestsTotal.inc({
      method: req.method,
      route,
      status_code: String(res.statusCode),
      tenant_id: tenantId,
    });

    httpRequestDuration.observe(
      { method: req.method, route, status_code: String(res.statusCode) },
      durationSec,
    );
  });

  next();
}
