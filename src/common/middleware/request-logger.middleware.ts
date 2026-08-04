import { Request, Response, NextFunction } from "express";
import { pinoLogger } from "../services/logger.service";
import crypto from "crypto";

const REQUEST_ID_HEADER = "x-request-id";

export function requestLoggerMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const requestId =
    (req.headers[REQUEST_ID_HEADER] as string) || crypto.randomUUID();
  req.headers[REQUEST_ID_HEADER] = requestId;
  res.setHeader(REQUEST_ID_HEADER, requestId);

  const start = Date.now();
  const { method, url } = req;
  const tenantId =
    (req as any).user?.tenantId || req.headers["x-tenant-id"] || "anon";
  const userId = (req as any).user?.userId || "anon";

  res.on("finish", () => {
    const duration = Date.now() - start;
    const level =
      res.statusCode >= 500 ? "error" : res.statusCode >= 400 ? "warn" : "info";

    pinoLogger[level](
      {
        requestId,
        method,
        url,
        statusCode: res.statusCode,
        duration,
        tenantId,
        userId,
      },
      `${method} ${url} ${res.statusCode} ${duration}ms`,
    );
  });

  next();
}
