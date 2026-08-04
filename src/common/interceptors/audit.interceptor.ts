import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from "@nestjs/common";
import { Observable, tap } from "rxjs";
import { idpPrisma, prisma } from "@unerp/database";
import { pinoLogger } from "../services/logger.service";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const ACTION_BY_METHOD: Record<string, string> = {
  POST: "CREATE",
  PUT: "UPDATE",
  PATCH: "UPDATE",
  DELETE: "DELETE",
};

interface RequestPrincipal {
  tenantId?: string;
  userId?: string;
}

/**
 * Coarse, always-on compliance audit log: records actor + tenant + action +
 * entity for every successful mutating request. This is distinct from the
 * field-level change history (`ChangeHistoryInterceptor`, opt-in via
 * `@TrackChanges`) — audit answers "who did what, when", change history answers
 * "what exactly changed".
 *
 * Best-effort and fire-and-forget: an audit failure never breaks the request.
 */
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = context.switchToHttp().getRequest();
    const method: string = req.method;

    if (!MUTATING_METHODS.has(method)) {
      return next.handle();
    }

    return next.handle().pipe(
      tap((result) => {
        // Don't block the response — record asynchronously.
        void this.record(req, method, result);
      }),
    );
  }

  private async record(
    req: {
      user?: RequestPrincipal;
      originalUrl?: string;
      url: string;
      params?: Record<string, string>;
      ip?: string;
      headers: Record<string, unknown>;
      body?: unknown;
    },
    method: string,
    result: unknown,
  ): Promise<void> {
    const user = req.user;
    if (!user?.tenantId || !user?.userId) {
      return; // unauthenticated or non-tenant context — nothing to attribute
    }

    try {
      const path = (req.originalUrl ?? req.url).split("?")[0] ?? "";
      const entityType = this.deriveEntityType(path);
      const entityId =
        req.params?.id ?? (result as { id?: string })?.id ?? "n/a";

      await prisma.auditLog.create({
        data: {
          tenantId: user.tenantId,
          userId: user.userId,
          action: ACTION_BY_METHOD[method] ?? method,
          entityType,
          entityId,
          changes: this.safeBody(req.body),
          ipAddress: req.ip ?? null,
          userAgent: (req.headers["user-agent"] as string) ?? null,
        },
      });
    } catch (err) {
      pinoLogger.warn({ err }, "audit log write failed");
    }
  }

  /** Turn `/api/v1/finance/invoices/123` into `finance.invoices`. */
  private deriveEntityType(path: string): string {
    const parts = path.split("/").filter(Boolean);
    const apiIdx = parts.indexOf("v1");
    const segments = apiIdx >= 0 ? parts.slice(apiIdx + 1) : parts;
    const named = segments.filter((s) => !/^[0-9a-f-]{8,}$/i.test(s));
    return named.slice(0, 2).join(".") || "unknown";
  }

  /** Store a bounded snapshot of the request body, never secrets. */
  private safeBody(body: unknown): object | undefined {
    if (!body || typeof body !== "object") return undefined;
    const redactKeys = ["password", "token", "secret", "apiKey", "key"];
    const clone: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(body as Record<string, unknown>)) {
      clone[k] = redactKeys.some((r) => k.toLowerCase().includes(r))
        ? "[redacted]"
        : v;
    }
    return clone;
  }
}
