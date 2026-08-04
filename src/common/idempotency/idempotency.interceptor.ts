/**
 * Global Idempotency-Key interceptor (Foundation Roadmap Track G.3).
 *
 * Opt-in per request: state-changing requests (POST/PUT/PATCH/DELETE) that
 * send an `Idempotency-Key` header get exactly-once semantics per
 * (tenant, key):
 *
 *   - first request claims the key and executes; the response is stored
 *     (TTL 24h) and returned;
 *   - a concurrent duplicate gets 409 IDEMPOTENCY_IN_FLIGHT;
 *   - a later duplicate with the SAME payload gets the stored response with
 *     `Idempotency-Replayed: true`;
 *   - the same key with a DIFFERENT payload gets 422 IDEMPOTENCY_KEY_REUSED;
 *   - a handler failure releases the claim so the client may retry.
 *
 * Requests without the header are untouched.
 */
import {
  CallHandler,
  ConflictException,
  ExecutionContext,
  Injectable,
  NestInterceptor,
  UnprocessableEntityException,
} from "@nestjs/common";
import type { Request, Response } from "express";
import { createHash } from "node:crypto";
import { Observable, from, of, switchMap } from "rxjs";
import type { IdempotencyStore } from "./idempotency.store";

export const IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60;
const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const KEY_PATTERN = /^[A-Za-z0-9_-]{8,128}$/;

interface TenantRequest extends Request {
  user?: { tenantId?: string; sub?: string; id?: string; userId?: string };
}

@Injectable()
export class IdempotencyInterceptor implements NestInterceptor {
  constructor(private readonly store: IdempotencyStore) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<TenantRequest>();
    const clientKey = request.headers["idempotency-key"];

    if (
      !clientKey ||
      typeof clientKey !== "string" ||
      !MUTATING_METHODS.has(request.method)
    ) {
      return next.handle();
    }
    if (!KEY_PATTERN.test(clientKey)) {
      throw new UnprocessableEntityException({
        message: "Idempotency-Key must be 8-128 chars of [A-Za-z0-9_-]",
        code: "IDEMPOTENCY_KEY_INVALID",
      });
    }

    // Issue #25: keys are scoped to the authenticated PRINCIPAL
    // (tenant + user), so one user can never receive another user's stored
    // response, and unauthenticated requests never participate (anonymous
    // flows keep their own bespoke idempotency, e.g. checkout).
    const tenantId = request.user?.tenantId;
    const principalId =
      request.user?.sub ?? request.user?.id ?? request.user?.userId;
    if (!tenantId || !principalId) {
      return next.handle();
    }
    const storageKey = `idem:${tenantId}:${principalId}:${clientKey}`;
    const requestHash = createHash("sha256")
      .update(request.method)
      .update("\n")
      .update(request.originalUrl ?? request.url)
      .update("\n")
      .update(JSON.stringify(request.body ?? null))
      .digest("hex");

    return from(
      this.store.claim(storageKey, requestHash, IDEMPOTENCY_TTL_SECONDS),
    ).pipe(
      switchMap((existing) => {
        if (existing) {
          if (existing.requestHash !== requestHash) {
            throw new UnprocessableEntityException({
              message:
                "Idempotency-Key was already used for a different request",
              code: "IDEMPOTENCY_KEY_REUSED",
            });
          }
          if (existing.state === "in-flight") {
            throw new ConflictException({
              message:
                "A request with this Idempotency-Key is still being processed",
              code: "IDEMPOTENCY_IN_FLIGHT",
            });
          }
          const response = context.switchToHttp().getResponse<Response>();
          response.setHeader("Idempotency-Replayed", "true");
          response.status(existing.statusCode);
          return of(existing.body);
        }

        return next.handle().pipe(
          switchMap((body) => {
            const response = context.switchToHttp().getResponse<Response>();
            return from(
              this.store.complete(
                storageKey,
                {
                  state: "completed",
                  requestHash,
                  statusCode: response.statusCode,
                  body,
                },
                IDEMPOTENCY_TTL_SECONDS,
              ),
            ).pipe(switchMap(() => of(body)));
          }),
          // On handler error, release the claim then rethrow.
          (source) =>
            new Observable((subscriber) => {
              const subscription = source.subscribe({
                next: (value) => subscriber.next(value),
                complete: () => subscriber.complete(),
                error: (error) => {
                  void this.store
                    .release(storageKey)
                    .catch(() => undefined)
                    .then(() => subscriber.error(error));
                },
              });
              return () => subscription.unsubscribe();
            }),
        );
      }),
    );
  }
}
