import { describe, expect, it, vi } from "vitest";
import {
  ConflictException,
  UnprocessableEntityException,
} from "@nestjs/common";
import { firstValueFrom, of, throwError } from "rxjs";
import { IdempotencyInterceptor } from "./idempotency.interceptor";
import { InMemoryIdempotencyStore } from "./idempotency.store";

function makeContext(overrides: {
  method?: string;
  key?: string | undefined;
  tenantId?: string;
  userId?: string;
  anonymous?: boolean;
  body?: unknown;
  url?: string;
}) {
  const response = {
    statusCode: 201,
    headers: {} as Record<string, string>,
    setHeader(name: string, value: string) {
      this.headers[name] = value;
    },
    status(code: number) {
      this.statusCode = code;
      return this;
    },
  };
  const request = {
    method: overrides.method ?? "POST",
    headers:
      overrides.key === undefined ? {} : { "idempotency-key": overrides.key },
    user: overrides.anonymous
      ? undefined
      : {
          tenantId: overrides.tenantId ?? "tenant-a",
          id: overrides.userId ?? "user-1",
        },
    body: overrides.body ?? { amount: 100 },
    url: overrides.url ?? "/api/v1/orders",
    originalUrl: overrides.url ?? "/api/v1/orders",
  };
  return {
    context: {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => response,
      }),
    } as never,
    response,
  };
}

const KEY = "order-create-0001";

describe("IdempotencyInterceptor (Track G.3)", () => {
  it("passes through without the header and does not touch the store", async () => {
    const store = new InMemoryIdempotencyStore();
    const claim = vi.spyOn(store, "claim");
    const interceptor = new IdempotencyInterceptor(store);
    const { context } = makeContext({ key: undefined });
    const result = await firstValueFrom(
      interceptor.intercept(context, { handle: () => of("fresh") } as never),
    );
    expect(result).toBe("fresh");
    expect(claim).not.toHaveBeenCalled();
  });

  it("executes once and replays the stored response for the same key+payload", async () => {
    const store = new InMemoryIdempotencyStore();
    const interceptor = new IdempotencyInterceptor(store);
    const handler = vi.fn(() => of({ id: "ord-1" }));

    const first = makeContext({ key: KEY });
    expect(
      await firstValueFrom(
        interceptor.intercept(first.context, { handle: handler } as never),
      ),
    ).toEqual({ id: "ord-1" });

    const second = makeContext({ key: KEY });
    const replayed = await firstValueFrom(
      interceptor.intercept(second.context, { handle: handler } as never),
    );
    expect(replayed).toEqual({ id: "ord-1" });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(second.response.headers["Idempotency-Replayed"]).toBe("true");
    expect(second.response.statusCode).toBe(201);
  });

  it("rejects the same key with a different payload (422)", async () => {
    const store = new InMemoryIdempotencyStore();
    const interceptor = new IdempotencyInterceptor(store);
    const first = makeContext({ key: KEY, body: { amount: 100 } });
    await firstValueFrom(
      interceptor.intercept(first.context, { handle: () => of("ok") } as never),
    );

    const second = makeContext({ key: KEY, body: { amount: 999 } });
    await expect(
      firstValueFrom(
        interceptor.intercept(second.context, {
          handle: () => of("nope"),
        } as never),
      ),
    ).rejects.toThrow(UnprocessableEntityException);
  });

  it("rejects a concurrent duplicate while in flight (409)", async () => {
    const store = new InMemoryIdempotencyStore();
    const interceptor = new IdempotencyInterceptor(store);
    await store.claim(
      `idem:tenant-a:user-1:${KEY}`,
      hashOf("POST", "/api/v1/orders", { amount: 100 }),
      60,
    );

    const dup = makeContext({ key: KEY });
    await expect(
      firstValueFrom(
        interceptor.intercept(dup.context, { handle: () => of("x") } as never),
      ),
    ).rejects.toThrow(ConflictException);
  });

  it("releases the claim on handler error so a retry executes", async () => {
    const store = new InMemoryIdempotencyStore();
    const interceptor = new IdempotencyInterceptor(store);
    const failing = makeContext({ key: KEY });
    await expect(
      firstValueFrom(
        interceptor.intercept(failing.context, {
          handle: () => throwError(() => new Error("boom")),
        } as never),
      ),
    ).rejects.toThrow("boom");

    const retry = makeContext({ key: KEY });
    const result = await firstValueFrom(
      interceptor.intercept(retry.context, {
        handle: () => of("recovered"),
      } as never),
    );
    expect(result).toBe("recovered");
  });

  it("scopes keys per tenant — tenant B is not a replay of tenant A", async () => {
    const store = new InMemoryIdempotencyStore();
    const interceptor = new IdempotencyInterceptor(store);
    const handler = vi.fn(() => of("run"));

    await firstValueFrom(
      interceptor.intercept(
        makeContext({ key: KEY, tenantId: "tenant-a" }).context,
        { handle: handler } as never,
      ),
    );
    await firstValueFrom(
      interceptor.intercept(
        makeContext({ key: KEY, tenantId: "tenant-b" }).context,
        { handle: handler } as never,
      ),
    );
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it("scopes keys per USER within a tenant — no cross-user replay (issue #25)", async () => {
    const store = new InMemoryIdempotencyStore();
    const interceptor = new IdempotencyInterceptor(store);
    const handler = vi.fn(() => of("run"));
    await firstValueFrom(
      interceptor.intercept(
        makeContext({ key: KEY, userId: "user-1" }).context,
        { handle: handler } as never,
      ),
    );
    await firstValueFrom(
      interceptor.intercept(
        makeContext({ key: KEY, userId: "user-2" }).context,
        { handle: handler } as never,
      ),
    );
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it("skips idempotency entirely for unauthenticated requests (issue #25)", async () => {
    const store = new InMemoryIdempotencyStore();
    const claim = vi.spyOn(store, "claim");
    const interceptor = new IdempotencyInterceptor(store);
    const { context } = makeContext({ key: KEY, anonymous: true });
    const result = await firstValueFrom(
      interceptor.intercept(context, { handle: () => of("anon") } as never),
    );
    expect(result).toBe("anon");
    expect(claim).not.toHaveBeenCalled();
  });

  it("rejects malformed keys", async () => {
    const store = new InMemoryIdempotencyStore();
    const interceptor = new IdempotencyInterceptor(store);
    const bad = makeContext({ key: "short" });
    expect(() =>
      interceptor.intercept(bad.context, { handle: () => of("x") } as never),
    ).toThrow(UnprocessableEntityException);
  });
});

import { createHash } from "node:crypto";
function hashOf(method: string, url: string, body: unknown): string {
  return createHash("sha256")
    .update(method)
    .update("\n")
    .update(url)
    .update("\n")
    .update(JSON.stringify(body))
    .digest("hex");
}
