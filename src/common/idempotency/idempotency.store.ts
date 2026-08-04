/**
 * Idempotency stores (Foundation Roadmap Track G.3).
 *
 * Records live under `idem:{tenantId}:{key}` with a TTL. Redis is the
 * production store (atomic NX claim works across API workers); the in-memory
 * store exists for unit tests and Redis-less dev. A durable Postgres audit
 * table can be added post-Track-A without changing this contract.
 */
import Redis from "ioredis";

export type IdempotencyRecord =
  | { state: "in-flight"; requestHash: string }
  | {
      state: "completed";
      requestHash: string;
      statusCode: number;
      body: unknown;
    };

export interface IdempotencyStore {
  /** Atomically claim a key. Returns the existing record when already taken. */
  claim(
    key: string,
    requestHash: string,
    ttlSeconds: number,
  ): Promise<IdempotencyRecord | null>;
  /** Overwrite a claimed key with the completed response. */
  complete(
    key: string,
    record: Extract<IdempotencyRecord, { state: "completed" }>,
    ttlSeconds: number,
  ): Promise<void>;
  /** Release a claim after a handler failure so the client may retry. */
  release(key: string): Promise<void>;
}

export class RedisIdempotencyStore implements IdempotencyStore {
  private client: Redis | null = null;

  constructor(private readonly redisUrl: string) {}

  private connection(): Redis {
    if (!this.client) {
      this.client = new Redis(this.redisUrl, {
        maxRetriesPerRequest: 2,
        lazyConnect: false,
      });
    }
    return this.client;
  }

  async claim(
    key: string,
    requestHash: string,
    ttlSeconds: number,
  ): Promise<IdempotencyRecord | null> {
    const record: IdempotencyRecord = { state: "in-flight", requestHash };
    const created = await this.connection().set(
      key,
      JSON.stringify(record),
      "EX",
      ttlSeconds,
      "NX",
    );
    if (created === "OK") return null;
    const existing = await this.connection().get(key);
    return existing ? (JSON.parse(existing) as IdempotencyRecord) : null;
  }

  async complete(
    key: string,
    record: Extract<IdempotencyRecord, { state: "completed" }>,
    ttlSeconds: number,
  ): Promise<void> {
    await this.connection().set(key, JSON.stringify(record), "EX", ttlSeconds);
  }

  async release(key: string): Promise<void> {
    await this.connection().del(key);
  }
}

export class InMemoryIdempotencyStore implements IdempotencyStore {
  private readonly entries = new Map<
    string,
    { record: IdempotencyRecord; expiresAt: number }
  >();

  async claim(
    key: string,
    requestHash: string,
    ttlSeconds: number,
  ): Promise<IdempotencyRecord | null> {
    const existing = this.entries.get(key);
    if (existing && existing.expiresAt > Date.now()) return existing.record;
    this.entries.set(key, {
      record: { state: "in-flight", requestHash },
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
    return null;
  }

  async complete(
    key: string,
    record: Extract<IdempotencyRecord, { state: "completed" }>,
    ttlSeconds: number,
  ): Promise<void> {
    this.entries.set(key, {
      record,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  }

  async release(key: string): Promise<void> {
    this.entries.delete(key);
  }
}
