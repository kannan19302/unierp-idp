import { ThrottlerStorage } from "@nestjs/throttler";
import Redis from "ioredis";

interface ThrottlerStorageRecord {
  totalHits: number;
  timeToExpire: number;
  isBlocked: boolean;
  timeToBlockExpire: number;
}

const KEY_PREFIX = "throttle:";

export class RedisThrottlerStorage implements ThrottlerStorage {
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

  async increment(
    key: string,
    ttl: number,
    limit: number,
    blockDuration: number,
    _throttlerName: string,
  ): Promise<ThrottlerStorageRecord> {
    const redisKey = `${KEY_PREFIX}${key}`;
    const redis = this.connection();

    const totalHits = await redis.incr(redisKey);
    if (totalHits === 1) {
      await redis.pexpire(redisKey, ttl);
    }

    const ttlLeft = await redis.pttl(redisKey);
    const timeToExpire = Math.max(0, Math.ceil(ttlLeft));
    const isBlocked = totalHits > limit;
    const timeToBlockExpire = isBlocked ? Math.max(0, blockDuration) : 0;

    return { totalHits, timeToExpire, isBlocked, timeToBlockExpire };
  }
}

export class InMemoryThrottlerStorage implements ThrottlerStorage {
  private storage = new Map<string, { hits: number; expiresAt: number }>();

  async increment(
    key: string,
    ttl: number,
    limit: number,
    blockDuration: number,
    _throttlerName: string,
  ): Promise<ThrottlerStorageRecord> {
    const now = Date.now();
    const entry = this.storage.get(key);

    if (!entry || entry.expiresAt <= now) {
      this.storage.set(key, { hits: 1, expiresAt: now + ttl });
      return {
        totalHits: 1,
        timeToExpire: ttl,
        isBlocked: false,
        timeToBlockExpire: 0,
      };
    }

    entry.hits += 1;
    const timeToExpire = Math.max(0, entry.expiresAt - now);
    const isBlocked = entry.hits > limit;
    const timeToBlockExpire = isBlocked ? blockDuration : 0;

    return {
      totalHits: entry.hits,
      timeToExpire,
      isBlocked,
      timeToBlockExpire,
    };
  }
}
