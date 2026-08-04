import { Injectable } from "@nestjs/common";

@Injectable()
export class CacheService {
  private memoryCache = new Map<
    string,
    { value: unknown; expiresAt: number }
  >();

  async get<T = unknown>(key: string): Promise<T | null> {
    // In production, use Redis: await redis.get(key)
    const entry = this.memoryCache.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.memoryCache.delete(key);
      return null;
    }
    return entry.value as T;
  }

  async set(key: string, value: unknown, ttlSeconds = 300): Promise<void> {
    // In production: await redis.setex(key, ttlSeconds, JSON.stringify(value))
    this.memoryCache.set(key, {
      value,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  }

  async del(key: string): Promise<void> {
    this.memoryCache.delete(key);
  }

  async invalidatePattern(pattern: string): Promise<number> {
    // In production: scan + del matching keys
    let count = 0;
    const regex = new RegExp(pattern.replace(/\*/g, ".*"));
    for (const key of this.memoryCache.keys()) {
      if (regex.test(key)) {
        this.memoryCache.delete(key);
        count++;
      }
    }
    return count;
  }

  async getOrSet<T>(
    key: string,
    factory: () => Promise<T>,
    ttlSeconds = 300,
  ): Promise<T> {
    const cached = await this.get<T>(key);
    if (cached !== null) return cached;

    const value = await factory();
    await this.set(key, value, ttlSeconds);
    return value;
  }
}
