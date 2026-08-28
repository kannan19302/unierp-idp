import { Injectable, Logger, OnModuleDestroy } from "@nestjs/common";
import { createHash, randomBytes } from "node:crypto";
import Redis from "ioredis";

export type ExternalAuthJourney = "login" | "register" | "link";
export type ExternalAuthProvider = "google" | "microsoft" | "github";

export interface ExternalAuthTransaction {
  provider: ExternalAuthProvider;
  journey: ExternalAuthJourney;
  tenantSlug: string | null;
  returnTo: string;
  nonce: string;
  codeVerifier: string;
  linkUserId?: string;
  linkTenantId?: string;
}

/** One-time inbound tenant federation callback binding. */
export interface FederationTransaction {
  tenantSlug: string;
  returnTo: string;
  nonce: string;
  codeVerifier: string;
}

export interface ExternalRegistrationProfile {
  provider: ExternalAuthProvider;
  subject: string;
  email: string;
  emailVerified: true;
  firstName?: string;
  lastName?: string;
  returnTo: string;
}

export interface PasskeyCeremony {
  purpose: "registration" | "authentication";
  challenge: string;
  rpId: string;
  expectedOrigins: string[];
  userId?: string;
  tenantId?: string;
  returnTo?: string;
}

const TRANSACTION_TTL_SECONDS = 10 * 60;
const REGISTRATION_TTL_SECONDS = 15 * 60;
const PASSKEY_CEREMONY_TTL_SECONDS = 5 * 60;

/**
 * One-time server-side storage for upstream OAuth/OIDC state and social
 * registration handoffs. Only an opaque random handle crosses the browser.
 * Redis makes callbacks safe across replicas; the in-memory fallback exists
 * only for tests and local development.
 */
@Injectable()
export class ExternalAuthStore implements OnModuleDestroy {
  private readonly logger = new Logger(ExternalAuthStore.name);
  private readonly redis: Redis | null;
  private readonly fallback = new Map<
    string,
    { expiresAt: number; value: string }
  >();

  constructor() {
    const url = process.env.REDIS_URL;
    this.redis = url
      ? new Redis(url, { maxRetriesPerRequest: 2, lazyConnect: false })
      : null;
    this.redis?.on("error", (err) =>
      this.logger.error(`External auth Redis error: ${err.message}`),
    );
    if (!this.redis && process.env.NODE_ENV === "production") {
      throw new Error(
        "REDIS_URL is required for replay-safe external authentication across replicas.",
      );
    }
  }

  async createTransaction(value: ExternalAuthTransaction): Promise<string> {
    return this.create("transaction", value, TRANSACTION_TTL_SECONDS);
  }

  async consumeTransaction(
    handle: string,
  ): Promise<ExternalAuthTransaction | null> {
    return this.consume<ExternalAuthTransaction>("transaction", handle);
  }

  async createFederationTransaction(value: FederationTransaction): Promise<string> {
    return this.create("federation", value, TRANSACTION_TTL_SECONDS);
  }

  async consumeFederationTransaction(
    handle: string,
  ): Promise<FederationTransaction | null> {
    return this.consume<FederationTransaction>("federation", handle);
  }

  async createRegistration(
    value: ExternalRegistrationProfile,
  ): Promise<string> {
    return this.create("registration", value, REGISTRATION_TTL_SECONDS);
  }

  async peekRegistration(
    handle: string,
  ): Promise<ExternalRegistrationProfile | null> {
    return this.peek<ExternalRegistrationProfile>("registration", handle);
  }

  async consumeRegistration(
    handle: string,
  ): Promise<ExternalRegistrationProfile | null> {
    return this.consume<ExternalRegistrationProfile>("registration", handle);
  }

  async createPasskeyCeremony(value: PasskeyCeremony): Promise<string> {
    return this.create("passkey", value, PASSKEY_CEREMONY_TTL_SECONDS);
  }

  async consumePasskeyCeremony(handle: string): Promise<PasskeyCeremony | null> {
    return this.consume<PasskeyCeremony>("passkey", handle);
  }

  async onModuleDestroy(): Promise<void> {
    if (this.redis) await this.redis.quit().catch(() => undefined);
  }

  private async create(
    namespace: string,
    value: unknown,
    ttlSeconds: number,
  ): Promise<string> {
    const handle = randomBytes(32).toString("base64url");
    const key = this.key(namespace, handle);
    const serialized = JSON.stringify(value);
    if (this.redis) {
      await this.redis.set(key, serialized, "EX", ttlSeconds, "NX");
    } else {
      this.pruneFallback();
      this.fallback.set(key, {
        expiresAt: Date.now() + ttlSeconds * 1000,
        value: serialized,
      });
    }
    return handle;
  }

  private async peek<T>(namespace: string, handle: string): Promise<T | null> {
    if (!isValidHandle(handle)) return null;
    const key = this.key(namespace, handle);
    const serialized = this.redis
      ? await this.redis.get(key)
      : this.readFallback(key, false);
    return parseStored<T>(serialized);
  }

  private async consume<T>(
    namespace: string,
    handle: string,
  ): Promise<T | null> {
    if (!isValidHandle(handle)) return null;
    const key = this.key(namespace, handle);
    let serialized: string | null;
    if (this.redis) {
      serialized = (await this.redis.eval(
        "local v=redis.call('GET',KEYS[1]); if v then redis.call('DEL',KEYS[1]) end; return v",
        1,
        key,
      )) as string | null;
    } else {
      serialized = this.readFallback(key, true);
    }
    return parseStored<T>(serialized);
  }

  private readFallback(key: string, consume: boolean): string | null {
    const entry = this.fallback.get(key);
    if (!entry || entry.expiresAt <= Date.now()) {
      this.fallback.delete(key);
      return null;
    }
    if (consume) this.fallback.delete(key);
    return entry.value;
  }

  private pruneFallback(): void {
    const now = Date.now();
    for (const [key, entry] of this.fallback) {
      if (entry.expiresAt <= now) this.fallback.delete(key);
    }
  }

  private key(namespace: string, handle: string): string {
    const digest = createHash("sha256").update(handle).digest("base64url");
    return `external-auth:${namespace}:${digest}`;
  }
}

function isValidHandle(handle: string): boolean {
  return /^[A-Za-z0-9_-]{40,64}$/.test(handle);
}

function parseStored<T>(serialized: string | null): T | null {
  if (!serialized) return null;
  try {
    return JSON.parse(serialized) as T;
  } catch {
    return null;
  }
}
