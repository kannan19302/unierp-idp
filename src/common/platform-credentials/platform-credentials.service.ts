import { BadRequestException, Injectable } from "@nestjs/common";
import { prisma, encryptField, decryptField } from "@unerp/database";
import {
  findProviderSpec,
  PLATFORM_CREDENTIAL_PROVIDERS,
} from "./provider-registry";

export interface MaskedField {
  value: string;
  isSet: boolean;
  sensitive: boolean;
}

/**
 * Platform-wide (not tenant-scoped) admin-editable integration credentials.
 * DB value wins when present; otherwise falls back per-field to
 * process.env[envFallback], so existing .env-based deployments keep working
 * unchanged until an admin saves a value from the SaaS Portal Settings UI.
 *
 * Reads are cached briefly (mirrors EntitlementGate's pattern in
 * apps/api/src/common/middleware/entitlement.middleware.ts) since callers
 * like the OAuth flow, Stripe client, and the email queue read this on
 * every request/job.
 */
@Injectable()
export class PlatformCredentialsService {
  private cache = new Map<
    string,
    { at: number; values: Record<string, string> }
  >();
  private readonly TTL = 15_000;

  private maskValue(value: string): string {
    if (!value) return "";
    const tail = value.slice(-4);
    return value.length <= 4
      ? "•".repeat(value.length)
      : `${"•".repeat(8)}${tail}`;
  }

  /** Real (decrypted) values for internal use by other backend services only — never send over HTTP. */
  async get(provider: string): Promise<Record<string, string>> {
    const cached = this.cache.get(provider);
    const now = Date.now();
    if (cached && now - cached.at < this.TTL) return cached.values;

    const spec = findProviderSpec(provider);
    if (!spec) return {};

    const rows = await prisma.platformCredential.findMany({
      where: { provider },
    });
    const byKey = new Map(rows.map((r) => [r.key, r]));

    const values: Record<string, string> = {};
    for (const field of spec.fields) {
      const row = byKey.get(field.key);
      if (row && row.value) {
        values[field.key] = field.sensitive
          ? decryptField(row.value)
          : row.value;
      } else if (field.envFallback) {
        values[field.key] = process.env[field.envFallback] ?? "";
      } else {
        values[field.key] = "";
      }
    }

    this.cache.set(provider, { at: now, values });
    return values;
  }

  /** Masked values for the admin UI — sensitive fields are never returned decrypted. */
  async getMasked(provider: string): Promise<Record<string, MaskedField>> {
    const spec = findProviderSpec(provider);
    if (!spec) return {};

    const rows = await prisma.platformCredential.findMany({
      where: { provider },
    });
    const byKey = new Map(rows.map((r) => [r.key, r]));

    const result: Record<string, MaskedField> = {};
    for (const field of spec.fields) {
      const row = byKey.get(field.key);
      const isSet = !!row && !!row.value;
      let value: string;
      if (isSet) {
        const real = field.sensitive ? decryptField(row!.value) : row!.value;
        value = field.sensitive ? this.maskValue(real) : real;
      } else {
        value =
          field.envFallback && process.env[field.envFallback]
            ? "(using environment default)"
            : "";
      }
      result[field.key] = { value, isSet, sensitive: field.sensitive };
    }
    return result;
  }

  async getAllMasked(): Promise<
    Array<{
      provider: string;
      label: string;
      fields: Array<MaskedField & { key: string; label: string }>;
    }>
  > {
    const out: Array<{
      provider: string;
      label: string;
      fields: Array<MaskedField & { key: string; label: string }>;
    }> = [];
    for (const spec of PLATFORM_CREDENTIAL_PROVIDERS) {
      const masked = await this.getMasked(spec.provider);
      out.push({
        provider: spec.provider,
        label: spec.label,
        fields: spec.fields.map((f) => ({
          key: f.key,
          label: f.label,
          ...masked[f.key]!,
        })),
      });
    }
    return out;
  }

  async set(
    provider: string,
    values: Record<string, string>,
    updatedBy: string,
  ): Promise<void> {
    const spec = findProviderSpec(provider);
    if (!spec) throw new BadRequestException(`Unknown provider: ${provider}`);

    const fieldsByKey = new Map(spec.fields.map((f) => [f.key, f]));
    for (const key of Object.keys(values)) {
      if (!fieldsByKey.has(key)) {
        throw new BadRequestException(
          `Unknown field "${key}" for provider "${provider}"`,
        );
      }
    }

    for (const [key, rawValue] of Object.entries(values)) {
      const field = fieldsByKey.get(key)!;
      const value = field.sensitive ? encryptField(rawValue) : rawValue;
      await prisma.platformCredential.upsert({
        where: { provider_key: { provider, key } },
        update: { value, isSensitive: field.sensitive, updatedBy },
        create: {
          provider,
          key,
          value,
          isSensitive: field.sensitive,
          updatedBy,
        },
      });
    }

    this.cache.delete(provider);
  }
}
