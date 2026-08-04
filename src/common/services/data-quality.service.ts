import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { idpPrisma, prisma } from "@unerp/database";

interface DuplicateGroup {
  field: string;
  value: string;
  count: number;
  ids: string[];
  records: any[];
}

interface MergeStrategy {
  field: string;
  strategy: "keep_first" | "keep_last" | "concat" | "sum" | "latest";
}

interface QualityCheckResult {
  modelName: string;
  totalRecords: number;
  issues: {
    type: "missing_field" | "invalid_value" | "duplicate" | "format_error";
    field: string;
    count: number;
    examples: any[];
  }[];
  score: number;
}

const QUALITY_MODELS = new Set([
  "customer",
  "vendor",
  "contact",
  "lead",
  "employee",
]);

@Injectable()
export class DataQualityService {
  constructor(private readonly eventEmitter?: EventEmitter2) {}

  private getModel(modelName: string): any {
    if (!QUALITY_MODELS.has(modelName)) {
      throw new BadRequestException(
        `Model '${modelName}' is not supported for data quality operations`,
      );
    }
    const model = (prisma as any)[modelName];
    if (!model || typeof model.findMany !== "function") {
      throw new BadRequestException(`Invalid Prisma model: ${modelName}`);
    }
    return model;
  }

  async deduplicate(
    tenantId: string,
    modelName: string,
    fields: string[],
  ): Promise<DuplicateGroup[]> {
    if (!fields || fields.length === 0) {
      throw new BadRequestException(
        "At least one field is required for deduplication",
      );
    }

    this.getModel(modelName);
    const allRecords = await (prisma as any)[modelName].findMany({
      where: { tenantId, deletedAt: null },
    });

    const groups: Map<string, { ids: string[]; records: any[] }> = new Map();

    for (const record of allRecords) {
      const key = fields
        .map((f) => String(record[f] ?? ""))
        .join("||")
        .toLowerCase();
      if (!key || key === "||||") continue;

      if (!groups.has(key)) {
        groups.set(key, { ids: [], records: [] });
      }
      const group = groups.get(key)!;
      group.ids.push(record.id);
      group.records.push(record);
    }

    const duplicates: DuplicateGroup[] = [];
    for (const [key, group] of groups.entries()) {
      if (group.ids.length > 1) {
        const values = key.split("||");
        duplicates.push({
          field: fields.join(", "),
          value: values.join(", "),
          count: group.ids.length,
          ids: group.ids,
          records: group.records,
        });
      }
    }

    return duplicates;
  }

  async mergeDuplicates(
    tenantId: string,
    modelName: string,
    primaryId: string,
    duplicateIds: string[],
    mergeStrategy: MergeStrategy[] = [],
  ): Promise<any> {
    this.getModel(modelName);
    const model = (prisma as any)[modelName];

    const primary = await model.findUnique({
      where: { id: primaryId, tenantId },
    });
    if (!primary) {
      throw new NotFoundException(`Primary record ${primaryId} not found`);
    }

    const duplicates = await model.findMany({
      where: { id: { in: duplicateIds }, tenantId },
    });

    if (duplicates.length !== duplicateIds.length) {
      throw new BadRequestException("Some duplicate records were not found");
    }

    const merged = await idpPrisma.$transaction(async (tx) => {
      const updateData: Record<string, any> = {};

      for (const strategy of mergeStrategy) {
        const field = strategy.field;
        if (!(field in primary)) continue;

        const values = [primary, ...duplicates]
          .map((r) => r[field])
          .filter((v) => v != null);

        switch (strategy.strategy) {
          case "keep_first":
            updateData[field] = primary[field];
            break;
          case "keep_last":
            updateData[field] = values[values.length - 1];
            break;
          case "concat":
            updateData[field] = values.join(", ");
            break;
          case "sum":
            updateData[field] = values.reduce(
              (acc: number, v: any) => acc + (Number(v) || 0),
              0,
            );
            break;
          case "latest":
            updateData[field] = values[values.length - 1];
            break;
        }
      }

      const updated = await (tx as any)[modelName].update({
        where: { id: primaryId },
        data: updateData,
      });

      for (const dupId of duplicateIds) {
        await (tx as any)[modelName].update({
          where: { id: dupId },
          data: { deletedAt: new Date() },
        });
      }

      return updated;
    });

    if (this.eventEmitter) {
      this.eventEmitter.emit("data-quality.merged", {
        tenantId,
        modelName,
        primaryId,
        mergedCount: duplicateIds.length,
      });
    }

    return merged;
  }

  async validateDataQuality(
    tenantId: string,
    modelName: string,
  ): Promise<QualityCheckResult> {
    this.getModel(modelName);
    const model = (prisma as any)[modelName];

    const allRecords = await model.findMany({
      where: { tenantId, deletedAt: null },
    });

    const issues: QualityCheckResult["issues"] = [];
    let issueCount = 0;

    const requiredFields = this.getRequiredFields(modelName);
    for (const field of requiredFields) {
      const missing = allRecords.filter(
        (r: any) => r[field] == null || String(r[field]).trim() === "",
      );
      if (missing.length > 0) {
        issueCount += missing.length;
        issues.push({
          type: "missing_field",
          field,
          count: missing.length,
          examples: missing
            .slice(0, 3)
            .map((r: any) => ({ id: r.id, [field]: r[field] })),
        });
      }
    }

    const emailFields = ["email", "emailAddress", "personalEmail", "workEmail"];
    for (const field of emailFields) {
      if (!allRecords[0] || !(field in allRecords[0])) continue;
      const invalid = allRecords.filter(
        (r: any) =>
          r[field] != null && r[field] !== "" && !this.isValidEmail(r[field]),
      );
      if (invalid.length > 0) {
        issueCount += invalid.length;
        issues.push({
          type: "format_error",
          field,
          count: invalid.length,
          examples: invalid
            .slice(0, 3)
            .map((r: any) => ({ id: r.id, [field]: r[field] })),
        });
      }
    }

    const phoneFields = ["phone", "mobile", "phoneNumber", "mobileNumber"];
    for (const field of phoneFields) {
      if (!allRecords[0] || !(field in allRecords[0])) continue;
      const invalid = allRecords.filter(
        (r: any) =>
          r[field] != null &&
          r[field] !== "" &&
          !this.isValidPhone(String(r[field])),
      );
      if (invalid.length > 0) {
        issueCount += invalid.length;
        issues.push({
          type: "format_error",
          field,
          count: invalid.length,
          examples: invalid
            .slice(0, 3)
            .map((r: any) => ({ id: r.id, [field]: r[field] })),
        });
      }
    }

    const totalChecks =
      allRecords.length *
      (requiredFields.length + emailFields.length + phoneFields.length);
    const score =
      totalChecks > 0
        ? Math.round(((totalChecks - issueCount) / totalChecks) * 100)
        : 100;

    return {
      modelName,
      totalRecords: allRecords.length,
      issues,
      score,
    };
  }

  standardizeAddress(address: {
    addressLine1?: string;
    addressLine2?: string;
    city?: string;
    state?: string;
    postalCode?: string;
    country?: string;
  }): Record<string, string> {
    const standardized: Record<string, string> = {};

    if (address.addressLine1) {
      standardized.addressLine1 = address.addressLine1
        .trim()
        .replace(/\s+/g, " ");
    }
    if (address.addressLine2) {
      standardized.addressLine2 = address.addressLine2
        .trim()
        .replace(/\s+/g, " ");
    }
    if (address.city) {
      standardized.city = address.city.trim().replace(/\s+/g, " ");
    }
    if (address.state) {
      standardized.state = address.state.trim().toUpperCase();
    }
    if (address.postalCode) {
      standardized.postalCode = address.postalCode.trim().replace(/\s+/g, "");
    }
    if (address.country) {
      standardized.country = address.country.trim();
    }

    return standardized;
  }

  normalizePhone(phone: string, country = "US"): string {
    if (!phone) return "";

    const digits = phone.replace(/[^\d]/g, "");

    const countryCodes: Record<string, string> = {
      US: "1",
      GB: "44",
      CA: "1",
      AU: "61",
      IN: "91",
      DE: "49",
      FR: "33",
      JP: "81",
      BR: "55",
      MX: "52",
    };

    const cc = countryCodes[country] || "1";

    if (digits.length === 10) {
      return `+${cc}${digits}`;
    }
    if (digits.length === 11 && digits.startsWith(cc)) {
      return `+${digits}`;
    }
    if (digits.length > 11 && digits.startsWith(cc)) {
      return `+${digits}`;
    }

    return `+${digits}`;
  }

  validateEmail(email: string): {
    valid: boolean;
    normalized?: string;
    reason?: string;
  } {
    if (!email || !email.includes("@")) {
      return { valid: false, reason: "Missing @ symbol" };
    }

    const normalized = email.trim().toLowerCase();
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (!emailRegex.test(normalized)) {
      return { valid: false, reason: "Invalid email format" };
    }

    const domain = normalized.split("@")[1];
    if (!domain) return { valid: false, reason: "Invalid email domain" };

    const disposableDomains = new Set([
      "tempmail.com",
      "throwaway.com",
      "mailinator.com",
      "guerrillamail.com",
      "10minutemail.com",
      "yopmail.com",
      "trashmail.com",
    ]);

    if (disposableDomains.has(domain)) {
      return {
        valid: false,
        reason: "Disposable email domain not allowed",
        normalized,
      };
    }

    return { valid: true, normalized };
  }

  private getRequiredFields(modelName: string): string[] {
    const fieldMap: Record<string, string[]> = {
      customer: ["name", "email"],
      vendor: ["name", "email"],
      contact: ["firstName", "lastName", "email"],
      lead: ["firstName", "lastName", "email"],
      employee: ["firstName", "lastName", "email", "employeeCode"],
    };
    return fieldMap[modelName] || [];
  }

  private isValidEmail(email: string): boolean {
    return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);
  }

  private isValidPhone(phone: string): boolean {
    const digits = phone.replace(/[^\d]/g, "");
    return digits.length >= 7 && digits.length <= 15;
  }
}
