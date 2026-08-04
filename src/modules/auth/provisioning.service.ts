import { Injectable, Logger } from "@nestjs/common";
import Redis from "ioredis";

export interface ProvisioningStatus {
  progress: number;
  currentStep: string;
  status: "pending" | "success" | "failed";
  error?: string;
}

@Injectable()
export class ProvisioningService {
  private readonly logger = new Logger(ProvisioningService.name);
  private readonly memoryStore = new Map<string, ProvisioningStatus>();
  private redisClient: Redis | null = null;

  constructor() {
    if (process.env.REDIS_URL) {
      try {
        this.redisClient = new Redis(process.env.REDIS_URL, {
          maxRetriesPerRequest: 2,
          lazyConnect: true,
        });
      } catch (err) {
        this.logger.warn(
          `Could not connect to Redis for provisioning tracker: ${err}`,
        );
      }
    }
  }

  private getKey(tenantId: string): string {
    return `tenant:provisioning:${tenantId}`;
  }

  async setProgress(
    tenantId: string,
    progress: number,
    currentStep: string,
    status: "pending" | "success" | "failed" = "pending",
    error?: string,
  ) {
    const data: ProvisioningStatus = { progress, currentStep, status, error };
    this.memoryStore.set(tenantId, data);

    if (this.redisClient) {
      try {
        await this.redisClient.setex(
          this.getKey(tenantId),
          300,
          JSON.stringify(data),
        );
      } catch (err) {
        this.logger.warn(
          `Failed to set provisioning progress in Redis: ${err}`,
        );
      }
    }
  }

  async getProgress(tenantId: string): Promise<ProvisioningStatus> {
    if (this.redisClient) {
      try {
        const cached = await this.redisClient.get(this.getKey(tenantId));
        if (cached) {
          return JSON.parse(cached) as ProvisioningStatus;
        }
      } catch (err) {
        this.logger.warn(
          `Failed to get provisioning progress from Redis: ${err}`,
        );
      }
    }

    return (
      this.memoryStore.get(tenantId) || {
        progress: 0,
        currentStep: "Initializing setup...",
        status: "pending",
      }
    );
  }
}
