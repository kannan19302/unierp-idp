import {
  Controller,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
} from "@nestjs/common";
import { InjectQueue } from "@nestjs/bullmq";
import { Queue } from "bullmq";
import { IDENTITY_EMAIL_QUEUE } from "./common/queues/queue.constants";
import { ApiTags, ApiOperation } from "@nestjs/swagger";
import { idpPrisma, prisma } from "@kannan19302/database";
import { EmailDeliveryOperationsService } from "./common/queues/email-delivery-operations.service";
import { Public } from "./common/decorators/public.decorator";

type CheckStatus = "up" | "down";

interface DependencyCheck {
  status: CheckStatus;
  latencyMs?: number;
  error?: string;
  detail?: string;
}

class ServiceUnavailableException extends HttpException {
  constructor(body: object) {
    super(body, HttpStatus.SERVICE_UNAVAILABLE);
  }
}

@ApiTags("health")
@Controller()
export class HealthController {
  constructor(
    @InjectQueue(IDENTITY_EMAIL_QUEUE) private readonly redisProbeQueue: Queue,
    private readonly emailOperations: EmailDeliveryOperationsService,
  ) {}

  @Get("health")
  @Public("Liveness exposes no tenant or dependency data and is required by the orchestrator")
  @ApiOperation({ summary: "Liveness probe — process is up" })
  check() {
    return {
      status: "ok",
      timestamp: new Date().toISOString(),
      service: "UniERP API",
      version: "0.0.1",
    };
  }

  @Get("ready")
  @Public("Readiness exposes only service availability for the orchestrator; dependency diagnostics stay internal")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Readiness probe — dependencies are reachable" })
  async ready() {
    const [database, redis, emailDelivery] = await Promise.all([
      this.checkDatabase(),
      this.checkRedis(),
      this.checkEmailDelivery(),
    ]);

    const checks = { database, redis, emailDelivery };
    const allUp = Object.values(checks).every((c) => c.status === "up");

    if (!allUp) {
      // 503 so orchestrators (k8s, load balancers) stop routing traffic.
      throw new ServiceUnavailableException({ status: "unavailable" });
    }

    return { status: "ready" };
  }

  private async checkDatabase(): Promise<DependencyCheck> {
    const start = Date.now();
    try {
      await prisma.$queryRaw`SELECT 1`;
      return { status: "up", latencyMs: Date.now() - start };
    } catch (err) {
      return { status: "down", error: (err as Error).message };
    }
  }

  private async checkRedis(): Promise<DependencyCheck> {
    const start = Date.now();
    try {
      const client = (await this.redisProbeQueue.client) as unknown as {
        ping: () => Promise<string>;
      };
      await client.ping();
      return { status: "up", latencyMs: Date.now() - start };
    } catch (err) {
      return { status: "down", error: (err as Error).message };
    }
  }

  private async checkEmailDelivery(): Promise<DependencyCheck> {
    try {
      const result = await this.emailOperations.canaryReadiness();
      return {
        status: result.status === "down" ? "down" : "up",
        detail: result.detail,
      };
    } catch (err) {
      return { status: "down", error: (err as Error).message };
    }
  }
}
