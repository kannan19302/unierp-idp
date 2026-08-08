import {
  Controller,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
} from "@nestjs/common";
import { InjectQueue } from "@nestjs/bullmq";
import { Queue } from "bullmq";
import { ApiTags, ApiOperation } from "@nestjs/swagger";
import { idpPrisma, prisma } from "@kannan19302/database";

type CheckStatus = "up" | "down";

interface DependencyCheck {
  status: CheckStatus;
  latencyMs?: number;
  error?: string;
}

class ServiceUnavailableException extends HttpException {
  constructor(body: object) {
    super(body, HttpStatus.SERVICE_UNAVAILABLE);
  }
}

@ApiTags("health")
@Controller()
export class HealthController {
  constructor(@InjectQueue("email") private readonly redisProbeQueue: Queue) {}

  @Get("health")
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
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Readiness probe — dependencies are reachable" })
  async ready() {
    const [database, redis] = await Promise.all([
      this.checkDatabase(),
      this.checkRedis(),
    ]);

    const checks = { database, redis };
    const allUp = Object.values(checks).every((c) => c.status === "up");

    if (!allUp) {
      // 503 so orchestrators (k8s, load balancers) stop routing traffic.
      throw new ServiceUnavailableException({ status: "unavailable", checks });
    }

    return { status: "ready", checks };
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
}
