import { Controller, Get, Res, UseGuards } from "@nestjs/common";
import { Response } from "express";
import { metricsRegistry } from "./common/middleware/metrics.middleware";
import { JwtAuthGuard } from "./common/guards/jwt-auth.guard";
import { RbacGuard } from "./common/guards/rbac.guard";
import { Permissions } from "./common/decorators/permissions.decorator";

@Controller()
export class MetricsController {
  @Get("metrics")
  @UseGuards(JwtAuthGuard, RbacGuard)
  @Permissions("system.metrics.read")
  async getMetrics(@Res() res: Response) {
    res.set("Content-Type", metricsRegistry.contentType);
    res.end(await metricsRegistry.metrics());
  }
}
