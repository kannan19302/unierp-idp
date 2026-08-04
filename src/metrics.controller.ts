import { Controller, Get, Res } from "@nestjs/common";
import { Response } from "express";
import { metricsRegistry } from "./common/middleware/metrics.middleware";

@Controller()
export class MetricsController {
  @Get("metrics")
  async getMetrics(@Res() res: Response) {
    res.set("Content-Type", metricsRegistry.contentType);
    res.end(await metricsRegistry.metrics());
  }
}
