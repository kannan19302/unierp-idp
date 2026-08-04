import { Injectable, LoggerService as NestLoggerService } from "@nestjs/common";
import pino from "pino";

const LOG_LEVEL = process.env.LOG_LEVEL || "info";

const pinoLogger = pino({
  level: LOG_LEVEL,
  transport:
    process.env.NODE_ENV !== "production"
      ? { target: "pino/file", options: { destination: 1 } }
      : undefined,
  formatters: {
    level: (label) => ({ level: label }),
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  base: { service: "unerp-api", env: process.env.NODE_ENV || "development" },
});

@Injectable()
export class AppLogger implements NestLoggerService {
  private context = "App";

  setContext(context: string) {
    this.context = context;
  }

  log(message: string, ...optionalParams: unknown[]) {
    pinoLogger.info({ context: this.extractContext(optionalParams) }, message);
  }

  error(message: any, ...optionalParams: unknown[]) {
    const trace = optionalParams[0];
    const context = optionalParams[1] || this.context;
    const msgStr =
      typeof message === "string"
        ? message
        : message?.message || JSON.stringify(message);
    const errStack = message?.stack || trace;
    pinoLogger.error({ context, trace: errStack, err: message }, msgStr);
  }

  warn(message: string, ...optionalParams: unknown[]) {
    pinoLogger.warn({ context: this.extractContext(optionalParams) }, message);
  }

  debug(message: string, ...optionalParams: unknown[]) {
    pinoLogger.debug({ context: this.extractContext(optionalParams) }, message);
  }

  verbose(message: string, ...optionalParams: unknown[]) {
    pinoLogger.trace({ context: this.extractContext(optionalParams) }, message);
  }

  private extractContext(params: unknown[]): string {
    const last = params[params.length - 1];
    return typeof last === "string" ? last : this.context;
  }
}

export { pinoLogger };
