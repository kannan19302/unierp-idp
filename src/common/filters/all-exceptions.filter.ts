import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from "@nestjs/common";
import type { Request, Response } from "express";
import { IdpPrismaTypes as Prisma } from "@unerp/database";
import { ZodError } from "zod";
import { RecordNotFoundForUpdateError, StaleWriteError } from "@unerp/database";
import { codeForStatus, type ErrorEnvelope } from "@unerp/shared";
import { pinoLogger } from "../services/logger.service";

const REQUEST_ID_HEADER = "x-request-id";

/**
 * Global exception filter that converts every thrown error into a consistent
 * envelope: { statusCode, code, message, requestId, timestamp, path, errors }.
 *
 * Maps:
 *  - HttpException        → its own status + a stable `code`
 *  - ZodError             → 400 VALIDATION_FAILED with field-level `errors`
 *  - Prisma known errors  → 409 / 404 / 400 based on the Prisma error code
 *  - everything else      → 500 INTERNAL_ERROR (details hidden from clients)
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const requestId =
      (request.headers?.[REQUEST_ID_HEADER] as string) ?? "unknown";

    const envelope = this.toEnvelope(exception, request, requestId);

    if (envelope.statusCode >= 500) {
      pinoLogger.error(
        { requestId, path: envelope.path, err: exception },
        envelope.message,
      );
    } else if (envelope.statusCode >= 400) {
      pinoLogger.warn(
        { requestId, path: envelope.path, code: envelope.code },
        envelope.message,
      );
    }

    response.status(envelope.statusCode).json(envelope);
  }

  private toEnvelope(
    exception: unknown,
    request: Request,
    requestId: string,
  ): ErrorEnvelope {
    const base = {
      requestId,
      timestamp: new Date().toISOString(),
      path: request.url,
    };

    // 0. Optimistic-locking outcomes (Track G.2)
    if (exception instanceof StaleWriteError) {
      return {
        ...base,
        statusCode: HttpStatus.CONFLICT,
        code: "STALE_WRITE",
        message: exception.message,
        errors: { currentVersion: exception.currentVersion },
      };
    }
    if (exception instanceof RecordNotFoundForUpdateError) {
      return {
        ...base,
        statusCode: HttpStatus.NOT_FOUND,
        code: "NOT_FOUND",
        message: exception.message,
      };
    }

    // 1. Zod validation errors
    if (exception instanceof ZodError) {
      return {
        ...base,
        statusCode: HttpStatus.BAD_REQUEST,
        code: "VALIDATION_FAILED",
        message: "Validation failed",
        errors: exception.errors,
      };
    }

    // 2. Nest HttpExceptions (includes BadRequestException from ZodValidationPipe)
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const res = exception.getResponse();
      const { message, errors } = this.unwrapHttpResponse(res);
      return {
        ...base,
        statusCode: status,
        code: codeForStatus(status),
        message,
        errors,
      };
    }

    // 3. Prisma known request errors
    if (exception instanceof Prisma.PrismaClientKnownRequestError) {
      return { ...base, ...this.mapPrismaError(exception) };
    }

    if (exception instanceof Prisma.PrismaClientValidationError) {
      return {
        ...base,
        statusCode: HttpStatus.BAD_REQUEST,
        code: "DB_VALIDATION_ERROR",
        message: "Invalid database query",
      };
    }

    // 4. Fallback — never leak internals
    return {
      ...base,
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
      code: "INTERNAL_ERROR",
      message: "An unexpected error occurred",
    };
  }

  private mapPrismaError(
    error: Prisma.PrismaClientKnownRequestError,
  ): Pick<ErrorEnvelope, "statusCode" | "code" | "message"> {
    switch (error.code) {
      case "P2002":
        return {
          statusCode: HttpStatus.CONFLICT,
          code: "UNIQUE_CONSTRAINT",
          message: "A record with these values already exists",
        };
      case "P2025":
        return {
          statusCode: HttpStatus.NOT_FOUND,
          code: "NOT_FOUND",
          message: "The requested record was not found",
        };
      case "P2003":
        return {
          statusCode: HttpStatus.BAD_REQUEST,
          code: "FK_CONSTRAINT",
          message: "Related record constraint failed",
        };
      default:
        return {
          statusCode: HttpStatus.BAD_REQUEST,
          code: `DB_${error.code}`,
          message: "Database request failed",
        };
    }
  }

  private unwrapHttpResponse(res: string | object): {
    message: string;
    errors?: unknown;
  } {
    if (typeof res === "string") {
      return { message: res };
    }
    const obj = res as Record<string, unknown>;
    const message =
      typeof obj.message === "string"
        ? obj.message
        : Array.isArray(obj.message)
          ? (obj.message as string[]).join(", ")
          : "Request failed";
    return {
      message,
      errors:
        obj.errors ?? (Array.isArray(obj.message) ? obj.message : undefined),
    };
  }
}
