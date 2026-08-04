import { Body } from "@nestjs/common";
import { ZodSchema } from "zod";
import { ZodValidationPipe } from "../pipes/zod-validation.pipe";

/**
 * One-line zod-validated request body.
 *
 * Replaces the verbose `@Body(new ZodValidationPipe(Schema)) dto: Dto` with:
 *   create(@ZodBody(CreateThingSchema) dto: CreateThingDto) { ... }
 *
 * Pair with `z.infer<typeof Schema>` for the parameter type so the validated
 * shape and the static type stay in sync. This is the canonical validation
 * pattern for every write endpoint (see the `pos` module's `dto/` folder).
 */
export const ZodBody = (schema: ZodSchema) =>
  Body(new ZodValidationPipe(schema));
