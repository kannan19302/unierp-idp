import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Observable, from, switchMap } from "rxjs";
import { idpPrisma, prisma } from "@kannan19302/database";
import { ChangeHistoryService } from "../services/change-history.service";
import {
  TRACK_CHANGES_KEY,
  TrackChangesMetadata,
} from "../decorators/track-changes.decorator";
import type { ChangeAction } from "@kannan19302/shared";

@Injectable()
export class ChangeHistoryInterceptor implements NestInterceptor {
  constructor(
    private readonly reflector: Reflector,
    private readonly changeHistoryService: ChangeHistoryService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const metadata = this.reflector.get<TrackChangesMetadata>(
      TRACK_CHANGES_KEY,
      context.getHandler(),
    );

    if (!metadata) {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest();
    const method = request.method;

    if (method === "GET") {
      return next.handle();
    }

    const user = request.user as
      | {
          tenantId: string;
          userId: string;
          email: string;
          firstName?: string;
          lastName?: string;
        }
      | undefined;
    if (!user) {
      return next.handle();
    }

    const entityId = request.params[metadata.entityIdParam];
    const entityType = metadata.entityType;
    const tenantId = user.tenantId;
    const userName =
      [user.firstName, user.lastName].filter(Boolean).join(" ") || user.email;

    const action: ChangeAction =
      method === "DELETE" ? "DELETE" : entityId ? "UPDATE" : "CREATE";

    const snapshotPromise = entityId
      ? this.getEntitySnapshot(entityType, entityId)
      : Promise.resolve(null);

    return from(snapshotPromise).pipe(
      switchMap((oldSnapshot) => {
        return new Observable((subscriber) => {
          next.handle().subscribe({
            next: async (result) => {
              try {
                const newEntityId =
                  entityId ||
                  ((result as Record<string, unknown>)?.id as string);
                if (newEntityId) {
                  const newSnapshot =
                    action === "DELETE"
                      ? {}
                      : await this.getEntitySnapshot(entityType, newEntityId);

                  const fieldChanges =
                    action === "CREATE"
                      ? Object.entries(newSnapshot || {})
                          .filter(
                            ([k]) =>
                              ![
                                "id",
                                "tenantId",
                                "tenant_id",
                                "updatedAt",
                                "updated_at",
                                "createdAt",
                                "created_at",
                              ].includes(k),
                          )
                          .map(([k, v]) => ({
                            field: k,
                            label: k
                              .replace(/([A-Z])/g, " $1")
                              .replace(/^./, (s) => s.toUpperCase())
                              .trim(),
                            oldValue: null,
                            newValue: v,
                          }))
                      : this.changeHistoryService.diffFields(
                          oldSnapshot || {},
                          newSnapshot || {},
                        );

                  if (fieldChanges.length > 0 || action === "DELETE") {
                    await this.changeHistoryService.recordChange({
                      tenantId,
                      userId: user.userId,
                      userName,
                      entityType,
                      entityId: newEntityId,
                      action,
                      fieldChanges,
                      metadata: {
                        ipAddress: request.ip,
                        userAgent: request.headers["user-agent"],
                      },
                    });
                  }
                }
              } catch {
                // Don't fail the request if history tracking fails
              }
              subscriber.next(result);
              subscriber.complete();
            },
            error: (err: unknown) => subscriber.error(err),
          });
        });
      }),
    );
  }

  private async getEntitySnapshot(
    entityType: string,
    entityId: string,
  ): Promise<Record<string, unknown> | null> {
    const modelName = entityType.charAt(0).toLowerCase() + entityType.slice(1);
    const model = (prisma as any)[modelName];
    if (model && typeof (model as any).findUnique === "function") {
      try {
        return await (
          model as {
            findUnique: (args: {
              where: { id: string };
            }) => Promise<Record<string, unknown> | null>;
          }
        ).findUnique({ where: { id: entityId } });
      } catch {
        return null;
      }
    }
    return null;
  }
}
