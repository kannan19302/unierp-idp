import { SetMetadata } from "@nestjs/common";

export const TRACK_CHANGES_KEY = "track_changes";

export interface TrackChangesMetadata {
  entityType: string;
  entityIdParam: string;
}

export const TrackChanges = (
  entityType: string,
  entityIdParam: string = "id",
) =>
  SetMetadata(TRACK_CHANGES_KEY, {
    entityType,
    entityIdParam,
  } as TrackChangesMetadata);
