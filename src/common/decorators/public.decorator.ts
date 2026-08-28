import { SetMetadata } from "@nestjs/common";

export const IS_PUBLIC_KEY = "isPublic";
export const PUBLIC_REASON_KEY = "publicReason";

/**
 * Documents an intentional no-session boundary. It does not bypass a guard:
 * routes that authenticate a protocol client, bearer token or signed webhook
 * must still perform that verification in their own guard or handler.
 */
export const Public = (reason: string): ClassDecorator & MethodDecorator => {
  if (!reason.trim()) throw new Error("Public routes require an explicit reason");
  return (target: object, key?: string | symbol, descriptor?: PropertyDescriptor): void => {
    const applyPublic = SetMetadata(IS_PUBLIC_KEY, true);
    const applyReason = SetMetadata(PUBLIC_REASON_KEY, reason);
    if (key !== undefined && descriptor !== undefined) {
      applyPublic(target, key, descriptor);
      applyReason(target, key, descriptor);
      return;
    }
    applyPublic(target as never);
    applyReason(target as never);
    return;
  };
};
