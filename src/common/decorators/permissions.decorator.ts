export const PERMISSIONS_KEY = "permissions";

/**
 * Annotates NestJS controllers or handlers with the required RBAC permissions.
 * Example: @Permissions('finance.invoice.create')
 * Supports multiple calls (stacking) by merging permissions rather than overwriting.
 */
export const Permissions = (...permissions: string[]) => {
  const decoratorFactory = (target: object, _key?: any, descriptor?: any) => {
    if (descriptor) {
      const existing =
        Reflect.getMetadata(PERMISSIONS_KEY, descriptor.value) || [];
      // Use Set to deduplicate permissions
      const merged = Array.from(new Set([...existing, ...permissions]));
      Reflect.defineMetadata(PERMISSIONS_KEY, merged, descriptor.value);
      return descriptor;
    }
    const existing = Reflect.getMetadata(PERMISSIONS_KEY, target) || [];
    const merged = Array.from(new Set([...existing, ...permissions]));
    Reflect.defineMetadata(PERMISSIONS_KEY, merged, target);
    return target;
  };
  decoratorFactory.KEY = PERMISSIONS_KEY;
  return decoratorFactory;
};
