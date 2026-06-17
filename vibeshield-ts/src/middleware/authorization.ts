import { VibeShieldAuthorizationError, checkPermission, validateResourceOwnership } from '../core/authorization-protector.js';

export interface AuthOptions {
  roles?: string[];
  permissions?: string[];
  resourceIdParam?: string;
  public?: boolean;
}

export function requireAuth(options: AuthOptions = {}) {
  return (req: any, res?: any, next?: any) => {
    // Next.js Route Handler Wrapper check: arg1 is a function
    if (typeof req === 'function') {
      const handler = req;
      return async (webReq: any, ...args: any[]) => {
        if (options.public) {
          return handler(webReq, ...args);
        }

        const user = webReq.user;
        if (!user) {
          throw new VibeShieldAuthorizationError('Authentication required: User context missing');
        }

        if (options.roles && !options.roles.includes(user.role) && user.role !== 'admin') {
          throw new VibeShieldAuthorizationError(`Forbidden: Required role not matched`);
        }

        if (options.permissions) {
          for (const perm of options.permissions) {
            const [resource, action] = perm.split(':');
            if (!checkPermission(user, resource, action as any)) {
              throw new VibeShieldAuthorizationError(`Forbidden: Required permission "${perm}" not granted`);
            }
          }
        }

        if (options.resourceIdParam) {
          // Dynamic query/body lookup
          let url: URL;
          try {
            url = new URL(webReq.url || '', 'http://localhost');
          } catch (e) {
            url = new URL('http://localhost');
          }
          const query = Object.fromEntries(url.searchParams.entries());
          let body: any = {};
          if (typeof webReq.json === 'function') {
            try {
              const clone = webReq.clone();
              body = await clone.json();
            } catch (e) {
              body = {};
            }
          }
          const resourceId = query[options.resourceIdParam] || body[options.resourceIdParam] || (webReq as any).resourceId;
          const resourceOwnerId = webReq.resourceOwnerId || body.ownerId || body.userId;

          if (resourceId !== undefined && resourceOwnerId !== undefined) {
            if (!validateResourceOwnership(user.id, resourceId, resourceOwnerId, user.role)) {
              throw new VibeShieldAuthorizationError('Forbidden: Resource ownership verification failed (IDOR)');
            }
          }
        }

        return handler(webReq, ...args);
      };
    }

    // Express middleware
    if (options.public) {
      if (typeof next === 'function') next();
      return;
    }

    const user = req.user;
    if (!user) {
      throw new VibeShieldAuthorizationError('Authentication required: User context missing');
    }

    if (options.roles && !options.roles.includes(user.role) && user.role !== 'admin') {
      throw new VibeShieldAuthorizationError('Forbidden: Required role not matched');
    }

    if (options.permissions) {
      for (const perm of options.permissions) {
        const [resource, action] = perm.split(':');
        if (!checkPermission(user, resource, action as any)) {
          throw new VibeShieldAuthorizationError(`Forbidden: Required permission "${perm}" not granted`);
        }
      }
    }

    if (options.resourceIdParam) {
      const resourceId = req.params[options.resourceIdParam] || req.query[options.resourceIdParam] || (req.body && req.body[options.resourceIdParam]);
      const resourceOwnerId = req.resourceOwnerId || (req.body && (req.body.ownerId || req.body.userId));
      if (resourceId !== undefined && resourceOwnerId !== undefined) {
        if (!validateResourceOwnership(user.id, resourceId, resourceOwnerId, user.role)) {
          throw new VibeShieldAuthorizationError('Forbidden: Resource ownership verification failed (IDOR)');
        }
      }
    }

    if (typeof next === 'function') {
      next();
    }
  };
}

export function requireRole(roles: string[]) {
  return requireAuth({ roles });
}

export function requirePermission(permissions: string[]) {
  return requireAuth({ permissions });
}

export function requireOwnership(resourceIdParam: string) {
  return requireAuth({ resourceIdParam });
}
