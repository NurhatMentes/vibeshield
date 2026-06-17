import { describe, it, expect, vi } from 'vitest';
import {
  checkPermission,
  validateResourceOwnership,
  detectMissingAuthMiddleware,
  VibeShieldAuthorizationError,
  UserContext
} from '../src/core/authorization-protector.js';
import {
  requireAuth,
  requireRole,
  requirePermission,
  requireOwnership
} from '../src/middleware/authorization.js';

describe('VibeShield Authorization & Access Control Protector', () => {
  describe('checkPermission', () => {
    it('1. should allow admin role to access everything', () => {
      const user: UserContext = { id: 1, role: 'admin', permissions: [] };
      expect(checkPermission(user, 'users', 'delete')).toBe(true);
      expect(checkPermission(user, 'settings', 'admin')).toBe(true);
      expect(checkPermission(user, 'any_resource', 'read')).toBe(true);
    });

    it('2. should check direct permissions matching exact resource:action', () => {
      const user: UserContext = { id: 2, role: 'guest', permissions: ['posts:delete'] };
      expect(checkPermission(user, 'posts', 'delete')).toBe(true);
      expect(checkPermission(user, 'posts', 'read')).toBe(true); // allowed via guest matrix
      expect(checkPermission(user, 'posts', 'write')).toBe(false);
    });

    it('3. should check direct permissions matching resource wildcard (resource:*)', () => {
      const user: UserContext = { id: 3, role: 'guest', permissions: ['settings:*'] };
      expect(checkPermission(user, 'settings', 'read')).toBe(true);
      expect(checkPermission(user, 'settings', 'write')).toBe(true);
      expect(checkPermission(user, 'settings', 'admin')).toBe(true);
      expect(checkPermission(user, 'posts', 'write')).toBe(false);
    });

    it('4. should check global wildcard (*:*)', () => {
      const user: UserContext = { id: 4, role: 'guest', permissions: ['*:*'] };
      expect(checkPermission(user, 'settings', 'admin')).toBe(true);
      expect(checkPermission(user, 'users', 'delete')).toBe(true);
    });

    it('5. should use PERMISSION_MATRIX for user role (posts:read, posts:write, users:read, settings:read)', () => {
      const user: UserContext = { id: 5, role: 'user', permissions: [] };
      expect(checkPermission(user, 'posts', 'read')).toBe(true);
      expect(checkPermission(user, 'posts', 'write')).toBe(true);
      expect(checkPermission(user, 'posts', 'delete')).toBe(false);
      expect(checkPermission(user, 'users', 'read')).toBe(true);
      expect(checkPermission(user, 'users', 'write')).toBe(false);
      expect(checkPermission(user, 'settings', 'read')).toBe(true);
      expect(checkPermission(user, 'settings', 'write')).toBe(false);
    });

    it('6. should use PERMISSION_MATRIX for guest role (only posts:read)', () => {
      const user: UserContext = { id: 6, role: 'guest', permissions: [] };
      expect(checkPermission(user, 'posts', 'read')).toBe(true);
      expect(checkPermission(user, 'posts', 'write')).toBe(false);
      expect(checkPermission(user, 'users', 'read')).toBe(false);
      expect(checkPermission(user, 'settings', 'read')).toBe(false);
    });

    it('7. should return false for unsupported resource or action combinations', () => {
      const user: UserContext = { id: 7, role: 'guest', permissions: [] };
      expect(checkPermission(user, 'unknown_resource', 'read')).toBe(false);
    });
  });

  describe('validateResourceOwnership', () => {
    it('8. should return true if user is admin', () => {
      expect(validateResourceOwnership('user-123', 'post-456', 'user-789', 'admin')).toBe(true);
    });

    it('9. should return true if userId matches resourceOwnerId', () => {
      expect(validateResourceOwnership('user-123', 'post-456', 'user-123')).toBe(true);
    });

    it('10. should return false if userId does not match resourceOwnerId', () => {
      expect(validateResourceOwnership('user-123', 'post-456', 'user-789')).toBe(false);
    });

    it('11. should handle numeric and string type mismatches gracefully', () => {
      expect(validateResourceOwnership(123, 'post-456', '123')).toBe(true);
      expect(validateResourceOwnership('123', 'post-456', 123)).toBe(true);
    });
  });

  describe('detectMissingAuthMiddleware', () => {
    it('12. should return safe with empty findings for empty code', () => {
      const result = detectMissingAuthMiddleware('');
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it('13. should flag Express admin route defined without auth keyword as critical', () => {
      const code = `
        app.get('/admin/users', (req, res) => {});
      `;
      const result = detectMissingAuthMiddleware(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].pattern).toBe('Missing Auth in Admin Route');
    });

    it('14. should not flag Express admin route if check is on previous line', () => {
      const code = `
        router.use(requireAuth);
        router.get('/admin/settings', handler);
      `;
      const result = detectMissingAuthMiddleware(code);
      expect(result.safe).toBe(true);
    });

    it('15. should flag decorator style admin route missing auth', () => {
      const code = `
        @app.route('/admin')
        def admin(): pass
      `;
      const result = detectMissingAuthMiddleware(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
    });

    it('16. should flag sensitive user endpoint without ownership check as warning', () => {
      const code = `
        app.get('/api/users/:userId', (req, res) => {});
      `;
      const result = detectMissingAuthMiddleware(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('warning');
      expect(result.findings[0].pattern).toBe('Missing Ownership Check');
    });

    it('17. should not flag sensitive user endpoint if ownership check is present', () => {
      const code = `
        app.get('/api/users/:userId', requireOwnership('userId'), (req, res) => {});
      `;
      const result = detectMissingAuthMiddleware(code);
      expect(result.safe).toBe(true);
    });

    it('18. should flag Next.js HTTP method exports without any auth reference in file as high', () => {
      const code = `
        export async function DELETE(req: Request) {
          return new Response("Deleted");
        }
      `;
      const result = detectMissingAuthMiddleware(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].pattern).toBe('Next.js HTTP Handler Missing Auth');
    });

    it('19. should not flag Next.js HTTP method exports if auth reference exists in file', () => {
      const code = `
        import { requireAuth } from '../middleware/authorization';
        export async function DELETE(req: Request) {
          return new Response("Deleted");
        }
      `;
      const result = detectMissingAuthMiddleware(code);
      expect(result.safe).toBe(true);
    });

    it('20. should sort findings by line number', () => {
      const code = `
        app.get('/api/users/:userId', (req, res) => {});
        app.get('/admin', (req, res) => {});
      `;
      const result = detectMissingAuthMiddleware(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(2);
      expect(result.findings[0].line).toBe(2);
      expect(result.findings[1].line).toBe(3);
    });
  });

  describe('requireAuth Middleware', () => {
    describe('Express Mode', () => {
      it('21. should pass when public option is true', () => {
        const next = vi.fn();
        const req = {};
        requireAuth({ public: true })(req, {}, next);
        expect(next).toHaveBeenCalledTimes(1);
      });

      it('22. should throw VibeShieldAuthorizationError when user context is missing', () => {
        const next = vi.fn();
        const req = {};
        expect(() => requireAuth()(req, {}, next)).toThrow(
          /Authentication required: User context missing/
        );
        expect(next).not.toHaveBeenCalled();
      });

      it('23. should throw error when role filter specified and user does not match', () => {
        const next = vi.fn();
        const req = { user: { id: 1, role: 'user', permissions: [] } };
        expect(() => requireAuth({ roles: ['admin'] })(req, {}, next)).toThrow(
          /Forbidden: Required role not matched/
        );
        expect(next).not.toHaveBeenCalled();
      });

      it('24. should pass when user role matches one of allowed roles', () => {
        const next = vi.fn();
        const req = { user: { id: 1, role: 'user', permissions: [] } };
        requireAuth({ roles: ['user', 'moderator'] })(req, {}, next);
        expect(next).toHaveBeenCalledTimes(1);
      });

      it('25. should bypass role restrictions if user is admin', () => {
        const next = vi.fn();
        const req = { user: { id: 1, role: 'admin', permissions: [] } };
        requireAuth({ roles: ['user'] })(req, {}, next);
        expect(next).toHaveBeenCalledTimes(1);
      });

      it('26. should throw error when permission is required but not granted', () => {
        const next = vi.fn();
        const req = { user: { id: 1, role: 'guest', permissions: ['posts:read'] } };
        expect(() =>
          requireAuth({ permissions: ['posts:write'] })(req, {}, next)
        ).toThrow(/Forbidden: Required permission "posts:write" not granted/);
      });

      it('27. should pass when required permission is granted', () => {
        const next = vi.fn();
        const req = { user: { id: 1, role: 'user', permissions: ['posts:write'] } };
        requireAuth({ permissions: ['posts:write'] })(req, {}, next);
        expect(next).toHaveBeenCalledTimes(1);
      });

      it('28. should check resource ownership correctly via req.params', () => {
        const next = vi.fn();
        const req = {
          user: { id: 'user-1', role: 'user', permissions: [] },
          params: { id: 'post-10' },
          resourceOwnerId: 'user-1'
        };
        requireAuth({ resourceIdParam: 'id' })(req, {}, next);
        expect(next).toHaveBeenCalledTimes(1);
      });

      it('29. should fail resource ownership when IDs mismatch', () => {
        const next = vi.fn();
        const req = {
          user: { id: 'user-1', role: 'user', permissions: [] },
          params: { id: 'post-10' },
          resourceOwnerId: 'user-2'
        };
        expect(() =>
          requireAuth({ resourceIdParam: 'id' })(req, {}, next)
        ).toThrow(/Forbidden: Resource ownership verification failed/);
      });

      it('30. should bypass ownership checks if user is admin', () => {
        const next = vi.fn();
        const req = {
          user: { id: 'user-admin', role: 'admin', permissions: [] },
          params: { id: 'post-10' },
          resourceOwnerId: 'user-2'
        };
        requireAuth({ resourceIdParam: 'id' })(req, {}, next);
        expect(next).toHaveBeenCalledTimes(1);
      });
    });

    describe('Next.js Mode', () => {
      const mockHandler = vi.fn().mockImplementation(async (webReq: any) => {
        return new Response('Success');
      });

      it('31. should pass when public option is true', async () => {
        const wrapped = requireAuth({ public: true })(mockHandler);
        const webReq = {};
        const response = await wrapped(webReq);
        expect(await response.text()).toBe('Success');
      });

      it('32. should throw when user is missing in Next.js mode', async () => {
        const wrapped = requireAuth()(mockHandler);
        const webReq = {};
        await expect(wrapped(webReq)).rejects.toThrow(
          /Authentication required: User context missing/
        );
      });

      it('33. should check Next.js ownership via query and body successfully', async () => {
        const wrapped = requireAuth({ resourceIdParam: 'postId' })(mockHandler);
        const webReq = {
          user: { id: 'user-1', role: 'user', permissions: [] },
          url: 'http://localhost/api/posts?postId=post-10',
          clone: () => ({
            json: async () => ({ ownerId: 'user-1' })
          }),
          json: async () => ({ ownerId: 'user-1' })
        };
        const response = await wrapped(webReq);
        expect(await response.text()).toBe('Success');
      });

      it('34. should throw when Next.js ownership fails', async () => {
        const wrapped = requireAuth({ resourceIdParam: 'postId' })(mockHandler);
        const webReq = {
          user: { id: 'user-1', role: 'user', permissions: [] },
          url: 'http://localhost/api/posts?postId=post-10',
          clone: () => ({
            json: async () => ({ ownerId: 'user-2' })
          }),
          json: async () => ({ ownerId: 'user-2' })
        };
        await expect(wrapped(webReq)).rejects.toThrow(
          /Forbidden: Resource ownership verification failed/
        );
      });
    });
  });

  describe('Helper Wrappers', () => {
    it('35. requireRole should construct appropriate options', () => {
      const next = vi.fn();
      const req = { user: { id: 1, role: 'user', permissions: [] } };
      expect(() => requireRole(['admin'])(req, {}, next)).toThrow();
    });

    it('36. requirePermission should check permissions successfully', () => {
      const next = vi.fn();
      const req = { user: { id: 1, role: 'user', permissions: ['posts:write'] } };
      requirePermission(['posts:write'])(req, {}, next);
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('37. requireOwnership should check ownership successfully', () => {
      const next = vi.fn();
      const req = {
        user: { id: 'user-1', role: 'user', permissions: [] },
        params: { id: 'post-10' },
        resourceOwnerId: 'user-1'
      };
      requireOwnership('id')(req, {}, next);
      expect(next).toHaveBeenCalledTimes(1);
    });
  });
});
