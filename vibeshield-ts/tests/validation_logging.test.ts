import { describe, it, expect, vi } from 'vitest';
import { validatePayload } from '../src/core/validation';
import { startAuditTimer, endAuditTimer, logPerformanceWarning } from '../src/core/logging';

describe('VibeShield Phase 3.5: Recursive Validation & Logging Engine', () => {
  describe('Deep Recursive Validation Engine', () => {
    const schema = {
      user: {
        type: 'object',
        required: true,
        schema: {
          profile: {
            type: 'object',
            required: true,
            schema: {
              email: { type: 'string', required: true, format: 'email' },
              age: { type: 'number', min: 18 }
            }
          }
        }
      },
      cart: {
        type: 'object',
        schema: {
          items: {
            type: 'array',
            min: 1,
            elementSchema: {
              type: 'object',
              schema: {
                productId: { type: 'string', required: true },
                quantity: { type: 'number', min: 1 }
              }
            }
          }
        }
      },
      tags: {
        type: 'array',
        elementSchema: { type: 'string', min: 2 }
      }
    } as any;

    it('should pass fully valid deep nested payloads', () => {
      const payload = {
        user: { profile: { email: 'test@example.com', age: 25 } },
        cart: { items: [{ productId: 'abc', quantity: 2 }] },
        tags: ['premium', 'vip']
      };
      const result = validatePayload(payload, schema);
      expect(result.isValid).toBe(true);
      expect(result.errors).toBeNull();
    });

    it('should fail and generate dot-notation paths for missing nested fields', () => {
      const payload = {
        user: { profile: { age: 25 } } // missing email
      };
      const result = validatePayload(payload, schema);
      expect(result.isValid).toBe(false);
      expect(result.errors?.['user.profile.email']).toContain('required');
    });

    it('should fail and generate bracket-notation paths for invalid array elements', () => {
      const payload = {
        user: { profile: { email: 'test@example.com', age: 25 } },
        cart: { items: [{ productId: 'abc', quantity: 2 }, { productId: 'def', quantity: 0 }] } // 0 is invalid
      };
      const result = validatePayload(payload, schema);
      expect(result.isValid).toBe(false);
      expect(result.errors?.['cart.items[1].quantity']).toContain('greater than or equal to 1');
    });

    it('should fail and generate bracket-notation paths for arrays of primitives', () => {
      const payload = {
        user: { profile: { email: 'test@example.com', age: 25 } },
        tags: ['ok', 'a'] // 'a' is too short
      };
      const result = validatePayload(payload, schema);
      expect(result.isValid).toBe(false);
      expect(result.errors?.['tags[1]']).toContain('at least 2 characters');
    });

    it('should fail on type mismatches in deep objects', () => {
      const payload = {
        user: { profile: { email: 123, age: 25 } } // email should be string
      };
      const result = validatePayload(payload, schema);
      expect(result.isValid).toBe(false);
      expect(result.errors?.['user.profile.email']).toContain('Expected type \'string\'');
    });

    it('should enforce array length constraints on root arrays', () => {
      const payload = {
        user: { profile: { email: 'test@example.com', age: 25 } },
        cart: { items: [] } // requires at least 1
      };
      const result = validatePayload(payload, schema);
      expect(result.isValid).toBe(false);
      expect(result.errors?.['cart.items']).toContain('at least 1 items');
    });
  });

  describe('Performance Logging', () => {
    it('should measure execution duration using hrtime', () => {
      const start = startAuditTimer();
      expect(typeof start).toBe('bigint');
      const duration = endAuditTimer(start);
      expect(typeof duration).toBe('number');
      expect(duration).toBeGreaterThanOrEqual(0);
    });

    it('should trigger console warnings via the logger interface', () => {
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      logPerformanceWarning('POST', '/api/checkout', 600, 500);
      expect(consoleWarnSpy).toHaveBeenCalled();
      expect(consoleWarnSpy.mock.calls[0][0]).toContain('PERFORMANCE WARNING');
      consoleWarnSpy.mockRestore();
    });
  });
});
