import { describe, it, expect, vi } from 'vitest';
import { validatePayload } from '../src/core/validation';
import { startAuditTimer, endAuditTimer, logAudit, logPerformanceWarning } from '../src/core/logging';

describe('VibeShield Phase 3: Validation & Logging Engine', () => {
  describe('Validation Engine', () => {
    const schema = {
      email: { type: 'string', required: true, format: 'email' },
      age: { type: 'number', min: 18, max: 120 },
      tags: { type: 'array', min: 1, max: 3 }
    } as any;

    it('should pass valid payloads', () => {
      const payload = {
        email: 'test@example.com',
        age: 25,
        tags: ['premium']
      };
      const result = validatePayload(payload, schema);
      expect(result.isValid).toBe(true);
      expect(result.errors).toBeNull();
    });

    it('should fail if required fields are missing', () => {
      const payload = { age: 25 };
      const result = validatePayload(payload, schema);
      expect(result.isValid).toBe(false);
      expect(result.errors?.email).toContain('required');
    });

    it('should fail if email format is invalid', () => {
      const payload = { email: 'not-an-email', age: 25 };
      const result = validatePayload(payload, schema);
      expect(result.isValid).toBe(false);
      expect(result.errors?.email).toContain('format');
    });

    it('should enforce numeric min/max constraints', () => {
      const payload = { email: 'test@example.com', age: 15 };
      const result = validatePayload(payload, schema);
      expect(result.isValid).toBe(false);
      expect(result.errors?.age).toContain('greater than or equal to 18');
    });

    it('should enforce array length constraints', () => {
      const payload = { email: 'test@example.com', tags: ['a', 'b', 'c', 'd'] };
      const result = validatePayload(payload, schema);
      expect(result.isValid).toBe(false);
      expect(result.errors?.tags).toContain('not contain more than 3 items');
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
      expect(consoleWarnSpy.mock.calls[0][0]).toContain('600');
      consoleWarnSpy.mockRestore();
    });
  });
});
