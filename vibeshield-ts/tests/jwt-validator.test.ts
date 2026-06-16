import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { validateJwtSecret } from '../src/core/jwt-validator.js';
import { enforceJwtSecurity } from '../src/core/jwt-security.js';

// ==========================================
// 1. JWT VALIDATOR — CORE VALIDATION TESTS
// ==========================================
describe('JWT Secret Validator', () => {
  // ── Undefined / Empty / Whitespace ──────────────────────────────────
  it('should reject undefined secret', () => {
    const result = validateJwtSecret(undefined);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('undefined');
  });

  it('should reject empty string secret', () => {
    const result = validateJwtSecret('');
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('empty');
  });

  it('should reject whitespace-only secret', () => {
    const result = validateJwtSecret('     ');
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('empty');
  });

  // ── Hardcoded Pattern Detection ─────────────────────────────────────
  it('should reject "secret" as a hardcoded weak value', () => {
    const result = validateJwtSecret('secret');
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('well-known weak value'))).toBe(true);
  });

  it('should reject "123456" as a hardcoded weak value', () => {
    const result = validateJwtSecret('123456');
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('well-known weak value'))).toBe(true);
  });

  it('should reject "changeme" as a hardcoded weak value (case-insensitive)', () => {
    const result = validateJwtSecret('CHANGEME');
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('well-known weak value'))).toBe(true);
  });

  it('should reject "jwt_secret" as a hardcoded weak value', () => {
    const result = validateJwtSecret('jwt_secret');
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('well-known weak value'))).toBe(true);
  });

  it('should reject "password" as a hardcoded weak value', () => {
    const result = validateJwtSecret('password');
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('well-known weak value'))).toBe(true);
  });

  // ── Length Check ────────────────────────────────────────────────────
  it('should reject secrets shorter than 10 characters', () => {
    const result = validateJwtSecret('Ab3$xYz!q');  // 9 chars
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('too short'))).toBe(true);
  });

  it('should warn for secrets between 10-31 characters', () => {
    const result = validateJwtSecret('xK9#mL2$pQ7!nW4@');  // 16 chars, diverse
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('Recommended'))).toBe(true);
  });

  // ── Repeating Characters ────────────────────────────────────────────
  it('should reject secret with all repeating characters (aaaaaaaaaa)', () => {
    const result = validateJwtSecret('aaaaaaaaaa');
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Contains repetitive characters');
  });

  it('should reject secret with all repeating digits (1111111111)', () => {
    const result = validateJwtSecret('1111111111');
    expect(result.valid).toBe(false);
    // Should be flagged for repeating chars AND/OR all-digits
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('should reject secret with repeating pattern (abcabcabcabc)', () => {
    const result = validateJwtSecret('abcabcabcabc');
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Contains repeated patterns');
  });

  // ── All-Digit Secret ────────────────────────────────────────────────
  it('should reject an all-digit secret of sufficient length', () => {
    const result = validateJwtSecret('98765432101234');
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('only digits'))).toBe(true);
  });

  // ── Low Diversity ───────────────────────────────────────────────────
  it('should warn for all-lowercase secret of sufficient length', () => {
    const result = validateJwtSecret('xkmslqpwnvcz');
    expect(result.valid).toBe(true);  // valid but warns
    expect(result.warnings.some(w => w.includes('lowercase'))).toBe(true);
  });

  it('should warn for all-uppercase secret of sufficient length', () => {
    const result = validateJwtSecret('XKMSLQPWNCVZ');
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('uppercase'))).toBe(true);
  });

  // ── Valid Strong Secrets ────────────────────────────────────────────
  it('should accept a strong 32+ character mixed secret', () => {
    const strong = 'aB3$xPz!qW8#mL2@pQ7&nK4*jR9^tF1%';
    const result = validateJwtSecret(strong);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('should accept an openssl-style base64 secret', () => {
    const base64Secret = '83xPRXLD8+zohXic1Uwep2TfMx8Ogv8NZ5mstGLADFg=';
    const result = validateJwtSecret(base64Secret);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // ── Unicode / Special Characters ────────────────────────────────────
  it('should accept a secret with unicode and special characters', () => {
    const unicodeSecret = 'Kö$ñ!gstrÆße_T0ken#2024_Sëcürê';
    const result = validateJwtSecret(unicodeSecret);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // ── Character Class Diversity Warning ───────────────────────────────
  it('should warn when fewer than 3 character classes are used', () => {
    const result = validateJwtSecret('xkmslqpwnv12');  // only lower + digits = 2 classes
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('character classes'))).toBe(true);
  });

  // ── Shannon Entropy ─────────────────────────────────────────────────
  describe('Shannon Entropy', () => {
    it('should detect low entropy (aaaaaa)', () => {
      const result = validateJwtSecret('aaaaaa');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Low entropy detected');
    });
    
    it('should detect low entropy (111111)', () => {
      const result = validateJwtSecret('111111');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Low entropy detected');
    });
    
    it('should accept high entropy (aB3!xY7@zK9#mN)', () => {
      const result = validateJwtSecret('aB3!xY7@zK9#mN');
      expect(result.valid).toBe(true);
      expect(result.warnings).not.toContain(expect.stringContaining('Low entropy'));
    });
  });

  // ── Sequential Patterns ─────────────────────────────────────────────
  describe('Sequential Patterns', () => {
    it('should detect abc sequential pattern', () => {
      const result = validateJwtSecret('abc12345678901234567890');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Contains sequential patterns');
    });
    
    it('should detect 123 sequential pattern', () => {
      const result = validateJwtSecret('123abcdefghij1234567890');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Contains sequential patterns');
    });
    
    it('should detect qwerty pattern', () => {
      const result = validateJwtSecret('qwerty12345678901234567890');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Contains sequential patterns');
    });
  });

  // ── Repeated Patterns ───────────────────────────────────────────────
  describe('Repeated Patterns', () => {
    it('should detect abcabc pattern', () => {
      const result = validateJwtSecret('abcabc12345678901234567890');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Contains repeated patterns');
    });
    
    it('should detect 123123 pattern', () => {
      const result = validateJwtSecret('123123abcdefghij1234567890');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Contains repeated patterns');
    });
  });
});

// ==========================================
// 2. JWT SECURITY MIDDLEWARE TESTS
// ==========================================
describe('JWT Security Middleware', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should block insecure secrets and return allowed=false', () => {
    const result = enforceJwtSecurity('secret');
    expect(result.allowed).toBe(false);
    expect(result.trackingId).toMatch(/^VS-JWT-[A-Z0-9]{4}$/);
    expect(result.validation.valid).toBe(false);
  });

  it('should allow strong secrets and return allowed=true', () => {
    const result = enforceJwtSecurity('aB3$xPz!qW8#mL2@pQ7&nK4*jR9^tF1%');
    expect(result.allowed).toBe(true);
    expect(result.trackingId).toMatch(/^VS-JWT-[A-Z0-9]{4}$/);
    expect(result.validation.valid).toBe(true);
  });

  it('should log detailed errors in development mode for rejected secrets', () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';

    // Use a short but non-pattern secret so we can verify the VALUE isn't logged
    enforceJwtSecurity('xQ3$z');

    const errorCalls = (console.error as any).mock.calls.flat().join(' ');
    expect(errorCalls).toContain('JWT SECURITY CHECK FAILED');
    // Ensure the actual secret value is NOT in the log
    expect(errorCalls).not.toContain('xQ3$z');

    process.env.NODE_ENV = originalEnv;
  });

  it('should never log the actual secret value in error output', () => {
    const dangerousSecret = 'my-super-secret-api-key-12345';
    enforceJwtSecurity(dangerousSecret);

    const allOutput = (console.error as any).mock.calls.flat().join(' ') +
                      (console.warn as any).mock.calls.flat().join(' ');
    expect(allOutput).not.toContain(dangerousSecret);
  });
});
