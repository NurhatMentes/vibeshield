import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { validateCorsConfig } from '../src/core/cors-validator.js';
import { enforceCorsPolicy } from '../src/core/cors-security.js';

// ==========================================
// 1. CORS VALIDATOR — CORE VALIDATION TESTS
// ==========================================
describe('CORS Config Validator', () => {
  let originalEnv: string | undefined;

  beforeEach(() => {
    originalEnv = process.env.NODE_ENV;
    // Default to development unless explicitly set
    process.env.NODE_ENV = 'development';
  });

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  // ── Missing / Undefined Config ───────────────────────────────────────
  it('should reject undefined config', () => {
    const result = validateCorsConfig(undefined as any);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('missing');
  });

  it('should reject null config', () => {
    const result = validateCorsConfig(null as any);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('missing');
  });

  // ── Valid Minimal Config ─────────────────────────────────────────────
  it('should accept a valid minimal config with explicit origins', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // ── Wildcard Origin ──────────────────────────────────────────────────
  it('should warn on wildcard origin in development', () => {
    process.env.NODE_ENV = 'development';
    const result = validateCorsConfig({
      allowedOrigins: ['*'],
    });
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('Wildcard origin'))).toBe(true);
  });

  it('should error on wildcard origin in production', () => {
    process.env.NODE_ENV = 'production';
    const result = validateCorsConfig({
      allowedOrigins: ['*'],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Wildcard origin'))).toBe(true);
  });

  // ── Wildcard + Credentials (CRITICAL) ────────────────────────────────
  it('should always error on wildcard origin with credentials', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['*'],
      allowCredentials: true,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('CRITICAL'))).toBe(true);
  });

  it('should error on wildcard + credentials even in development', () => {
    process.env.NODE_ENV = 'development';
    const result = validateCorsConfig({
      allowedOrigins: ['*'],
      allowCredentials: true,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('credentials'))).toBe(true);
  });

  // ── Invalid Origin Format ────────────────────────────────────────────
  it('should reject origin without protocol', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['example.com'],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid origin format'))).toBe(true);
  });

  it('should reject origin with trailing slash', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com/'],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid origin format'))).toBe(true);
  });

  // ── Valid Origin Formats ─────────────────────────────────────────────
  it('should accept http origins', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['http://example.com'],
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('should accept https origins', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('should accept origins with port numbers', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com:8080'],
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // ── Localhost in Production ──────────────────────────────────────────
  it('should error on localhost origin in production', () => {
    process.env.NODE_ENV = 'production';
    const result = validateCorsConfig({
      allowedOrigins: ['http://localhost:3000'],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Localhost'))).toBe(true);
  });

  it('should error on 127.0.0.1 origin in production', () => {
    process.env.NODE_ENV = 'production';
    const result = validateCorsConfig({
      allowedOrigins: ['http://127.0.0.1:8080'],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Localhost'))).toBe(true);
  });

  it('should allow localhost origin in development', () => {
    process.env.NODE_ENV = 'development';
    const result = validateCorsConfig({
      allowedOrigins: ['http://localhost:3000'],
    });
    expect(result.valid).toBe(true);
  });

  // ── Empty Origins ────────────────────────────────────────────────────
  it('should warn when no origins are specified', () => {
    const result = validateCorsConfig({
      allowedOrigins: [],
    });
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('No allowed origins'))).toBe(true);
  });

  it('should warn when allowedOrigins key is omitted', () => {
    const result = validateCorsConfig({});
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('No allowed origins'))).toBe(true);
  });

  // ── Sensitive Exposed Headers ────────────────────────────────────────
  it('should error when authorization header is exposed', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
      exposedHeaders: ['Authorization'],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Sensitive headers'))).toBe(true);
    expect(result.errors.some(e => e.includes('authorization'))).toBe(true);
  });

  it('should error when set-cookie header is exposed', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
      exposedHeaders: ['Set-Cookie'],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('set-cookie'))).toBe(true);
  });

  it('should allow non-sensitive exposed headers like content-type', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
      exposedHeaders: ['Content-Type', 'X-Request-Id'],
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // ── Dangerous HTTP Methods ───────────────────────────────────────────
  it('should error when TRACE method is allowed', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
      allowedMethods: ['GET', 'TRACE'],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('TRACE'))).toBe(true);
  });

  it('should error when CONNECT method is allowed', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
      allowedMethods: ['GET', 'CONNECT'],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('CONNECT'))).toBe(true);
  });

  // ── Destructive Methods in Production ────────────────────────────────
  it('should warn on DELETE/PATCH in production', () => {
    process.env.NODE_ENV = 'production';
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
      allowedMethods: ['GET', 'POST', 'DELETE', 'PATCH'],
    });
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('Destructive methods'))).toBe(true);
    expect(result.warnings.some(w => w.includes('DELETE'))).toBe(true);
    expect(result.warnings.some(w => w.includes('PATCH'))).toBe(true);
  });

  it('should not warn on DELETE/PATCH in development', () => {
    process.env.NODE_ENV = 'development';
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
      allowedMethods: ['GET', 'POST', 'DELETE', 'PATCH'],
    });
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('Destructive methods'))).toBe(false);
  });

  // ── maxAge Validation ────────────────────────────────────────────────
  it('should error on negative maxAge', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
      maxAge: -1,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('negative'))).toBe(true);
  });

  it('should warn on excessive maxAge', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
      maxAge: 172800, // 48 hours
    });
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('maxAge'))).toBe(true);
    expect(result.warnings.some(w => w.includes('86400'))).toBe(true);
  });

  it('should accept normal maxAge without issues', () => {
    const result = validateCorsConfig({
      allowedOrigins: ['https://example.com'],
      maxAge: 3600,
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.warnings).toHaveLength(0);
  });

  // ── Credentials Without Origins ──────────────────────────────────────
  it('should warn when credentials are enabled without origins', () => {
    const result = validateCorsConfig({
      allowCredentials: true,
    });
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('Credentials enabled'))).toBe(true);
  });

  // ── Too Many Origins ─────────────────────────────────────────────────
  it('should warn when more than 20 origins are specified', () => {
    const manyOrigins = Array.from({ length: 25 }, (_, i) => `https://origin${i}.example.com`);
    const result = validateCorsConfig({
      allowedOrigins: manyOrigins,
    });
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('Large number'))).toBe(true);
    expect(result.warnings.some(w => w.includes('25'))).toBe(true);
  });

  // ── Full Valid Production Config ─────────────────────────────────────
  it('should accept a fully valid production config with no errors', () => {
    process.env.NODE_ENV = 'production';
    const result = validateCorsConfig({
      allowedOrigins: ['https://myapp.com', 'https://admin.myapp.com'],
      allowedMethods: ['GET', 'POST', 'PUT'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      exposedHeaders: ['X-Request-Id'],
      allowCredentials: true,
      maxAge: 3600,
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });
});

// ==========================================
// 2. CORS SECURITY ENFORCEMENT TESTS
// ==========================================
describe('CORS Security Enforcement', () => {
  let originalEnv: string | undefined;

  beforeEach(() => {
    originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
    vi.restoreAllMocks();
  });

  it('should return a tracking ID with VS-CORS prefix', () => {
    const result = enforceCorsPolicy({
      allowedOrigins: ['https://example.com'],
    });
    expect(result.trackingId).toMatch(/^VS-CORS-[A-Z0-9]{4}$/);
  });

  it('should block invalid CORS config and return allowed=false', () => {
    const result = enforceCorsPolicy({
      allowedOrigins: ['*'],
      allowCredentials: true,
    });
    expect(result.allowed).toBe(false);
    expect(result.trackingId).toMatch(/^VS-CORS-[A-Z0-9]{4}$/);
    expect(result.validation.valid).toBe(false);
  });

  it('should allow valid config and return allowed=true', () => {
    const result = enforceCorsPolicy({
      allowedOrigins: ['https://example.com'],
      allowedMethods: ['GET', 'POST'],
      allowCredentials: true,
      maxAge: 3600,
    });
    expect(result.allowed).toBe(true);
    expect(result.validation.valid).toBe(true);
  });

  it('should log detailed errors in development mode for blocked config', () => {
    process.env.NODE_ENV = 'development';
    enforceCorsPolicy({
      allowedOrigins: ['*'],
      allowCredentials: true,
    });

    const errorCalls = (console.error as any).mock.calls.flat().join(' ');
    expect(errorCalls).toContain('CORS Security Errors');
    expect(errorCalls).toContain('CRITICAL');
  });

  it('should log minimal error in production mode for blocked config', () => {
    process.env.NODE_ENV = 'production';
    enforceCorsPolicy({
      allowedOrigins: ['*'],
      allowCredentials: true,
    });

    const errorCalls = (console.error as any).mock.calls.flat().join(' ');
    expect(errorCalls).toContain('blocked due to security policy violations');
    // Should NOT contain detailed error messages in production
    expect(errorCalls).not.toContain('CRITICAL');
  });

  it('should log warnings in development for valid but suboptimal config', () => {
    process.env.NODE_ENV = 'development';
    enforceCorsPolicy({
      allowedOrigins: ['*'],
    });

    const warnCalls = (console.warn as any).mock.calls.flat().join(' ');
    expect(warnCalls).toContain('CORS Security Warnings');
    expect(warnCalls).toContain('Tip');
  });
});
