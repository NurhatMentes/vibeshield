import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { handleError } from '../src/core/errorHandler.js';
import { sanitizeStackTrace } from '../src/core/stack-sanitizer.js';

// ==========================================
// 1. STACK TRACE SANITIZER UNIT TESTS
// ==========================================
describe('Stack Trace Sanitizer', () => {
  it('should redact Unix absolute file paths (/home/...)', () => {
    const dirty = 'Error: ENOENT at /home/user/secret/db_password.js:42:10';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('/home/user/secret/db_password');
    expect(clean).toContain('[PROJECT_ROOT]/...');
  });

  it('should redact macOS absolute file paths (/Users/...)', () => {
    const dirty = 'TypeError: Cannot read at /Users/nurhat/projects/vibeshield/src/db.ts:15:3';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('/Users/nurhat');
    expect(clean).toContain('[PROJECT_ROOT]/...');
  });

  it('should redact Windows absolute file paths (C:\\...)', () => {
    const dirty = 'Error at C:\\Users\\nurha\\Desktop\\Uygulamalar\\VibeShield\\src\\index.ts:10:5';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('C:\\Users\\nurha');
    expect(clean).toContain('[PROJECT_ROOT]/...');
  });

  it('should redact node_modules paths', () => {
    const dirty = 'at Module._compile (node_modules/typescript/lib/tsc.js:1234:56)';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('node_modules/typescript');
    expect(clean).toContain('[NODE_MODULES]/...');
  });

  it('should redact IPv4 addresses', () => {
    const dirty = 'Connection refused to 192.168.1.100:5432';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('192.168.1.100');
    expect(clean).toContain('[REDACTED_IP]');
  });

  it('should redact IPv6 addresses', () => {
    const dirty = 'Listening on 2001:0db8:85a3:0000:0000:8a2e:0370:7334';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('2001:0db8');
    expect(clean).toContain('[REDACTED_IP]');
  });

  it('should redact PostgreSQL connection strings', () => {
    const dirty = 'Failed to connect: postgres://admin:p4ssw0rd@db.internal.io:5432/production_db';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('postgres://');
    expect(clean).not.toContain('p4ssw0rd');
    expect(clean).not.toContain('production_db');
    expect(clean).toContain('[REDACTED_DB_INFO]');
  });

  it('should redact MongoDB connection strings', () => {
    const dirty = 'MongoError: mongodb+srv://root:secret@cluster0.abc123.mongodb.net/mydb';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('mongodb+srv://');
    expect(clean).not.toContain('secret');
    expect(clean).toContain('[REDACTED_DB_INFO]');
  });

  it('should redact Redis connection strings', () => {
    const dirty = 'RedisError: redis://default:authpass@redis.cloud:6380/0';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('redis://');
    expect(clean).not.toContain('authpass');
    expect(clean).toContain('[REDACTED_DB_INFO]');
  });

  it('should redact SQL table references in error messages', () => {
    const dirty = 'Error: relation "public.users_payment_info" does not exist. SELECT * FROM users_payment_info';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).toContain('[REDACTED_DB_INFO]');
  });

  it('should handle Error objects (not just strings)', () => {
    const err = new Error('Connection failed at /home/user/secret/db_password with IP 192.168.1.100');
    const clean = sanitizeStackTrace(err);
    expect(clean).not.toContain('/home/user/secret');
    expect(clean).not.toContain('192.168.1.100');
    expect(clean).toContain('[PROJECT_ROOT]/...');
    expect(clean).toContain('[REDACTED_IP]');
  });

  it('should handle a complex multi-line stack trace with multiple leaks', () => {
    const dirty = [
      'Error: FATAL: password authentication failed for user "admin"',
      '    at Connection.parseE (/home/deploy/app/node_modules/pg/lib/client.js:95:11)',
      '    at Connection._handleCommandComplete (C:\\Users\\nurha\\Projects\\api\\src\\db.ts:42:8)',
      '    at TLSSocket.<anonymous> (192.168.1.50:5432)',
      '  Connection string: postgres://admin:s3cret@10.0.0.5:5432/prod_orders',
    ].join('\n');

    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('/home/deploy');
    expect(clean).not.toContain('C:\\Users\\nurha');
    expect(clean).not.toContain('192.168.1.50');
    expect(clean).not.toContain('10.0.0.5');
    expect(clean).not.toContain('postgres://');
    expect(clean).not.toContain('s3cret');
  });
});

// ==========================================
// 2. ERROR HANDLER INTEGRATION TESTS
// ==========================================
describe('Global Exception Middleware', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return a masked error response with status 500 by default', async () => {
    const error = new Error('Database password was: secret_db_123');
    const response = handleError(error);

    expect(response.status).toBe(500);
    expect(response.headers.get('Content-Type')).toBe('application/json');

    const body = await response.json();
    expect(body.error).toBe('Internal Server Error');
    expect(body.code).toBe('INTERNAL_SERVER_ERROR');
    expect(body.trackingId).toMatch(/^VS-[A-Z0-9]{4}$/);
    expect(body.message).toContain('An unexpected error occurred. Please contact support with code:');
    expect(body.message).not.toContain('secret_db_123'); // Masked!
  });

  it('should show the raw error message if masking is disabled', async () => {
    const error = new Error('Failed to resolve host');
    const response = handleError(error, { maskErrors: false });

    const body = await response.json();
    expect(body.message).toBe('Failed to resolve host'); // Raw error message is returned
    expect(body.trackingId).toMatch(/^VS-[A-Z0-9]{4}$/);
  });

  it('should log a sanitized stack trace (not the raw one) to console', () => {
    const error = new Error('Crash at /home/user/secret/db_password with IP 192.168.1.100');
    handleError(error);

    expect(console.error).toHaveBeenCalled();
    const logOutput = (console.error as any).mock.calls[0][0];
    expect(logOutput).toContain('[VibeShield]');
    expect(logOutput).toContain('Unhandled exception captured:');
    // Ensure the logged output is SANITIZED
    expect(logOutput).not.toContain('/home/user/secret');
    expect(logOutput).not.toContain('192.168.1.100');
    expect(logOutput).toContain('[PROJECT_ROOT]/...');
    expect(logOutput).toContain('[REDACTED_IP]');
  });

  it('should not log to console if logging is disabled', () => {
    const error = new Error('Test crash');
    handleError(error, { logErrors: false });

    expect(console.error).not.toHaveBeenCalled();
  });
});
