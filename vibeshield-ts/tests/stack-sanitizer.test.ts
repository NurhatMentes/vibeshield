import { describe, it, expect } from 'vitest';
import { sanitizeStackTrace } from '../src/core/stack-sanitizer.js';

describe('Stack Trace Sanitizer', () => {
  // 1. Unix home path redaction
  it('should redact Unix /home/... absolute paths', () => {
    const dirty = 'Error: ENOENT at /home/user/secret/db_password.js:42:10';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('/home/user/secret/db_password');
    expect(clean).toContain('[PROJECT_ROOT]/...');
  });

  // 2. macOS path redaction
  it('should redact macOS /Users/... absolute paths', () => {
    const dirty = 'TypeError: Cannot read at /Users/nurhat/projects/vibeshield/src/db.ts:15:3';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('/Users/nurhat');
    expect(clean).toContain('[PROJECT_ROOT]/...');
  });

  // 3. Windows path redaction
  it('should redact Windows C:\\... absolute paths', () => {
    const dirty = 'Error at C:\\Users\\nurha\\Desktop\\Uygulamalar\\VibeShield\\src\\index.ts:10:5';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('C:\\Users\\nurha');
    expect(clean).toContain('[PROJECT_ROOT]/...');
  });

  // 4. node_modules path redaction
  it('should redact node_modules/... paths', () => {
    const dirty = 'at Module._compile (node_modules/typescript/lib/tsc.js:1234:56)';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('node_modules/typescript');
    expect(clean).toContain('[NODE_MODULES]/...');
  });

  // 5. IPv4 address redaction
  it('should redact IPv4 addresses', () => {
    const dirty = 'Connection refused to 192.168.1.100:5432';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('192.168.1.100');
    expect(clean).toContain('[REDACTED_IP]');
  });

  // 6. IPv6 address redaction
  it('should redact IPv6 addresses', () => {
    const dirty = 'Listening on 2001:0db8:85a3:0000:0000:8a2e:0370:7334';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('2001:0db8');
    expect(clean).toContain('[REDACTED_IP]');
  });

  // 7. Postgres connection string redaction
  it('should redact PostgreSQL connection strings', () => {
    const dirty = 'Failed to connect: postgres://admin:p4ssw0rd@db.internal.io:5432/production_db';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('postgres://');
    expect(clean).not.toContain('p4ssw0rd');
    expect(clean).not.toContain('production_db');
    expect(clean).toContain('[REDACTED_DB_INFO]');
  });

  // 8. MongoDB connection string redaction
  it('should redact MongoDB connection strings', () => {
    const dirty = 'MongoError: mongodb+srv://root:secret@cluster0.abc123.mongodb.net/mydb';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('mongodb+srv://');
    expect(clean).not.toContain('secret');
    expect(clean).toContain('[REDACTED_DB_INFO]');
  });

  // 9. Redis connection string redaction
  it('should redact Redis connection strings', () => {
    const dirty = 'RedisError: redis://default:authpass@redis.cloud:6380/0';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('redis://');
    expect(clean).not.toContain('authpass');
    expect(clean).toContain('[REDACTED_DB_INFO]');
  });

  // 10. SQL table reference redaction
  it('should redact SQL table/schema references in error messages', () => {
    const dirty = 'Error: relation does not exist. SELECT * FROM users_payment_info WHERE id = 1';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).toContain('[REDACTED_DB_INFO]');
    expect(clean).not.toContain('users_payment_info');
  });

  // 11. Error object handling
  it('should handle Error objects (not just strings)', () => {
    const err = new Error('Connection failed at /home/user/secret/db_password with IP 192.168.1.100');
    const clean = sanitizeStackTrace(err);
    expect(clean).not.toContain('/home/user/secret');
    expect(clean).not.toContain('192.168.1.100');
    expect(clean).toContain('[PROJECT_ROOT]/...');
    expect(clean).toContain('[REDACTED_IP]');
  });

  // 12. String input handling
  it('should handle plain string input (not an Error object)', () => {
    // IP inside DB URI gets absorbed by DB pattern; use a separate standalone IP to assert IP redaction
    const dirty = 'Raw log line: DB at postgres://user:pass@db-host/appdb crashed, client was 192.168.99.1';
    const clean = sanitizeStackTrace(dirty);
    expect(clean).not.toContain('postgres://');
    expect(clean).not.toContain('pass');
    expect(clean).not.toContain('192.168.99.1');
    expect(clean).toContain('[REDACTED_DB_INFO]');
    expect(clean).toContain('[REDACTED_IP]');
  });

  // 13. Complex multiline stack trace
  it('should redact all sensitive data in a complex multiline Node.js stack trace', () => {
    const dirty = [
      'Error: FATAL: password authentication failed for user "admin"',
      '    at Connection.parseE (/home/deploy/app/node_modules/pg/lib/client.js:95:11)',
      '    at Connection._handleCommandComplete (C:\\Users\\nurha\\Projects\\api\\src\\db.ts:42:8)',
      '    at TLSSocket.<anonymous> (192.168.1.50:5432)',
      '    at Object.<anonymous> (node_modules/express/lib/router/index.js:284:15)',
      '  Connection string: postgres://admin:s3cret@10.0.0.5:5432/prod_orders',
    ].join('\n');

    const clean = sanitizeStackTrace(dirty);

    expect(clean).not.toContain('/home/deploy');
    expect(clean).not.toContain('C:\\Users\\nurha');
    expect(clean).not.toContain('192.168.1.50');
    expect(clean).not.toContain('10.0.0.5');
    expect(clean).not.toContain('postgres://');
    expect(clean).not.toContain('s3cret');
    expect(clean).not.toContain('node_modules/express');
    expect(clean).toContain('[PROJECT_ROOT]/...');
    expect(clean).toContain('[REDACTED_IP]');
    expect(clean).toContain('[REDACTED_DB_INFO]');
    expect(clean).toContain('[NODE_MODULES]/...');
  });

  it('should redact container paths', () => {
    const stack = 'Error at /app/src/index.js:10:5';
    expect(sanitizeStackTrace(stack)).toContain('[PROJECT_ROOT]');
    expect(sanitizeStackTrace(stack)).not.toContain('/app/');
  });

  it('should redact Kubernetes paths', () => {
    const stack = 'Error at /srv/app/dist/bundle.js:1:1';
    expect(sanitizeStackTrace(stack)).toContain('[PROJECT_ROOT]');
    expect(sanitizeStackTrace(stack)).not.toContain('/srv/');
  });
});
