/**
 * VibeShield CORS Security — Usage Example
 *
 * Demonstrates how to validate CORS configurations before applying them.
 *
 * Run with: npx tsx examples/cors-usage.ts
 */

import { validateCorsConfig } from '../src/core/cors-validator.js';
import { enforceCorsPolicy } from '../src/core/cors-security.js';

// === CASE 1: Wildcard origin (insecure) ===
console.log('=== CASE 1: Wildcard Origin ===');
const wildcardResult = validateCorsConfig({
  allowedOrigins: ['*'],
  allowCredentials: true,
});
console.log('Valid:', wildcardResult.valid);
console.log('Errors:', wildcardResult.errors);
console.log();

// === CASE 2: Sensitive headers exposed ===
console.log('=== CASE 2: Sensitive Headers Exposed ===');
const headersResult = validateCorsConfig({
  allowedOrigins: ['https://example.com'],
  exposedHeaders: ['Authorization', 'Set-Cookie'],
});
console.log('Valid:', headersResult.valid);
console.log('Errors:', headersResult.errors);
console.log();

// === CASE 3: Dangerous methods ===
console.log('=== CASE 3: Dangerous Methods ===');
const methodsResult = validateCorsConfig({
  allowedOrigins: ['https://example.com'],
  allowedMethods: ['GET', 'POST', 'TRACE'],
});
console.log('Valid:', methodsResult.valid);
console.log('Errors:', methodsResult.errors);
console.log();

// === CASE 4: Secure production config ===
console.log('=== CASE 4: Secure Production Config ===');
const secureResult = validateCorsConfig({
  allowedOrigins: ['https://myapp.com', 'https://admin.myapp.com'],
  allowedMethods: ['GET', 'POST', 'PUT'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['X-Request-Id'],
  allowCredentials: true,
  maxAge: 3600,
});
console.log('Valid:', secureResult.valid);
console.log('Warnings:', secureResult.warnings);
console.log();

// === CASE 5: Middleware Enforcement ===
console.log('=== CASE 5: Middleware Enforcement ===');
const enforcement = enforceCorsPolicy({
  allowedOrigins: ['*'],
  allowCredentials: true,
});
console.log('Allowed:', enforcement.allowed);
console.log('Tracking ID:', enforcement.trackingId);
console.log();

// === CASE 6: Secure enforcement ===
console.log('=== CASE 6: Secure Enforcement ===');
const secureEnforcement = enforceCorsPolicy({
  allowedOrigins: ['https://myapp.com'],
  allowedMethods: ['GET', 'POST'],
  allowCredentials: true,
  maxAge: 3600,
});
console.log('Allowed:', secureEnforcement.allowed);
console.log('Tracking ID:', secureEnforcement.trackingId);

console.log('\n💡 Tip: Always validate CORS configs at startup and use environment variables for allowed origins.');
