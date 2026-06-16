/**
 * VibeShield JWT Security Middleware
 *
 * Intercepts JWT secret usage and enforces validation before any token
 * operation can proceed. In production, blocks insecure secrets entirely.
 * In development, logs detailed warnings with tracking IDs.
 *
 * Zero external dependencies.
 */

import { validateJwtSecret, JwtValidationResult } from './jwt-validator.js';

/**
 * Generates a tracking ID of format VS-JWT-XXXX.
 */
function generateJwtTrackingId(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let suffix = '';
  for (let i = 0; i < 4; i++) {
    suffix += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `VS-JWT-${suffix}`;
}

/**
 * Environment detection: true when NODE_ENV is "production".
 */
function isProduction(): boolean {
  return typeof process !== 'undefined' && process.env?.NODE_ENV === 'production';
}

/** Result returned by the JWT security guard. */
export interface JwtSecurityCheckResult {
  allowed: boolean;
  trackingId: string;
  validation: JwtValidationResult;
}

/**
 * Validates a JWT secret and enforces security policy.
 *
 * **Development mode:** Logs detailed warnings to the console but allows
 * the operation to proceed if there are only warnings (no errors).
 *
 * **Production mode:** Blocks operations with insecure secrets and logs
 * a generic message with a tracking ID. The secret value is NEVER logged.
 *
 * @param secret - The JWT secret to validate.
 * @returns A {@link JwtSecurityCheckResult} indicating whether the operation is allowed.
 */
export function enforceJwtSecurity(secret: string | undefined): JwtSecurityCheckResult {
  const trackingId = generateJwtTrackingId();
  const validation = validateJwtSecret(secret);
  const prod = isProduction();

  if (!validation.valid) {
    if (prod) {
      // Production: generic message, NEVER log the secret value
      console.error(
        `[VibeShield] [${trackingId}] JWT security check FAILED. ` +
        `${validation.errors.length} error(s) detected. Application should not start with an insecure JWT secret.`
      );
    } else {
      // Development: detailed output for developer feedback
      console.error(`\n⚠️  [VIBESHIELD JWT SECURITY CHECK FAILED] ⚠️`);
      console.error(`Tracking ID: ${trackingId}`);
      console.error(`\nErrors:`);
      for (const err of validation.errors) {
        console.error(`  ❌ ${err}`);
      }
      if (validation.warnings.length > 0) {
        console.error(`\nWarnings:`);
        for (const warn of validation.warnings) {
          console.error(`  ⚠️  ${warn}`);
        }
      }
      console.error(
        `\n💡 Fix: Set a strong secret via environment variable, e.g.:\n` +
        `   export JWT_SECRET=$(openssl rand -base64 48)\n`
      );
    }

    return { allowed: false, trackingId, validation };
  }

  // Valid but may have warnings
  if (validation.warnings.length > 0 && !prod) {
    console.warn(`\n⚠️  [VIBESHIELD JWT SECURITY WARNINGS] ⚠️`);
    console.warn(`Tracking ID: ${trackingId}`);
    for (const warn of validation.warnings) {
      console.warn(`  ⚠️  ${warn}`);
    }
    console.warn('');
  }

  return { allowed: true, trackingId, validation };
}
