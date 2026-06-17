/**
 * VibeShield CORS Security Enforcement
 *
 * Wraps the CORS validator with environment-aware logging and tracking.
 *
 * @module cors-security
 */

import { validateCorsConfig, CorsConfig, CorsValidationResult } from './cors-validator.js';

export interface CorsSecurityCheckResult {
  allowed: boolean;
  trackingId: string;
  validation: CorsValidationResult;
}

function generateCorsTrackingId(): string {
  const random = Math.random().toString(36).substring(2, 6).toUpperCase();
  return `VS-CORS-${random}`;
}

function isProduction(): boolean {
  const env = (process.env.NODE_ENV || '').toLowerCase();
  return env === 'production';
}

/**
 * Enforces CORS security policy with environment-aware logging.
 *
 * @param config - The CORS configuration to enforce
 * @returns {CorsSecurityCheckResult} Security check result with tracking ID
 */
export function enforceCorsPolicy(config: CorsConfig): CorsSecurityCheckResult {
  const trackingId = generateCorsTrackingId();
  const validation = validateCorsConfig(config);
  const prod = isProduction();

  if (!validation.valid) {
    if (prod) {
      console.error(`[VibeShield] [${trackingId}] CORS configuration blocked due to security policy violations.`);
    } else {
      console.error(`\n❌ [VibeShield] CORS Security Errors (${trackingId}):`);
      for (const error of validation.errors) {
        console.error(`   • ${error}`);
      }
    }
    return { allowed: false, trackingId, validation };
  }

  if (validation.warnings.length > 0 && !prod) {
    console.warn(`\n⚠️ [VibeShield] CORS Security Warnings (${trackingId}):`);
    for (const warning of validation.warnings) {
      console.warn(`   • ${warning}`);
    }
    console.warn('💡 Tip: Review CORS configuration before deploying to production.\n');
  }

  return { allowed: true, trackingId, validation };
}
