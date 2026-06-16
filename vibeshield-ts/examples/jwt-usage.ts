/**
 * VibeShield JWT Security — Usage Example
 *
 * This file demonstrates how to integrate VibeShield's JWT secret
 * validator into your application's startup routine.
 *
 * Run with: npx tsx examples/jwt-usage.ts
 */

import { validateJwtSecret } from '../src/core/jwt-validator.js';
import { enforceJwtSecurity } from '../src/core/jwt-security.js';

console.log('=============================================================');
console.log('🔐 VIBESHIELD JWT SECRET VALIDATION DEMO');
console.log('=============================================================\n');

// ── Example 1: Weak AI-generated secret ─────────────────────────────
console.log('--- CASE 1: AI-Generated Weak Secret ---');
const weak = validateJwtSecret('mysecret');
console.log('Input:  "mysecret"');
console.log('Valid:', weak.valid);
console.log('Errors:', weak.errors);
console.log('');

// ── Example 2: Too-short secret ─────────────────────────────────────
console.log('--- CASE 2: Short Secret ---');
const short = validateJwtSecret('Ab3$z');
console.log('Input:  "Ab3$z" (5 chars)');
console.log('Valid:', short.valid);
console.log('Errors:', short.errors);
console.log('');

// ── Example 3: All-digit secret ─────────────────────────────────────
console.log('--- CASE 3: All-Digit Secret ---');
const digits = validateJwtSecret('98765432101234');
console.log('Input:  "98765432101234"');
console.log('Valid:', digits.valid);
console.log('Errors:', digits.errors);
console.log('');

// ── Example 4: Repeating pattern ────────────────────────────────────
console.log('--- CASE 4: Repeating Pattern ---');
const repeating = validateJwtSecret('abcabcabcabc');
console.log('Input:  "abcabcabcabc"');
console.log('Valid:', repeating.valid);
console.log('Errors:', repeating.errors);
console.log('');

// ── Example 5: Valid strong secret ──────────────────────────────────
console.log('--- CASE 5: Strong Secret (PASS) ---');
const strong = validateJwtSecret('aB3$xYz!qW8#mL2@pQ7&nK4*jR9^tF1%');
console.log('Input:  "aB3$xYz!qW8#mL2@pQ7&nK4*jR9^tF1%"');
console.log('Valid:', strong.valid);
console.log('Errors:', strong.errors);
console.log('Warnings:', strong.warnings);
console.log('');

// ── Example 6: Full middleware enforcement ──────────────────────────
console.log('--- CASE 6: Middleware Enforcement ---');
const result = enforceJwtSecurity(process.env.JWT_SECRET || 'changeme');
console.log('Allowed:', result.allowed);
console.log('Tracking ID:', result.trackingId);
console.log('');

console.log('=============================================================');
console.log('💡 TIP: Set a strong secret via env var:');
console.log('   export JWT_SECRET=$(openssl rand -base64 48)');
console.log('=============================================================');
