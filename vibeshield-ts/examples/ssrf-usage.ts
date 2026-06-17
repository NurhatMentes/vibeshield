/**
 * VibeShield SSRF URL Validator — Usage Example
 *
 * This file demonstrates how to use the SSRF URL Validator and security middleware
 * to prevent Server-Side Request Forgery vulnerabilities.
 *
 * Run with: npx tsx examples/ssrf-usage.ts
 */

import { validateUrl, enforceSafeUrl, VibeShieldSSRFError } from '../src/index.js';

console.log('=============================================================');
console.log('🛡️ VIBESHIELD SSRF URL VALIDATOR DEMO');
console.log('=============================================================\n');

const testUrls = [
  'https://api.github.com/users/octocat',
  'http://localhost',
  'http://127.0.0.1/admin',
  'http://0x7f.0.0.1/db',
  'http://2852039166', // 169.254.169.254 in decimal
  'http://10.0.0.1',
  'http://[::1]',
  'http://[fe80::1]',
  'http://[::ffff:127.0.0.1]',
  'http://googlе.com', // Cyrillic 'е' homograph
  'https://vibeshield.security/docs'
];

console.log('--- 1. Validation Checks (non-throwing) ---');
for (const url of testUrls) {
  const result = validateUrl(url);
  console.log(`URL: ${url}`);
  console.log(`  Safe: ${result.safe ? '✅ Yes' : '❌ No'}`);
  if (result.reason) {
    console.log(`  Reason: ${result.reason}`);
  }
  console.log();
}

console.log('--- 2. Enforcing Safe URL (throws on unsafe) ---');
for (const url of testUrls) {
  try {
    enforceSafeUrl(url);
    console.log(`✅ Allowed URL: ${url}`);
  } catch (error) {
    if (error instanceof VibeShieldSSRFError) {
      console.log(`❌ Blocked URL: ${error.url}`);
      console.log(`   Exception: ${error.name}`);
      console.log(`   Message: ${error.message}`);
      console.log(`   Reason: ${error.reason}`);
    } else {
      console.log(`💥 Unknown Error: ${(error as any).message}`);
    }
  }
  console.log();
}

console.log('=============================================================');
console.log('💡 TIP: Use enforceSafeUrl() before making outbound requests');
console.log('   with fetch(), axios, or node http modules.');
console.log('=============================================================');
