/**
 * VibeShield Password Policy Protector — Usage Example
 *
 * This file demonstrates how to use the Password Policy Protector to validate
 * passwords, detect weaknesses, and generate policy reports.
 *
 * Run with: npx tsx examples/password-usage.ts
 */

import { validatePassword, generatePasswordPolicyReport } from '../src/index.js';

console.log('=============================================================');
console.log('🛡️ VIBESHIELD PASSWORD POLICY PROTECTOR DEMO');
console.log('=============================================================\n');

const context = {
  username: 'john_doe',
  email: 'john.doe@example.com',
  firstName: 'John',
  lastName: 'Doe',
  birthDate: '1990-05-15'
};

const passwordsToTest = [
  // Very weak / empty
  '',
  // Blacklisted common password
  'password123',
  // Short password
  'Ab1!',
  // Lacking complexity
  'abcdefghijklmnop',
  // Context leak
  'Securejohn_doe12!',
  // BirthDate part context leak
  'Pass1990!',
  // Repetitive characters
  'Abcd1234!!!xyz',
  // Sequential characters
  'Abc123xyz!!!',
  // Secure password
  'Tr0ub4dor&3Secure!'
];

console.log(`User Context for Leak Detection:`);
console.log(JSON.stringify(context, null, 2));
console.log('\n');

for (const password of passwordsToTest) {
  console.log(`Analyzing: "${password}"`);
  const report = generatePasswordPolicyReport(password, context);
  console.log(report);
  console.log('\n');
}

console.log('=============================================================');
console.log('💡 TIP: Use this protector in registration and password change');
console.log('   endpoints to prevent users from selecting weak passwords.');
console.log('=============================================================');
