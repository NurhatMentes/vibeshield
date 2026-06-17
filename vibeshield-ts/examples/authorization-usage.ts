/**
 * VibeShield Authorization & Access Control Protector — Usage Example
 *
 * This file demonstrates how to use the checkPermission, validateResourceOwnership,
 * requireAuth middleware, and detectMissingAuthMiddleware static scanner.
 *
 * Run with: npx tsx examples/authorization-usage.ts
 */

import {
  checkPermission,
  validateResourceOwnership,
  detectMissingAuthMiddleware,
  requireAuth,
  UserContext
} from '../src/index.js';

console.log('=============================================================');
console.log('🛡️ VIBESHIELD AUTHORIZATION & ACCESS CONTROL DEMO');
console.log('=============================================================\n');

// 1. Context definitions
const adminUser: UserContext = {
  id: 1,
  role: 'admin',
  permissions: []
};

const standardUser: UserContext = {
  id: 2,
  role: 'user',
  permissions: ['posts:write', 'settings:read']
};

const guestUser: UserContext = {
  id: 3,
  role: 'guest',
  permissions: []
};

console.log('--- 1. Role & Permission Matrix Checks ---');
console.log(`Admin access to "users:delete": ${checkPermission(adminUser, 'users', 'delete') ? '✅ Allowed' : '❌ Denied'}`);
console.log(`Standard User access to "posts:write": ${checkPermission(standardUser, 'posts', 'write') ? '✅ Allowed' : '❌ Denied'}`);
console.log(`Standard User access to "posts:delete": ${checkPermission(standardUser, 'posts', 'delete') ? '✅ Allowed' : '❌ Denied'}`);
console.log(`Guest access to "posts:read": ${checkPermission(guestUser, 'posts', 'read') ? '✅ Allowed' : '❌ Denied'}`);
console.log(`Guest access to "settings:read": ${checkPermission(guestUser, 'settings', 'read') ? '✅ Allowed' : '❌ Denied'}`);
console.log();

console.log('--- 2. Direct/Wildcard Permission Overrides ---');
const wildcardUser: UserContext = {
  id: 4,
  role: 'guest',
  permissions: ['settings:*']
};
console.log(`Wildcard user (guest + "settings:*") access to "settings:admin": ${checkPermission(wildcardUser, 'settings', 'admin') ? '✅ Allowed' : '❌ Denied'}`);
console.log();

console.log('--- 3. IDOR / Resource Ownership Validation ---');
const ownerId = 42;
const nonOwnerId = 99;
console.log(`Owner (User 42) accessing resource 100 owned by 42: ${validateResourceOwnership(ownerId, 100, ownerId) ? '✅ Allowed' : '❌ Denied'}`);
console.log(`Non-Owner (User 99) accessing resource 100 owned by 42: ${validateResourceOwnership(nonOwnerId, 100, ownerId) ? '✅ Allowed' : '❌ Denied'}`);
console.log(`Admin bypassing resource ownership: ${validateResourceOwnership(nonOwnerId, 100, ownerId, 'admin') ? '✅ Allowed (Bypassed)' : '❌ Denied'}`);
console.log();

console.log('--- 4. Code Scanning for Missing Auth Middleware ---');
const unsafeExpressCode = `
const express = require('express');
const router = express.Router();

// Critical: Admin route missing auth checks
router.get('/admin/dashboard', (req, res) => {
  res.send('Dashboard');
});

// Warning: User endpoint missing ownership checks
router.get('/api/users/:id', (req, res) => {
  res.send('User info');
});
`;

const scanResult = detectMissingAuthMiddleware(unsafeExpressCode);
console.log(`Scan Safe: ${scanResult.safe ? '✅ Yes' : '❌ No'}`);
console.log(`Findings count: ${scanResult.findings.length}`);
scanResult.findings.forEach(f => {
  console.log(`- [Line ${f.line}] [${f.severity.toUpperCase()}] ${f.pattern}`);
  console.log(`  Code: "${f.originalCode}"`);
  console.log(`  Suggestion: ${f.suggestion}`);
});
console.log();

console.log('--- 5. Middleware Simulation (Express & Next.js) ---');
// Simulating an Express middleware run - IDOR Blocked (User 2 tries to access resource owned by 42)
const reqBlocked = {
  user: standardUser,
  params: { id: '100' },
  body: { ownerId: '42' }
};

try {
  const expressMiddleware = requireAuth({ roles: ['user'], resourceIdParam: 'id' });
  expressMiddleware(reqBlocked, {}, () => {
    console.log('✅ Express Middleware passed unexpectedly.');
  });
} catch (err: any) {
  console.log(`🛡️ Express Middleware blocked unauthorized access: ${err.message}`);
}

// Simulating an Express middleware run - Allowed (User 2 tries to access resource owned by 2)
const reqAllowed = {
  user: standardUser,
  params: { id: '100' },
  body: { ownerId: '2' }
};

try {
  const expressMiddleware = requireAuth({ roles: ['user'], resourceIdParam: 'id' });
  expressMiddleware(reqAllowed, {}, () => {
    console.log('✅ Express Middleware passed for User 2 accessing own resource.');
  });
} catch (err: any) {
  console.log(`❌ Express Middleware failed: ${err.message}`);
}

