/**
 * VibeShield Deserialization & Prototype Pollution Protection — Usage Example
 *
 * This file demonstrates how to use the Deserialization Protection utilities to:
 * 1. Safe JSON parsing with prototype pollution protection.
 * 2. Deep JSON nesting DoS prevention.
 * 3. Static scanning for dangerous libraries (e.g. node-serialize) and eval execution.
 *
 * Run with: npx tsx examples/deserialization-usage.ts
 */

import {
  safeJsonParse,
  detectUnsafeDeserialization,
  enforceSafeJson,
  VibeShieldDeserializationError
} from '../src/index.js';

console.log('=============================================================');
console.log('🛡️ VIBESHIELD DESERIALIZATION & PROTOTYPE POLLUTION PROTECTION');
console.log('=============================================================\n');

// 1. Prototype Pollution Prevention
console.log('--- 1. Prototype Pollution Prevention ---');
const maliciousPayload = `{
  "user": "Alice",
  "role": "guest",
  "__proto__": {
    "isAdmin": true
  },
  "constructor": {
    "prototype": {
      "isSuperAdmin": true
    }
  }
}`;

console.log('Malicious payload containing prototype pollution:');
console.log(maliciousPayload);

try {
  // Using standard JSON.parse can cause issues depending on how property access is handled
  const normalParsed = JSON.parse(maliciousPayload);
  console.log(`\nStandard JSON.parse:`);
  console.log(`  - user: ${normalParsed.user}`);
  console.log(`  - role: ${normalParsed.role}`);
  console.log(`  - __proto__.isAdmin: ${normalParsed.__proto__?.isAdmin}`);

  // Using safeJsonParse
  const safeParsed = safeJsonParse<any>(maliciousPayload);
  console.log(`\n🛡️ VibeShield safeJsonParse:`);
  console.log(`  - user: ${safeParsed.user}`);
  console.log(`  - role: ${safeParsed.role}`);
  console.log(`  - __proto__: ${safeParsed.__proto__}`); // Should be undefined
  console.log(`  - constructor: ${safeParsed.constructor}`); // Should be undefined
  console.log(`  - Global Object Pollution Check (isAdmin): ${(Object.prototype as any).isAdmin}`); // Should be undefined
} catch (error) {
  console.log(`❌ Parse failed: ${(error as any).message}`);
}
console.log('\n');

// 2. Nesting Depth DoS Protection
console.log('--- 2. Nesting Depth DoS Protection ---');
// Let's create a nested structure
let nestedPayload = '{"value": "leaf"}';
for (let i = 0; i < 70; i++) {
  nestedPayload = `{"level_${i}": ${nestedPayload}}`;
}

console.log('Attempting to parse payload with depth of 71 layers (default max is 64):');
try {
  safeJsonParse(nestedPayload);
  console.log('✅ Parsed successfully? (Should not happen with default 64 max depth!)');
} catch (error) {
  if (error instanceof VibeShieldDeserializationError) {
    console.log(`🛡️ Blocked: ${error.message}`);
  } else {
    console.log(`💥 Unknown Error: ${(error as any).message}`);
  }
}

console.log('\nParsing with custom max depth set to 80:');
try {
  const parsed = safeJsonParse<any>(nestedPayload, { maxDepth: 80 });
  console.log('✅ Successfully parsed deep JSON payload by overriding maxDepth limit!');
} catch (error) {
  console.log(`❌ Failed: ${(error as any).message}`);
}
console.log('\n');

// 3. Middleware Helper enforceSafeJson
console.log('--- 3. Middleware Helper (enforceSafeJson) ---');
const emptyBody = '   ';
console.log(`Parsing empty body: "${emptyBody}"`);
const parsedEmpty = enforceSafeJson(emptyBody);
console.log('Result:', parsedEmpty); // Should be {}

const validBody = '{"active": true}';
console.log(`Parsing valid body: "${validBody}"`);
const parsedValid = enforceSafeJson(validBody);
console.log('Result:', parsedValid);
console.log('\n');

// 4. Static Scanning for Unsafe Deserialization
console.log('--- 4. Static Scanning for Unsafe Deserialization ---');
const vulnerableSourceCode = `
import serialize from 'serialize-to-js';
const express = require('express');
const app = express();

app.post('/unserialize', (req, res) => {
  const payload = req.body.data;
  // Dangerous: eval with unserialize keyword
  const obj = eval("unserialize(" + payload + ")");
  
  // Dangerous: using serialize-to-js directly
  const data = serialize.deserialize(payload);
  
  res.send("Done");
});
`;

console.log('Scanning source code for unsafe deserialization practices...');
const scanResult = detectUnsafeDeserialization(vulnerableSourceCode);
console.log(`Safe status: ${scanResult.safe ? '✅ SAFE' : '❌ VULNERABLE'}`);
console.log(`Findings count: ${scanResult.findings.length}`);
for (const finding of scanResult.findings) {
  console.log(`  - Line ${finding.line}: [${finding.severity.toUpperCase()}] Pattern: "${finding.pattern}"`);
  console.log(`    Code: \`${finding.originalCode}\``);
  console.log(`    Suggestion: ${finding.suggestion}`);
}
console.log('\n=============================================================');
