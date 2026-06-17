/**
 * VibeShield Strict Schema Validator — Usage Example
 *
 * Demonstrates how to validate and sanitize complex schemas,
 * enforce strict types, reject unknown fields, and use the middleware.
 *
 * Run with: npx tsx examples/schema-validation-usage.ts
 */

import { validateSchema, SchemaDefinition } from '../src/core/schema-validator.js';
import { validateRequest } from '../src/middleware/request-validator.js';

// Define a strict schema for a user registration payload
const registrationSchema: SchemaDefinition = {
  username: { type: 'string', required: true, min: 3, max: 20, trim: true },
  email: { type: 'string', required: true, format: 'email' },
  role: { type: 'string', required: true, enum: ['admin', 'user', 'guest'] },
  profile: {
    type: 'object',
    required: true,
    schema: {
      bio: { type: 'string', required: false, max: 150, trim: true },
      age: { type: 'number', required: true, min: 18, max: 120 }
    }
  },
  skills: {
    type: 'array',
    required: false,
    min: 1,
    elementSchema: {
      type: 'string',
      min: 2
    }
  }
};

console.log('--- CASE 1: Valid registration payload ---');
const validPayload = {
  username: '   john_doe   ', // will be trimmed
  email: 'john.doe@example.com',
  role: 'user',
  profile: {
    bio: 'Software engineer and security enthusiast.   ',
    age: 28
  },
  skills: ['TypeScript', 'Node.js', 'Express']
};

const result1 = validateSchema(validPayload, registrationSchema);
console.log('Valid:', result1.valid);
console.log('Sanitized Data:', JSON.stringify(result1.sanitizedData, null, 2));
console.log();

console.log('--- CASE 2: Invalid payload (missing required field, age too young) ---');
const invalidPayload = {
  username: 'jd', // too short (min 3)
  // email is missing
  role: 'superadmin', // not in enum
  profile: {
    age: 15 // under 18
  }
};

const result2 = validateSchema(invalidPayload, registrationSchema);
console.log('Valid:', result2.valid);
console.log('Errors:', JSON.stringify(result2.errors, null, 2));
console.log();

console.log('--- CASE 3: Whitelist rejection (unknown field at root and nested) ---');
const unknownFieldsPayload = {
  username: 'john_doe',
  email: 'john@example.com',
  role: 'user',
  isAdmin: true, // Unknown field!
  profile: {
    age: 30,
    twitterHandle: '@john_doe' // Unknown field in nested object!
  }
};

const result3 = validateSchema(unknownFieldsPayload, registrationSchema);
console.log('Valid:', result3.valid);
console.log('Errors:', JSON.stringify(result3.errors, null, 2));
console.log();

console.log('--- CASE 4: Type coercion prevention (string sent as number) ---');
const coercedPayload = {
  username: 'john_doe',
  email: 'john@example.com',
  role: 'user',
  profile: {
    age: '28' // Should be a number! Strict validator rejects string representation.
  }
};

const result4 = validateSchema(coercedPayload, registrationSchema);
console.log('Valid:', result4.valid);
console.log('Errors:', JSON.stringify(result4.errors, null, 2));
console.log();

console.log('--- CASE 5: Express Middleware Demo ---');
const expressMiddleware = validateRequest(registrationSchema);

// Mocking Express req, res, next
const mockReq: any = {
  body: {
    username: 'alice',
    email: 'alice@example.com',
    role: 'admin',
    profile: { age: 32 }
  }
};
const mockRes: any = {
  status(code: number) {
    console.log(`[Express] Response Status set to: ${code}`);
    return this;
  },
  json(data: any) {
    console.log('[Express] JSON Response:', JSON.stringify(data, null, 2));
    return this;
  }
};
const mockNext = () => console.log('[Express] next() called successfully! Request is valid.');

expressMiddleware(mockReq, mockRes, mockNext);
console.log('Sanitized Express Request Body:', mockReq.body);
console.log();

console.log('--- CASE 6: Next.js API Route Wrapper Demo ---');
const nextWrapper = validateRequest(registrationSchema);

const mockNextHandler = async (req: any) => {
  console.log('[Next.js] Inner handler invoked!');
  console.log('[Next.js] Sanitized Body:', req.sanitizedBody);
  return new Response(JSON.stringify({ success: true }));
};

const wrappedNextHandler = nextWrapper(mockNextHandler);

// Mocking standard Web Request
const mockNextRequest: any = {
  url: 'https://example.com/api/register',
  clone() {
    return {
      json: async () => ({
        username: 'bob_next',
        email: 'bob@next.js',
        role: 'guest',
        profile: { age: 21 }
      })
    };
  },
  json: async () => ({
    username: 'bob_next',
    email: 'bob@next.js',
    role: 'guest',
    profile: { age: 21 }
  })
};

wrappedNextHandler(mockNextRequest).then(async (response: any) => {
  const bodyText = await response.text();
  console.log(`[Next.js] Response Status: ${response.status}`);
  console.log(`[Next.js] Response Body: ${bodyText}`);
});
