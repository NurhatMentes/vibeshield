# 🛡️ VibeShield

**Runtime security for AI-generated applications.**

> Zero-dependency runtime security for Next.js (TypeScript) and Python (FastAPI/Flask) applications —  
> featuring enterprise-grade protection, performance optimization, and a financial circuit-breaker layer.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.9+-green.svg)](https://www.python.org/)
[![CI](https://github.com/NurhatMentes/vibeshield/actions/workflows/test.yml/badge.svg)](https://github.com/NurhatMentes/vibeshield/actions)

---

## What Problem Does VibeShield Solve?

Modern AI coding assistants can generate working applications in minutes.  
They can also generate:

- SQL injection vulnerabilities
- Missing validation layers
- Exposed stack traces
- Weak JWT secrets
- Recursive API loops
- Expensive cloud billing incidents

VibeShield is a runtime protection layer designed specifically to harden AI-generated applications before those mistakes reach production.

---

## Quick Overview

VibeShield is a lightweight security layer that detects and blocks hidden vulnerabilities in code written with AI assistants (Cursor, Claude, GitHub Copilot) at runtime — while also multiplying your performance and keeping costs under control.

### Key Features

- 🔒 **Stack Trace Sanitizer** — Auto-mask file paths, IPs, and DB info in error messages
- 🔐 **JWT Security Validator** — Detect weak and hardcoded JWT secrets
- 🛡️ SQL/NoSQL Injection, XSS, Command Injection protection
- 🔐 AES-256-GCM transparent encryption
- ⚡ 98.59% faster response times (LRU cache)
- 💸 VibeBudgeter — AI/API spending limits
- 📊 Nanosecond-precision performance monitoring
- ✅ Recursive deep validation (nested objects/arrays)
- 🎯 Zero-dependency core (serverless-friendly)

---

## Installation

### TypeScript / Next.js

```bash
npm install @vibeshield/core
# or
pnpm add @vibeshield/core
# or
yarn add @vibeshield/core
```

### Python / FastAPI / Flask

```bash
pip install vibeshield-core
# or
poetry add vibeshield-core
```

---

## Getting Started in 60 Seconds

### TypeScript Example

```typescript
import { vibeShield } from '@vibeshield/core';

export const POST = vibeShield(async (req) => {
  const data = await req.json();
  await db.payment.create({ data });
  return Response.json({ status: 'success', data });
}, {
  security: {
    sanitizeBody: true,
    stackTraceProtection: true,
    validateJwtSecret: true
  },
  cache: { enabled: true, ttl: 60 },
  validationSchema: {
    email: { type: 'string', format: 'email', required: true },
    amount: { type: 'number', min: 1 }
  },
  crypto: {
    secretKey: process.env.VIBESHIELD_SECRET!,
    encryptFields: ['creditCard', 'ssn']
  },
  budget: {
    enabled: true,
    maxDailyRequests: 1000,
    maxDailyCost: 10.00
  }
});
```

### Python Example

```python
from fastapi import FastAPI
from vibeshield.core import VibeShieldASGIMiddleware

app = FastAPI()

app.add_middleware(
    VibeShieldASGIMiddleware,
    sanitize_body=True,
    stack_trace_protection=True,
    validate_jwt_secret=True,
    cache_enabled=True,
    cache_ttl=60,
    validation_schema={
        "email": {"type": "string", "format": "email", "required": True},
        "amount": {"type": "number", "min": 1}
    },
    secret_key="your-32-byte-secret-key",
    encrypt_fields=["credit_card", "ssn"],
    budget_enabled=True,
    max_daily_requests=1000
)
```

---

## Security Features

### Stack Trace Sanitizer

When AI-generated code throws errors, stack traces can leak file paths, IP addresses, and database credentials. VibeShield automatically masks all of them.

**Protected data:**

- ✅ Project directories (`/home/user/project/` → `[PROJECT_ROOT]/`)
- ✅ Environment variables
- ✅ IP addresses (IPv4 / IPv6)
- ✅ Database connection strings
- ✅ Node modules / venv paths
- ✅ SQL table and column names

**Before / After:**

```
// Before (Unsafe):
Error: Database connection failed
  at /home/user/myapp/src/db.ts:42:15
  postgres://admin:password123@192.168.1.100:5432/mydb

// After (Safe):
Error: Database connection failed
  at [PROJECT_ROOT]/src/db.ts:42:15
  [REDACTED_DB_INFO]
```

---

### JWT Security Validator

Detects and blocks weak JWT secrets produced by AI assistants.

**Detected issues:**

- ❌ Hardcoded values (`"secret"`, `"123456"`, `"password"`)
- ❌ Short secrets (< 10 characters)
- ❌ Low entropy (Shannon entropy < 3.5)
- ❌ Repeating patterns (`aaaaaa`, `123123`)
- ❌ Sequential patterns (`abc`, `123`, `qwerty`)
- ⚠️ Missing environment variable usage

```typescript
import { validateJwtSecret } from '@vibeshield/core';

const result = validateJwtSecret('myweaksecret123');

if (!result.valid) {
  console.error('JWT Security Issues:', result.errors);
  // ["Contains hardcoded value", "Low entropy detected"]
}
```

---

### Injection Protection

| Attack Type       | Example Payload              | VibeShield Action              |
|-------------------|------------------------------|--------------------------------|
| SQL Injection      | `' OR '1'='1`               | `' OR ''1''=''1` (escaped)     |
| NoSQL Injection    | `{"$ne": "admin"}`          | `{}` (stripped)                |
| XSS               | `<script>alert(1)</script>` | `Nice post!` (sanitized)       |
| Command Injection  | `; rm -rf /`                | Blocked                        |

---

## Performance

### TypeScript (Next.js)

| Metric        | Without VibeShield | With VibeShield | Improvement    |
|---------------|--------------------|-----------------|----------------|
| Response Time | 9.23 ms/req        | 0.13 ms/req     | 70.7x faster   |
| DB Latency    | 9,233 ms           | 130 ms          | 98.59% reduced |
| DB Queries    | 1,000              | 1               | 99.90% reduced |

### Python (FastAPI)

| Metric         | Without VibeShield | With VibeShield | Improvement    |
|----------------|--------------------|-----------------|----------------|
| Response Time  | 15.49 ms/req       | 0.55 ms/req     | 27.7x faster   |
| Execution Time | 15,492 ms          | 558 ms          | 96.39% reduced |
| DB Queries     | 1,000              | 1               | 99.90% reduced |

---

## Advanced Features

### VibeBudgeter — Financial Circuit Breaker

Stop runaway AI/API costs automatically.

```typescript
budget: {
  enabled: true,
  maxDailyRequests: 1000,
  maxDailyCost: 10.00,  // USD
  costPerRequest: 0.01
}

// Output when exceeded:
// 🚨 [VIBESHIELD BUDGET EXCEEDED]
// Daily threshold reached ($10.00).
// Request blocked automatically.
```

---

### Transparent Encryption

Sensitive fields are automatically encrypted with AES-256-GCM.

```typescript
crypto: {
  secretKey: process.env.VIBESHIELD_SECRET!,
  encryptFields: ['creditCard', 'ssn', 'password']
}

// Stored in database:
{ creditCard: "gcm:enc:a1b2c3d4..." }

// Returned in response (for authorized users):
{ creditCard: "1234-5678-9012-3456" }
```

---

### Performance Monitoring

Track your endpoints with nanosecond precision.

```typescript
performanceThresholdMs: 200

// Output:
// ⚠️ [VIBESHIELD PERFORMANCE WARNING]
// Route: POST /api/heavy-calculation
// Duration: 558 ms (threshold: 200 ms exceeded)
```

---

### Recursive Validation

Validate deeply nested objects and arrays.

```typescript
validationSchema: {
  user: {
    type: 'object',
    schema: {
      profile: {
        type: 'object',
        schema: {
          email: { type: 'string', format: 'email' }
        }
      }
    }
  }
}

// Validation error:
// { "errors": { "user.profile.email": "Invalid email format" } }
```

---

## API Reference

### Core Options

| Option                          | Type       | Description                  | Default |
|---------------------------------|------------|------------------------------|---------|
| `security.sanitizeBody`         | `boolean`  | Input sanitization           | `true`  |
| `security.stackTraceProtection` | `boolean`  | Stack trace masking          | `true`  |
| `security.validateJwtSecret`    | `boolean`  | JWT secret validation        | `true`  |
| `cache.enabled`                 | `boolean`  | Enable LRU cache             | `false` |
| `cache.ttl`                     | `number`   | Cache TTL (seconds)          | `60`    |
| `validationSchema`              | `object`   | JSON schema                  | `null`  |
| `crypto.secretKey`              | `string`   | 32-byte encryption key       | `null`  |
| `crypto.encryptFields`          | `string[]` | Fields to encrypt            | `[]`    |
| `budget.enabled`                | `boolean`  | Enable budget control        | `false` |
| `budget.maxDailyRequests`       | `number`   | Max requests per day         | `1000`  |
| `performanceThresholdMs`        | `number`   | Slow endpoint threshold (ms) | `200`   |

### Validation Schema Format

```typescript
{
  fieldName: {
    type: 'string' | 'number' | 'boolean' | 'object' | 'array',
    required: boolean,
    format?: 'email' | 'uuid' | 'url' | 'date',
    min?: number,
    max?: number,
    pattern?: RegExp,
    schema?: { /* nested object */ },
    elementSchema?: { /* array items */ }
  }
}
```

---

## Tests

### TypeScript

```bash
cd vibeshield-ts
npm test

# With coverage
npm run test:coverage

# Specific test file
npm test -- jwt-validator.test.ts
```

### Python

```bash
cd vibeshield-python
pytest

# With coverage
pytest --cov=src --cov-report=html

# Specific test file
pytest tests/test_jwt_validator.py -v
```

### Test Coverage — 70+ scenarios

| Module                  | Tests |
|-------------------------|-------|
| Stack Trace Sanitizer   | 13    |
| JWT Security Validator  | 17    |
| Input Sanitization      | 10    |
| Encryption / Decryption | 8     |
| Cache Performance       | 12    |
| Budget Control          | 10    |

---

## Repository Structure

```
vibeshield/
├── README.md
├── LICENSE
├── vibeshield-ts/
│   ├── src/
│   │   ├── core/
│   │   │   ├── stack-sanitizer.ts
│   │   │   ├── jwt-validator.ts
│   │   │   ├── sanitizer.ts
│   │   │   ├── crypto.ts
│   │   │   └── cache.ts
│   │   ├── middleware/
│   │   │   ├── errorHandler.ts
│   │   │   └── jwt-security.ts
│   │   └── index.ts
│   ├── tests/
│   │   ├── stack-sanitizer.test.ts
│   │   ├── jwt-validator.test.ts
│   │   └── ...
│   └── examples/
│       └── jwt-usage.ts
└── vibeshield-python/
    ├── src/
    │   ├── stack_sanitizer.py
    │   ├── jwt_validator.py
    │   ├── jwt_security.py
    │   └── ...
    ├── tests/
    │   ├── test_jwt_validator.py
    │   └── ...
    └── examples/
        └── jwt_usage.py
```

---

## Roadmap

### ✅ Completed (Phase 1–4)

- Dual-stack runtime core (TypeScript + Python)
- Zero-dependency architecture
- AES-256-GCM encryption
- Recursive validation
- VibeBudgeter (financial circuit breaker)
- Stack Trace Sanitizer
- JWT Security Validator
- 70+ test suite

### 🚀 Coming Soon (Phase 5)

- Prompt injection mitigation
- Dynamic token budget tuning
- Adaptive rate-limiting (Token Bucket)
- GraphQL support

### 🔮 Future (Phase 6)

- OpenTelemetry integration
- Prometheus metrics export
- Redis adapter (distributed cache)
- Admin dashboard
- Express.js, NestJS, Django adapters

---

## AI Assistant Integration

VibeShield includes configuration files for AI coding assistants:

- `.cursorrules` — for Cursor IDE
- `.clauderules` — for Claude

Add these files to your project root and your AI tools will automatically generate code with VibeShield protections applied.

---

## Documentation

- [Stack Trace Sanitizer Guide](docs/stack-trace-sanitizer.md)
- [JWT Security Guide](docs/jwt-security.md)
- [Performance Tuning](docs/performance.md)
- [Migration Guide](docs/migration.md)

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Development Setup

```bash
# TypeScript
cd vibeshield-ts
npm install
npm run dev

# Python
cd vibeshield-python
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## License

[MIT](LICENSE) © [NurhatMentes](https://github.com/NurhatMentes)
