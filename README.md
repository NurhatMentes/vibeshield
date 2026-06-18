# 🛡️ VibeShield

**Runtime security engine for AI-generated applications**

> 🚀 **Zero-dependency, enterprise-grade protection layer for Next.js (TypeScript) and Python (FastAPI/Flask)**
>
> Harden AI-generated code before those mistakes reach production.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.9+-green.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-840%20passing-brightgreen.svg)]()
[![CI](https://github.com/NurhatMentes/vibeshield/actions/workflows/test.yml/badge.svg)](https://github.com/NurhatMentes/vibeshield/actions)
[![Dual Stack](https://img.shields.io/badge/Stack-TS%20%2B%20Python-purple.svg)]()

---

## The Hidden Cost of Vibe Coding

Modern AI coding assistants (Cursor, Claude, GitHub Copilot, Windsurf) can generate working applications in minutes.

**They can also silently ship:**

| Category | Hidden Dangers |
|----------|----------------|
| 🔓 **Injection Attacks** | SQL/NoSQL injection, XSS, Command Injection, RCE |
| 🌐 **Network Attacks** | SSRF to AWS metadata, IP bypass attacks, IDN homographs |
| 🔑 **Auth Failures** | Weak JWT secrets, missing RBAC, IDOR vulnerabilities |
| 📦 **Data Leaks** | Exposed stack traces, insecure deserialization (pickle), prototype pollution |
| 💸 **Cost Explosions** | Recursive API loops, runaway AI calls, unbounded queries |
| ⚙️ **Misconfigs** | Wildcard CORS, shell=True execution, permissive schemas |

**VibeShield** is a zero-dependency runtime protection layer that detects and blocks all of these — while also multiplying your performance and keeping costs under control.

---

## ✨ Why VibeShield?

- 🛡️ **15 Security Modules** — Comprehensive protection across all attack vectors
- 🧪 **840 Passing Tests** — Enterprise-grade reliability with dual-stack parity
- ⚡ **70.7x Faster** — Built-in LRU cache with nanosecond monitoring
- 🎯 **Zero Dependencies** — No supply-chain risk, serverless-friendly cold starts
- 💸 **VibeBudgeter** — Financial circuit-breaker for AI/API costs
- 🤖 **AI Assistant Native** — Ships with rules files for Cursor, Claude, Copilot, Windsurf & more

---

## 📦 Installation

### TypeScript / Next.js

```bash
npm install @vibeshield/core
# or
pnpm add @vibeshield/core
# or
yarn add @vibeshield/core
```

### Python / FastAPI-Flask

```bash
pip install vibeshield-core
# or
poetry add vibeshield-core
```

### Python Development Setup

Since the package is not yet published to PyPI, clone the repository and install dependencies:

```bash
git clone https://github.com/NurhatMentes/vibeshield.git
cd vibeshield/vibeshield-python

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements-dev.txt
```

**requirements-dev.txt:**
```
pytest>=7.0.0
pytest-asyncio>=0.21.0
fastapi>=0.100.0
flask>=2.0.0
httpx>=0.24.0
uvicorn>=0.20.0
cryptography>=41.0.0
```

---

## 🚀 Quick Start (60 seconds)

### TypeScript — Next.js App Router

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
    validateJwtSecret: true,
    corsValidation: true,
    detectRcePatterns: true
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

### Python — FastAPI

```python
from fastapi import FastAPI
from vibeshield.core import VibeShieldASGIMiddleware

app = FastAPI()

app.add_middleware(
    VibeShieldASGIMiddleware,
    sanitize_body=True,
    stack_trace_protection=True,
    validate_jwt_secret=True,
    cors_validation=True,
    detect_rce_patterns=True,
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

## 🛡️ Security Modules

VibeShield is organized into **14 specialized security modules** across 4 phases.

### 🎯 Phase 1 — Quick Wins

#### 🔒 Stack Trace Sanitizer
Auto-masks file paths, IP addresses, and database credentials leaked in error messages.

```
Before: at /home/user/myapp/src/db.ts:42 postgres://admin:pass@192.168.1.100/db
After:  at [PROJECT_ROOT]/src/db.ts:42 [REDACTED_DB_INFO]
```

#### 🔐 JWT Security Validator
Detects weak, hardcoded, or low-entropy JWT secrets with **Shannon entropy analysis**.

- ❌ Hardcoded: `"secret"`, `"password"`, `"changeme"`
- ❌ Short secrets (< 10 chars)
- ❌ Low entropy (Shannon < 3.5)
- ❌ Repetitive patterns (`aaaaaa`, `123123`)
- ❌ Sequential patterns (`abc`, `qwerty`, `123`)

#### 🌐 CORS Security Validator
Blocks insecure CORS configurations AI assistants commonly produce:

- 🚫 Wildcard origins (`*`) in production
- 🚫 Wildcard + credentials (CRITICAL vulnerability)
- 🚫 Sensitive headers exposed (`Authorization`, `Set-Cookie`)
- 🚫 Dangerous HTTP methods (`TRACE`, `CONNECT`)

---

### ⚔️ Phase 2 — Critical Runtime Protection

#### 🧨 RCE Pattern Detector
Uses a **custom lexical state machine** to scan AI-generated code for remote code execution vectors — with comment/string masking to prevent false positives.

**Detects:** `eval()`, `exec()`, `Function()`, `child_process.exec`, `vm.runInNewContext`, `process.mainModule`, `require(variable)`

#### 🌍 SSRF URL Validator
Performs static URL analysis with **IP bypass decoding**:

- ✅ Blocks AWS/GCP metadata (`169.254.169.254`)
- ✅ Blocks private subnets (`10.x`, `172.16.x`, `192.168.x`)
- ✅ **Decodes bypass attempts:**
  - Decimal IP: `http://2130706433/` → `127.0.0.1`
  - Hex IP: `http://0x7f000001/` → `127.0.0.1`
  - Octal IP: `http://0177.0.0.1/` → `127.0.0.1`
- ✅ Detects IDN homograph attacks (Latin/Cyrillic mixing)

#### 💉 Command Injection Protection
**Strict whitelist** approach — allows only `[a-zA-Z0-9_\-\.@:]+` in arguments.

- 🛡️ Blocks shell metacharacters (`;`, `|`, `&`, `$`, `` ` ``)
- 🛡️ Blocks null byte & newline injection
- 🛡️ Blocks path traversal (`../../../etc/passwd`)
- 🛡️ **Forces `shell: false`** in all spawn wrappers

---

### 📦 Phase 3 — Data Security

#### 🎭 Insecure Deserialization Protector
Prevents the deadliest deserialization vulnerabilities:

- 🚫 **Python:** Detects `pickle.loads()`, `yaml.load()` (unsafe), `marshal`, `shelve`, `dill`, `jsonpickle`
- 🚫 **TypeScript:** Detects `node-serialize`, `eval(json)`, `new Function(json)`
- 🛡️ **JSON Depth Limiter:** Prevents stack-overflow DoS attacks (max depth: 64)
- 🛡️ **Prototype Pollution Block:** Strips `__proto__`, `constructor`, `prototype` keys recursively

#### ✅ Strict Schema Validator
Zero-dependency recursive validation engine with **whitelist-only** property retention.

- 🎯 Strict type checking (no coercion: `"123"` ≠ `123`)
- 🎯 Format matchers: `email`, `uuid`, `url`, `ipv4`, `ipv6`, `date`, `phone`
- 🎯 Recursive nested object & array validation
- 🎯 Unknown field rejection (strict mode)
- 🎯 Path-based error reporting: `user.profile.email`

---

### 🏰 Phase 4 — Application-Level Security

#### 🔑 Authorization & Access Control
Complete RBAC + IDOR protection with **static code analysis**:

- 👮 **RBAC Engine:** Role-based + permission-based matrix
- 🛡️ **IDOR Protection:** Validates resource ownership automatically
- 🔍 **Static Analyzer:** Scans routes for missing auth middleware
- 🎭 **Decorators/Middleware:** `@require_role`, `@require_permission`, `@require_ownership`

#### 🔒 Weak Password Policy Protector
Enterprise password validation with **embedded blacklist** of top 200 common passwords.

- 📊 Shannon entropy calculation
- 📊 Strength scoring (0-100)
- 🚫 **Context-aware:** Rejects passwords containing username, email, name, birthdate
- 🚫 Blocks repetitive & sequential patterns
- 🚫 Configurable complexity rules

---

### 🤖 Phase 5 — AI Safety

#### 🛡️ Prompt Injection Mitigation (Prompt Shield)
Detects and blocks OWASP #1 LLM vulnerability: Prompt Injection, Jailbreaking, and Prompt Leaking using zero-dependency heuristic scoring. Automatically injects canary tokens for leak detection.

##### TypeScript Example
```typescript
import { promptShieldMiddleware } from '@vibeshield/core';

// In Next.js / Express Route Handler
app.post('/api/chat', promptShieldMiddleware(), (req, res) => {
  // req.promptShieldCanary contains the generated canary token
  // req.promptShieldResult contains safety scan details
  const userPrompt = req.body.prompt;
  const systemPrompt = req.body.systemPrompt; // automatically includes canary token
  
  // call LLM with systemPrompt and userPrompt...
  res.json({ status: 'success' });
});
```

##### Python Example
```python
from flask import request
from vibeshield.core import prompt_shield_middleware

@app.route("/api/chat", methods=["POST"])
@prompt_shield_middleware()
def chat_endpoint():
    # request.prompt_shield_canary contains the generated canary token
    # request.prompt_shield_result contains safety scan details
    user_prompt = request.json.get("prompt")
    system_prompt = request.json.get("systemPrompt") # automatically includes canary token
    
    # call LLM...
    return {"status": "success"}
```

---

## 🎭 Injection Protection Matrix

| Attack Type | Example Payload | VibeShield Action |
|-------------|-----------------|-------------------|
| **SQL Injection** | `' OR '1'='1` | Escaped to `' OR ''1''=''1` |
| **NoSQL Injection** | `{"$ne": "admin"}` | Stripped to `{}` |
| **XSS** | `<script>alert(1)</script>` | Sanitized to `Nice post!` |
| **Command Injection** | `; rm -rf /` | Blocked (whitelist fail) |
| **SSRF** | `http://169.254.169.254/` | Blocked (metadata IP) |
| **Prototype Pollution** | `{"__proto__": {"admin": true}}` | Key stripped |

---

## ⚡ Performance Benchmarks

### TypeScript (Next.js)

| Metric | Without VibeShield | With VibeShield | Improvement |
|--------|-------------------|-----------------|-------------|
| Response Time | 9.23 ms/req | 0.13 ms/req | **70.7x faster** |
| DB Latency | 9,233 ms | 130 ms | **98.59% reduced** |
| DB Queries | 1,000 | 1 | **99.90% reduced** |

### Python (FastAPI)

| Metric | Without VibeShield | With VibeShield | Improvement |
|--------|-------------------|-----------------|-------------|
| Response Time | 15.49 ms/req | 0.55 ms/req | **27.7x faster** |
| Execution Time | 15,492 ms | 558 ms | **96.39% reduced** |
| DB Queries | 1,000 | 1 | **99.90% reduced** |

---

## 🔧 Advanced Features

### 💸 VibeBudgeter — Financial Circuit Breaker

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
// Daily threshold reached ($10.00). Request blocked automatically.
```

### 🔐 AES-256-GCM Transparent Encryption

Sensitive fields are encrypted at rest, decrypted in response.

```typescript
crypto: {
  secretKey: process.env.VIBESHIELD_SECRET!,
  encryptFields: ['creditCard', 'ssn', 'password']
}

// Database stores: { creditCard: "gcm:enc:a1b2c3d4..." }
// Response returns: { creditCard: "1234-5678-9012-3456" }
```

### ⏱️ Nanosecond Performance Monitoring

```typescript
performanceThresholdMs: 200

// Output:
// ⚠️ [VIBESHIELD PERFORMANCE WARNING]
// Route: POST /api/heavy-calculation
// Duration: 558 ms (threshold exceeded)
```

---

## 🤖 AI Assistant Integration

VibeShield ships with **native rules files** for every major AI coding assistant. Drop these into your project root and your AI tools will automatically generate secure, VibeShield-protected code.

| AI Assistant | Rules File | Location |
|--------------|-----------|----------|
| 🖱️ **Cursor** | `.cursorrules` / `.cursor/rules/vibeshield.mdc` | Project root |
| 🟣 **Claude Code** | `CLAUDE.md` | Project root |
| 🐙 **GitHub Copilot** | `.github/copilot-instructions.md` | `.github/` folder |
| 🌊 **Windsurf** | `.windsurfrules` | Project root |
| ⚡ **Cline** | `.clinerules` | Project root |
| 🤝 **Aider** | `.aider/rules/vibeshield.md` | `.aider/rules/` |
| 🧠 **OpenAI Codex** | `AGENTS.md` | Project root |
| 🚀 **Augment Code** | `AGENTS.md` | Project root |
| 🎯 **Amazon Q** | `.amazonq/rules/vibeshield.md` | `.amazonq/rules/` |
| 📐 **Kiro** | `.kiro/steering/vibeshield.md` | `.kiro/steering/` |
| 🎨 **Trae** | `.trae/rules/vibeshield.md` | `.trae/rules/` |

**All rules files contain:**
- ✅ Automatic VibeShield middleware usage
- ✅ Secure parsing patterns (`safeJsonParse`, `enforceSafeUrl`)
- ✅ Auth/authorization decorators for every route
- ✅ Command injection safe-exec wrappers
- ✅ Schema validation for all inputs
- ✅ SSRF/RCE/Deserialization avoidance patterns

👉 **See the [`/ai-rules`](./ai-rules) folder for ready-to-use templates.**

---

## 🧪 Test Coverage

**840 passing tests** with 100% dual-stack parity between TypeScript and Python.

| Module | TS Tests | Python Tests | Total |
|--------|----------|--------------|-------|
| Stack Trace Sanitizer | 13 | 13 | 26 |
| JWT Security Validator | 17 | 17 | 34 |
| CORS Validator | 36 | 32 | 68 |
| RCE Detector | 32 | 31 | 63 |
| SSRF Protector | 37 | 28 | 65 |
| Command Injection | 26 | 27 | 53 |
| Deserialization | 28 | 33 | 61 |
| Schema Validator | 40 | 61 | 101 |
| Authorization | 37 | 46 | 83 |
| Password Policy | 39 | 37 | 76 |
| Prompt Shield | 44 | 44 | 88 |
| Core (Cache, Crypto, Budget, Sanitizer) | 71 | 51 | 122 |
| **TOTAL** | **420** | **420** | **840** |

```bash
# TypeScript
cd vibeshield-ts && npm test

# Python
cd vibeshield-python && pytest
```

---

## 🏗️ Architecture

```
vibeshield/
├── vibeshield-ts/                    # TypeScript stack
│   ├── src/
│   │   ├── core/                     # 11 security modules
│   │   │   ├── stack-sanitizer.ts
│   │   │   ├── jwt-validator.ts
│   │   │   ├── cors-validator.ts
│   │   │   ├── rce-detector.ts
│   │   │   ├── ssrf-protector.ts
│   │   │   ├── command-sanitizer.ts
│   │   │   ├── deserialization-protector.ts
│   │   │   ├── schema-validator.ts
│   │   │   ├── authorization-protector.ts
│   │   │   ├── password-protector.ts
│   │   │   └── prompt-shield.ts
│   │   └── middleware/               # Integration wrappers
│   └── tests/                        # 420 Vitest tests
│
├── vibeshield-python/                # Python stack
│   ├── src/                          # Mirror of TS modules
│   │   ├── prompt_shield.py
│   │   └── middleware/
│   │       └── prompt_shield_middleware.py
│   └── tests/                        # 420 pytest tests
│
└── ai-rules/                         # AI assistant integration
    ├── cursorrules
    ├── CLAUDE.md
    ├── copilot-instructions.md
    ├── windsurfrules
    ├── clinerules
    ├── AGENTS.md
    └── ...
```

---

## 📚 API Reference

### Core Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `security.sanitizeBody` | boolean | Input sanitization | `true` |
| `security.stackTraceProtection` | boolean | Stack trace masking | `true` |
| `security.validateJwtSecret` | boolean | JWT secret validation | `true` |
| `security.corsValidation` | boolean | CORS config check | `true` |
| `security.detectRcePatterns` | boolean | RCE pattern scan | `true` |
| `cache.enabled` | boolean | Enable LRU cache | `false` |
| `cache.ttl` | number | Cache TTL (seconds) | `60` |
| `validationSchema` | object | Recursive schema | `null` |
| `crypto.secretKey` | string | 32-byte key | `null` |
| `crypto.encryptFields` | string[] | Fields to encrypt | `[]` |
| `budget.enabled` | boolean | Budget control | `false` |
| `budget.maxDailyCost` | number | Max USD/day | `10.00` |
| `performanceThresholdMs` | number | Slow endpoint alert | `200` |

---

## 🗺️ Roadmap

### ✅ Completed (Phases 1–5)
- [x] Dual-stack runtime core (TS + Python)
- [x] Zero-dependency architecture
- [x] 15 security modules with 840 tests
- [x] AI assistant rules for 11+ platforms
- [x] AES-256-GCM encryption
- [x] VibeBudgeter financial circuit-breaker
- [x] Prompt injection mitigation

### 🚧 In Progress (Phase 5)
- [ ] Dynamic token budget tuning
- [ ] Adaptive rate-limiting (Token Bucket)
- [ ] GraphQL support

### 🔮 Future (Phase 6)
- [ ] OpenTelemetry integration
- [ ] Prometheus metrics export
- [ ] Redis adapter (distributed cache)
- [ ] Admin dashboard
- [ ] Go & Rust support
- [ ] Express, NestJS, Django native adapters

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit: `git commit -m 'Add amazing feature'`
4. Push: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Development Setup

```bash
# TypeScript
cd vibeshield-ts && npm install && npm run dev

# Python
cd vibeshield-python
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⭐ Show Your Support

If VibeShield protects your AI-generated apps, please **star the repo** — it helps more developers discover secure vibe coding!

---

<div align="center">

**🛡️ VibeShield — Because AI writes fast, but security must be right.**

[Report Bug](https://github.com/NurhatMentes/vibeshield/issues) · [Request Feature](https://github.com/NurhatMentes/vibeshield/issues) · [Discussions](https://github.com/NurhatMentes/vibeshield/discussions)

</div>
