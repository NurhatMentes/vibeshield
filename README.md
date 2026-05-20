# 🛡️ VibeShield

> **AI writes your code. VibeShield protects your database and your wallet.**  
> A lightweight, zero-configuration (plug-and-play) security and performance middleware layer designed for Next.js (App Router) and Node.js applications.

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

---

## 💡 Why VibeShield?

With the rise of "vibe coding" and AI-assisted development tools like Cursor, Claude, and Bolt, building functional applications has never been faster. However, AI-generated code often misses critical **security sanitization** and **performance optimizations**, leaving production applications vulnerable to database leaks and unexpected cloud bills.

**VibeShield** acts as a bulletproof vest for your API routes. It intercepts incoming requests using high-performance ES6 Proxies to sanitize malicious payloads and automatically caches expensive operations — all with **zero configuration**.

---

## 📊 Live Benchmarks & Proofs

We simulated a hacker attack and a high-traffic load (1,000 rapid requests) against a standard AI-generated Next.js endpoint. Here is the raw empirical data:

### ⚡ Performance Optimization (1,000 Requests)

| Metric | Without VibeShield (Raw AI Code) | With VibeShield Layer | Improvement |
| :--- | :--- | :--- | :--- |
| **Total Duration** | 9,233.61 ms | **130.52 ms** | **70.7x Faster** |
| **Avg. Response Time** | 9.23 ms | **0.13 ms** | Ultra-Low Latency |
| **Database Load** | 1,000 direct queries | **1 query** (Cache Hit) | **99.90% DB Load Reduction** |

### 🛡️ Security Neutralization

- **SQL Injection (SQLi):** Automatically neutralizes payloads like `admin' OR '1'='1` into safe, escaped strings.
- **NoSQL Injection:** Recursively strips unauthorized MongoDB operators (like `$ne`, `$gt`) from nested JSON bodies.
- **Cross-Site Scripting (XSS):** Removes malicious `<script>` tags and JavaScript execution vectors before they reach your business logic.
- **Resilient Error Handling:** Prevents internal stack traces and DB credentials from leaking. If a crash occurs, the client receives a masked tracking ID (`VS-XXXX`) while the server logs the secure full trace.

---

## 🛠️ Architecture

Built with a disciplined Aspect-Oriented Programming (AOP) approach, the core is split into four independent, dependency-free modules:

```text
vibeshield-core/
├── src/
│   ├── core/
│   │   ├── wrapper.ts       # Module A: Main higher-order function (vibeShield)
│   │   ├── sanitizer.ts     # Module B: Recursive Security & Sanitization Engine
│   │   ├── cache.ts         # Module C: Lightweight Map-based LRU Cache
│   │   └── errorHandler.ts  # Module D: Safe Client Masking & Secure Server Logger
│
├── tests/
├── package.json
└── README.md
```

---

## 🚀 Quick Start (Plug & Play)

### 1. Installation

```bash
npm install @vibeshield/core
```

### 2. Wrap Your Next.js API Route (`route.ts`)

Simply wrap your standard Next.js App Router handlers. VibeShield automatically detects and resolves Next.js 15 asynchronous Promise context parameters dynamically.

```ts
import { vibeShield } from '@vibeshield/core';
import { db } from '@/lib/db';

export const GET = vibeShield(async (req) => {
  const users = await db.user.findMany();

  return Response.json(users);
}, {
  cache: {
    enabled: true,
    ttl: 60
  },
  security: {
    sanitizeBody: true
  }
});
```

---

## 🤖 AI Bridge: Automated Implementation

VibeShield includes a `.cursorrules` configuration. Drop this file into your workspace, and your favorite AI assistant (Cursor, Claude, ChatGPT) will automatically format and secure every new endpoint with VibeShield — helping prevent unsecured code from reaching production.

---

## 🗺️ Roadmap

- [x] Node.js & Next.js App Router (TypeScript) MVP
- [x] Comprehensive Test Suite (25/25 Vitest Tests Passed)
- [ ] Python Ecosystem Support (FastAPI / Flask Middleware Version)
- [ ] Global Dashboard for `VS-XXXX` Error Tracking

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
