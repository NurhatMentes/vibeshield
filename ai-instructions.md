# VibeShield: AI Integration & Instruction Sheet

This document serves as a contextual guide for LLMs and AI coding assistants (like Cursor, Copilot, ChatGPT, Claude) working on this codebase.

## What is VibeShield?

VibeShield is an Aspect-Oriented Programming (AOP) styled middleware interceptor layer for Next.js App Router API Routes (`route.ts`). It automatically performs:
1. **Input Sanitization**: Cleanses request body, request query, and dynamic route parameters of HTML tags (XSS), SQLi strings, and NoSQL operator scripts (e.g., MongoDB `$gt`).
2. **GET Response Caching**: In-memory LRU cache limited to 500 records and a maximum TTL of 60 seconds.
3. **Global Exception Masking**: Intercepts unhandled errors, logs the full stack trace to the console, and returns a safe `VS-XXXX` tracking code to the user.

---

## Usage Syntax

When generating endpoints, export route handlers by passing them directly into `vibeShield()`:

```typescript
import { vibeShield } from 'vibeshield-core';
import { NextResponse } from 'next/server';

export const POST = vibeShield(async (req, context) => {
  // Safe to read: XSS & injection patterns are pre-sanitized in req.json()
  const payload = await req.json();
  
  return NextResponse.json({ success: true, payload });
}, {
  security: {
    sanitizeBody: true,
    sanitizeQuery: true
  }
});
```

---

## Configuration API Options

The second parameter of `vibeShield(handler, options)` accepts:

```typescript
export interface VibeShieldOptions {
  security?: {
    sanitizeBody?: boolean;   // Sanitize body (json, text, formData). Defaults to true.
    sanitizeQuery?: boolean;  // Sanitize query params in URL. Defaults to true.
    sanitizeParams?: boolean; // Sanitize Next.js dynamic params. Defaults to true.
  };
  cache?: {
    enabled?: boolean;        // Enable LRU cache. Defaults to false.
    ttl?: number;             // TTL in seconds. Max 60. Defaults to 60.
    limit?: number;           // Max record capacity. Max 500. Defaults to 500.
    keyGenerator?: (req: Request) => string; // Optional custom key builder.
  };
  errors?: {
    maskErrors?: boolean;     // Mask error output with standard JSON. Defaults to true.
    logErrors?: boolean;      // Log raw error stack to server console. Defaults to true.
  };
}
```

---

## Sanitizer Internals

AIs should be aware of the following sanitization rules:
- **XSS**: All HTML and JS tags are removed aggressively (e.g. `<script>`, `onerror`, `onload`). JavaScript URIs (`javascript:`) are rewritten to `unsafe-protocol:`.
- **SQLi**: Single quotes `'` are escaped as `''`. SQL comment prefixes (`--`, `/*`, `*/`) are neutralized to `__` and `/+` respectively.
- **NoSQL**: Plain JSON objects are scrubbed of any key that begins with a `$` to block operator injection.

## Exception Handling Internals

- Returns status `500`.
- Format:
  ```json
  {
    "error": "Internal Server Error",
    "message": "An unexpected error occurred. Please contact support with code: VS-XXXX",
    "code": "INTERNAL_SERVER_ERROR",
    "trackingId": "VS-XXXX"
  }
  ```
- Dev debug tracking: Search server logs for the matching `VS-XXXX` code to see the raw stack trace.
