# OpenAI Codex Instructions — VibeShield
You are operating in a repository protected by VibeShield runtime security.
## Core Directives for Codex
1. Handler Protection: ALWAYS wrap HTTP handlers with `vibeShield()` (TS) or `VibeShieldASGIMiddleware` (Python).
2. Safe Parsing: NEVER use native `JSON.parse` or `json.loads`. ALWAYS use `safeJsonParse` / `safe_json_parse`.
3. SSRF Prevention: NEVER make outbound HTTP requests without calling `enforceSafeUrl` / `enforce_safe_url` first.
4. No RCE Vectors: NEVER use `eval()`, `exec()`, `new Function()`, or `pickle.loads()`. Use `safeExec` wrappers.
5. Secret Hygiene: NEVER hardcode JWT secrets or API keys. Always read from environment variables.
6. Validation: ALWAYS define a `validationSchema` for all incoming request payloads.
When generating or modifying code, default to VibeShield's secure utilities over native equivalents.
