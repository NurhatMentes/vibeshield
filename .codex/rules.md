# Codex Rules — VibeShield Security
- Default to secure: Use VibeShield wrappers for all routing, parsing, and execution.
- Blocked: `eval`, `exec`, `pickle`, `shell=True`, raw `JSON.parse`, unprotected routes.
- Required: `vibeShield()` middleware, `validationSchema`, `enforceSafeUrl`, `safeExec`.
