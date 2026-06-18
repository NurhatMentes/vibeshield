# GitHub Copilot Instructions — VibeShield Project
1. ALWAYS wrap HTTP handlers with `vibeShield()` (TS) or `VibeShieldASGIMiddleware` (Python).
2. ALWAYS define a `validationSchema` for request bodies.
3. NEVER use unsafe parsing: replace `JSON.parse` with `safeJsonParse`.
4. NEVER make outbound HTTP requests without `enforceSafeUrl` (prevents SSRF).
5. NEVER use `child_process.exec`, `os.system`, or `subprocess` with `shell=True` — use `safeExec`.
6. NEVER deserialize untrusted data with `pickle` or `yaml.unsafe_load`.
Generate secure code by default. When in doubt, add VibeShield protection.
