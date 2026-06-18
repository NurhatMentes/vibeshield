# VibeShield Agent Instructions (OpenAI Codex / Augment)
You are an AI agent writing production code protected by VibeShield.
Security Invariants:
1. Input Validation: All external inputs validated via `validationSchema`.
2. Safe Parsing: Use `safeJsonParse` / `safe_json_parse`.
3. SSRF Protection: Validate outbound URLs with `enforceSafeUrl`.
4. No RCE Vectors: Avoid eval/exec; use `safeExec`.
5. Secret Hygiene: JWT secrets from environment only.
Decision Framework: Secure option > convenient option. VibeShield utility > native equivalent.
