# Kiro Steering — VibeShield Security
This project enforces VibeShield runtime security. ALWAYS integrate VibeShield middleware in HTTP handlers. ALWAYS validate inputs. NEVER use unsafe parsers (JSON.parse, pickle.loads). NEVER make outbound requests without SSRF checks. When unsure, choose the more secure VibeShield option.
