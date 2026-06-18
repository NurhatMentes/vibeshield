# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-18

### Added
- **Core Security Modules**
  - Stack Trace Sanitizer with container path detection
  - JWT Security Validator with Shannon entropy analysis
  - SQL/NoSQL Injection protection (defense-in-depth)
  - XSS protection with HTML encoding
  - Command Injection protection with whitelist approach
  
- **Performance & Cost**
  - LRU Cache with 60s TTL (70.7x faster on cache hits)
  - VibeBudgeter financial circuit-breaker
  - Nanosecond-precision performance monitoring
  
- **Data Protection**
  - AES-256-GCM transparent encryption with HKDF key derivation
  - Recursive deep validation (nested objects/arrays)
  - Zero-dependency core (serverless-friendly)
  
- **AI Safety**
  - Prompt Injection mitigation with 50+ patterns
  - Jailbreak detection (DAN, STAN, etc.)
  - Prompt leak detection with canary tokens
  - Custom pattern extend API

### Security
- SQL sanitization documented as partial mitigation (not substitute for parameterized queries)
- Cache poisoning prevention with sorted query parameters
- Container-specific path detection (/app/, /srv/, /proc/, /run/)

### Documentation
- Comprehensive API reference
- Security best practices guide
- Performance benchmark methodology
- Custom permission matrix examples
