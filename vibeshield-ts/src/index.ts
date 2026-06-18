export { vibeShield } from './core/wrapper.js';
export { sanitize, sanitizeString, sanitizeUrl } from './core/sanitizer.js';
export { VibeShieldCache, globalCache } from './core/cache.js';
export { handleError } from './core/errorHandler.js';
export { vibeFetch } from './core/fetch.js';
export { sanitizeStackTrace } from './core/stack-sanitizer.js';
export { validateJwtSecret } from './core/jwt-validator.js';
export { enforceJwtSecurity } from './core/jwt-security.js';
export { validateCorsConfig } from './core/cors-validator.js';
export { enforceCorsPolicy } from './core/cors-security.js';
export { detectRcePatterns } from './core/rce-detector.js';
export { validateUrl } from './core/ssrf-protector.js';
export { enforceSafeUrl, VibeShieldSSRFError } from './middleware/ssrf-security.js';
export { sanitizeShellInput, validateSafeCommand, VibeShieldCommandInjectionError } from './core/command-sanitizer.js';
export { safeExec } from './middleware/safe-exec.js';
export * from './types/index.js';
export { safeJsonParse, detectUnsafeDeserialization, VibeShieldDeserializationError } from './core/deserialization-protector.js';
export { enforceSafeJson } from './middleware/safe-parser.js';
export { validateSchema } from './core/schema-validator.js';
export { validateRequest } from './middleware/request-validator.js';
export type { ValidationError, ValidationResult, SchemaDefinition, FieldSchema } from './core/schema-validator.js';

export { 
  VibeShieldAuthorizationError, 
  checkPermission, 
  validateResourceOwnership, 
  detectMissingAuthMiddleware,
  createPermissionMatrix
} from './core/authorization-protector.js';
export { requireAuth, requireRole, requirePermission, requireOwnership } from './middleware/authorization.js';
export type { UserContext } from './core/authorization-protector.js';
export type { AuthOptions } from './middleware/authorization.js';

export { validatePassword, calculateShannonEntropy, generatePasswordPolicyReport, COMMON_PASSWORDS } from './core/password-protector.js';
export { validatePasswordMiddleware } from './middleware/password-validator.js';
export type { PasswordContext, PasswordValidationResult, PasswordPolicyOptions } from './core/password-protector.js';

export { detectPromptInjection, sanitizeForLLM, detectPromptLeak, detectJailbreak, generateCanaryToken, PromptShield } from './core/prompt-shield.js';
export type { PromptShieldResult, PromptShieldOptions, CanaryToken } from './core/prompt-shield.js';
export { promptShieldMiddleware } from './middleware/prompt-shield-middleware.js';
export type { PromptShieldMiddlewareOptions } from './middleware/prompt-shield-middleware.js';

