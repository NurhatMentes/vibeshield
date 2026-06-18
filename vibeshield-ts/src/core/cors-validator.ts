/**
 * VibeShield CORS Security Validator
 * 
 * Detects insecure CORS configurations commonly produced by AI code generators.
 * Zero external dependencies — uses only built-in string methods and regex.
 * 
 * @module cors-validator
 */

export interface CorsConfig {
  allowedOrigins?: string[];
  allowedMethods?: string[];
  allowedHeaders?: string[];
  exposedHeaders?: string[];
  allowCredentials?: boolean;
  maxAge?: number;
}

export interface CorsValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

const SENSITIVE_EXPOSED_HEADERS: ReadonlyArray<string> = [
  'authorization',
  'x-api-key',
  'x-csrf-token',
  'set-cookie',
  'cookie',
  'x-forwarded-for',
  'x-real-ip',
  'proxy-authorization',
];

const DANGEROUS_METHODS: ReadonlyArray<string> = [
  'TRACE',
  'CONNECT',
];

const DESTRUCTIVE_METHODS: ReadonlyArray<string> = [
  'DELETE',
  'PATCH',
];

const MAX_SAFE_MAX_AGE = 86400; // 24 hours

function isProduction(): boolean {
  const env = (process.env.NODE_ENV || '').toLowerCase();
  return env === 'production';
}

function isWildcard(origin: string): boolean {
  return origin.trim() === '*';
}

function isValidOriginFormat(origin: string): boolean {
  // Exact origin
  if (/^https?:\/\/[a-zA-Z0-9.-]+(:\d+)?$/.test(origin)) {
    return true;
  }
  
  // Subdomain wildcard: *.example.com
  if (/^\*\.[a-zA-Z0-9.-]+$/.test(origin)) {
    return true;
  }
  
  return false;
}

function isLocalhostOrigin(origin: string): boolean {
  const lower = origin.toLowerCase();
  return lower.includes('localhost') || lower.includes('127.0.0.1') || lower.includes('0.0.0.0');
}

/**
 * Validates a CORS configuration for security issues.
 *
 * @param config - The CORS configuration to validate
 * @returns {CorsValidationResult} Validation result with errors and warnings
 */
export function validateCorsConfig(config: CorsConfig): CorsValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const prod = isProduction();

  // 1. Undefined/Empty Config Check
  if (!config) {
    errors.push('CORS configuration is missing or undefined.');
    return { valid: false, errors, warnings };
  }

  // 2. Wildcard Origin Check
  const origins = config.allowedOrigins || [];
  const hasWildcard = origins.some(isWildcard);

  if (hasWildcard) {
    if (prod) {
      errors.push('Wildcard origin "*" is not allowed in production. Specify explicit allowed origins.');
    } else {
      warnings.push('Wildcard origin "*" detected. This is acceptable in development but must be restricted in production.');
    }
  }

  // 3. Wildcard + Credentials (CRITICAL — always an error)
  if (hasWildcard && config.allowCredentials) {
    errors.push('CRITICAL: Wildcard origin "*" with credentials enabled is a security vulnerability. Browsers will reject this, but it indicates a misconfiguration.');
  }

  // 4. Origin Format Validation
  for (const origin of origins) {
    if (!isWildcard(origin) && !isValidOriginFormat(origin)) {
      errors.push(`Invalid origin format: "${origin}". Expected: "https://example.com" or "*.example.com"`);
    }
  }

  // 5. Localhost in Production
  if (prod) {
    const localhostOrigins = origins.filter(isLocalhostOrigin);
    if (localhostOrigins.length > 0) {
      errors.push(`Localhost origins detected in production: ${localhostOrigins.join(', ')}. Remove development origins from production config.`);
    }
  }

  // 6. No origins specified
  if (origins.length === 0) {
    warnings.push('No allowed origins specified. All cross-origin requests will be blocked.');
  }

  // 7. Sensitive Exposed Headers
  const exposed = (config.exposedHeaders || []).map(h => h.toLowerCase());
  const sensitiveFound = SENSITIVE_EXPOSED_HEADERS.filter(h => exposed.includes(h));
  if (sensitiveFound.length > 0) {
    errors.push(`Sensitive headers exposed to client: ${sensitiveFound.join(', ')}. Remove these from exposedHeaders.`);
  }

  // 8. Dangerous HTTP Methods
  const methods = (config.allowedMethods || []).map(m => m.toUpperCase());
  const dangerousFound = DANGEROUS_METHODS.filter(m => methods.includes(m));
  if (dangerousFound.length > 0) {
    errors.push(`Dangerous HTTP methods allowed: ${dangerousFound.join(', ')}. TRACE and CONNECT should never be allowed in CORS.`);
  }

  // 9. Destructive Methods Warning
  const destructiveFound = DESTRUCTIVE_METHODS.filter(m => methods.includes(m));
  if (destructiveFound.length > 0 && prod) {
    warnings.push(`Destructive methods (${destructiveFound.join(', ')}) are allowed. Ensure these are intentional and properly authorized.`);
  }

  // 10. maxAge Check
  if (config.maxAge !== undefined) {
    if (config.maxAge < 0) {
      errors.push('maxAge cannot be negative.');
    } else if (config.maxAge > MAX_SAFE_MAX_AGE) {
      warnings.push(`maxAge (${config.maxAge}s) exceeds recommended maximum of ${MAX_SAFE_MAX_AGE}s (24 hours). Long preflight cache may hide configuration changes.`);
    }
  }

  // 11. Credentials without specific origins
  if (config.allowCredentials && origins.length === 0) {
    warnings.push('Credentials enabled but no origins specified. Credentials require explicit allowed origins.');
  }

  // 12. Too many origins warning
  if (origins.length > 20) {
    warnings.push(`Large number of allowed origins (${origins.length}). Consider using a pattern-based approach or environment-specific configs.`);
  }

  return { valid: errors.length === 0, errors, warnings };
}
