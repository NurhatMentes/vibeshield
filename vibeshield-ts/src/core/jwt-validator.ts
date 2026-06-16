/**
 * VibeShield JWT Secret Key Validator
 *
 * Detects weak, hardcoded, or insecure JWT secret keys that AI code generators
 * commonly produce. This module performs validation only — it does NOT encode
 * or decode JWT tokens.
 *
 * Zero external dependencies.
 */

/** Result of a JWT secret validation check. */
export interface JwtValidationResult {
  /** Whether the secret passes all mandatory checks. */
  valid: boolean;
  /** Critical issues that must be fixed (blocks usage). */
  errors: string[];
  /** Non-critical observations the developer should review. */
  warnings: string[];
}

/**
 * Well-known weak secrets that AI models frequently hardcode.
 * All comparisons are case-insensitive.
 */
const HARDCODED_PATTERNS: ReadonlyArray<string> = [
  'secret',
  'password',
  '123456',
  '1234567890',
  'qwerty',
  'admin',
  'root',
  'jwt_secret',
  'jwt_key',
  'token_secret',
  'auth_secret',
  'mysecret',
  'my_secret',
  'my-secret',
  'supersecret',
  'super_secret',
  'changeme',
  'change_me',
  'test',
  'testing',
  'default',
  'example',
  'placeholder',
  'your_secret_here',
  'your-secret-here',
  'replace_me',
  'todo',
  'fixme',
  'key',
  'apikey',
  'api_key',
];

/** Minimum acceptable secret length. */
const MIN_SECRET_LENGTH = 10;

/** Minimum recommended secret length for strong security. */
const RECOMMENDED_SECRET_LENGTH = 32;

/**
 * Calculates Shannon entropy (bits per character) for a given string.
 * Higher entropy indicates more randomness/complexity.
 */
function calculateShannonEntropy(secret: string): number {
  if (!secret) return 0;
  
  const frequencyMap = new Map<string, number>();
  for (const char of secret) {
    frequencyMap.set(char, (frequencyMap.get(char) || 0) + 1);
  }
  
  let entropy = 0;
  const len = secret.length;
  
  for (const count of frequencyMap.values()) {
    const probability = count / len;
    entropy -= probability * Math.log2(probability);
  }
  
  return entropy;
}


/**
 * Validates a JWT secret key for common security vulnerabilities.
 *
 * This function checks for:
 * - Missing or empty secrets
 * - Known hardcoded/placeholder values
 * - Insufficient length
 * - Low character diversity (repeating chars, all-numeric, all-lowercase)
 * - Low Shannon entropy
 *
 * @param secret - The JWT secret string to validate (may be undefined).
 * @returns A {@link JwtValidationResult} with errors and warnings.
 */
export function validateJwtSecret(secret: string | undefined): JwtValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // ── 1. Undefined / Empty Check ──────────────────────────────────────
  if (secret === undefined || secret === null) {
    errors.push('JWT secret is undefined. Provide a secret via environment variable.');
    return { valid: false, errors, warnings };
  }

  const trimmed = secret.trim();
  if (trimmed.length === 0) {
    errors.push('JWT secret is empty or contains only whitespace.');
    return { valid: false, errors, warnings };
  }

  const withoutPadding = trimmed.replace(/=+$/, '');

  // ── 2. Hardcoded Pattern Detection ──────────────────────────────────
  const lower = trimmed.toLowerCase();
  for (const pattern of HARDCODED_PATTERNS) {
    if (lower === pattern) {
      errors.push(`JWT secret matches a well-known weak value: "${pattern}". Use a cryptographically random secret.`);
      break;
    }
  }

  // ── 3. Length Check ─────────────────────────────────────────────────
  if (trimmed.length < MIN_SECRET_LENGTH) {
    errors.push(`JWT secret is too short (${trimmed.length} chars). Minimum required: ${MIN_SECRET_LENGTH} characters.`);
  } else if (trimmed.length < RECOMMENDED_SECRET_LENGTH) {
    warnings.push(`JWT secret is ${trimmed.length} chars. Recommended: ${RECOMMENDED_SECRET_LENGTH}+ characters for production use.`);
  }

  // ── 4. Repeating Character / Pattern Check & Sequential Patterns ───
  // Repetitive characters (aaa, 111)
  if (/(.)\1{2,}/.test(withoutPadding)) {
    errors.push('Contains repetitive characters');
  }

  // Repeated patterns (abcabc, 123123)
  if (/(.+)\1+/.test(withoutPadding)) {
    errors.push('Contains repeated patterns');
  }

  // Sequential patterns (abc, 123, qwerty)
  const sequentialPatterns = [
    /abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i,
    /012|123|234|345|456|567|678|789|890/,
    /qwerty|asdfgh|zxcvbn|qazwsx/i,
  ];

  for (const pattern of sequentialPatterns) {
    if (pattern.test(withoutPadding)) {
      errors.push('Contains sequential patterns');
      break;
    }
  }

  // ── 5. Character Class Diversity ────────────────────────────────────
  const hasUpper = /[A-Z]/.test(trimmed);
  const hasLower = /[a-z]/.test(trimmed);
  const hasDigit = /\d/.test(trimmed);
  const hasSpecial = /[^A-Za-z0-9]/.test(trimmed);

  // All-numeric
  if (/^\d+$/.test(trimmed)) {
    errors.push('JWT secret contains only digits. Use a mix of letters, numbers, and symbols.');
  }

  // All same-case letters
  if (/^[a-z]+$/.test(trimmed) && trimmed.length >= MIN_SECRET_LENGTH) {
    warnings.push('JWT secret contains only lowercase letters. Consider adding uppercase, digits, and symbols.');
  }
  if (/^[A-Z]+$/.test(trimmed) && trimmed.length >= MIN_SECRET_LENGTH) {
    warnings.push('JWT secret contains only uppercase letters. Consider adding lowercase, digits, and symbols.');
  }

  // ── 6. Shannon Entropy Check ────────────────────────────────────────
  const entropy = calculateShannonEntropy(withoutPadding);
  if (entropy < 3.5) {
    errors.push('Low entropy detected');
    warnings.push(`Low entropy detected (Shannon entropy: ${entropy.toFixed(2)})`);
  }

  // ── 7. Complexity recommendation ────────────────────────────────────
  const classCount = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
  if (classCount < 3 && trimmed.length >= MIN_SECRET_LENGTH && errors.length === 0) {
    warnings.push('JWT secret uses fewer than 3 character classes. Mix uppercase, lowercase, digits, and symbols.');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}
