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
 * Checks whether a string consists of a single repeating character (e.g., "aaaaaa", "111111").
 */
function isRepeatingChars(s: string): boolean {
  if (s.length === 0) return false;
  const first = s[0];
  for (let i = 1; i < s.length; i++) {
    if (s[i] !== first) return false;
  }
  return true;
}

/**
 * Checks whether a string is a short repeating pattern (e.g., "abcabc", "ababab").
 */
function isRepeatingPattern(s: string): boolean {
  const len = s.length;
  if (len < 4) return false;
  // Check pattern lengths from 1 up to half the string length
  for (let patLen = 1; patLen <= Math.floor(len / 2); patLen++) {
    if (len % patLen !== 0) continue;
    const pattern = s.substring(0, patLen);
    let match = true;
    for (let i = patLen; i < len; i += patLen) {
      if (s.substring(i, i + patLen) !== pattern) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}

/**
 * Calculates Shannon entropy (bits per character) for a given string.
 * Higher entropy indicates more randomness/complexity.
 */
function calculateEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = s.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
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

  // ── 4. Repeating Character / Pattern Check ──────────────────────────
  if (isRepeatingChars(trimmed)) {
    errors.push('JWT secret consists of a single repeating character (e.g., "aaaaaa"). Use a diverse secret.');
  } else if (isRepeatingPattern(trimmed)) {
    errors.push('JWT secret is a short repeating pattern (e.g., "abcabc"). Use a non-predictable secret.');
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
  const entropy = calculateEntropy(trimmed);
  if (trimmed.length >= MIN_SECRET_LENGTH && entropy < 2.0) {
    warnings.push(`JWT secret has very low entropy (${entropy.toFixed(2)} bits/char). Consider using a more random value.`);
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
