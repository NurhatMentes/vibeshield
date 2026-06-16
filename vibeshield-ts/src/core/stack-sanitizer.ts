/**
 * VibeShield Stack Trace Sanitizer
 * 
 * Prevents sensitive information from leaking through error stack traces.
 * Redacts file paths, IP addresses, database connection strings, and 
 * environment-specific paths using pure regex-based pattern matching.
 * 
 * Zero external dependencies.
 */

/** Redaction markers */
const MARKERS = {
  PROJECT_ROOT: '[PROJECT_ROOT]/...',
  NODE_MODULES: '[NODE_MODULES]/...',
  REDACTED_IP: '[REDACTED_IP]',
  REDACTED_DB: '[REDACTED_DB_INFO]',
} as const;

/**
 * Compiled regex patterns for sensitive data detection.
 * Ordered by specificity: more specific patterns first to avoid partial matches.
 */
const PATTERNS: ReadonlyArray<{ regex: RegExp; replacement: string }> = [
  // Database connection strings (must run before generic path redaction)
  {
    regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|mariadb|sqlite):\/\/[^\s'",)}\]]+/gi,
    replacement: MARKERS.REDACTED_DB,
  },

  // Node modules paths (must run before generic path redaction)
  {
    regex: /node_modules\/[^\s'",)}\]:]+/g,
    replacement: MARKERS.NODE_MODULES,
  },

  // Absolute Unix/macOS file paths: /Users/..., /home/..., /var/..., /tmp/..., /opt/...
  {
    regex: /\/(?:Users|home|var|tmp|opt|etc|root)\/[^\s'",)}\]:]+/g,
    replacement: MARKERS.PROJECT_ROOT,
  },

  // Windows absolute file paths: C:\..., D:\...
  {
    regex: /[A-Z]:\\[^\s'",)}\]:]+/g,
    replacement: MARKERS.PROJECT_ROOT,
  },

  // IPv6 addresses (simplified but catches common formats including ::1 and full notation)
  {
    regex: /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|::1|::/g,
    replacement: MARKERS.REDACTED_IP,
  },

  // IPv4 addresses
  {
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    replacement: MARKERS.REDACTED_IP,
  },

  // Common database table/schema name patterns appearing in SQL-like contexts
  {
    regex: /(?:FROM|INTO|UPDATE|TABLE|JOIN|ALTER)\s+[`"']?(\w+\.)?(\w+)[`"']?/gi,
    replacement: (match: string) => {
      // Keep the SQL keyword, redact the table/schema reference
      const keyword = match.split(/\s+/)[0];
      return `${keyword} ${MARKERS.REDACTED_DB}`;
    },
  },
];

/**
 * Sanitizes stack trace content by redacting sensitive information.
 * 
 * This function processes the input through multiple regex patterns to remove:
 * - Absolute file paths (Unix, macOS, Windows)
 * - Node module paths
 * - IPv4 and IPv6 addresses
 * - Database connection URIs (postgres://, mongodb://, etc.)
 * - SQL table/schema references
 * 
 * @param error - An Error object or raw string to sanitize
 * @returns The sanitized string with all sensitive data replaced by safe markers
 */
export function sanitizeStackTrace(error: Error | string): string {
  let raw: string;

  if (error instanceof Error) {
    // Combine message + stack for comprehensive sanitization
    raw = error.stack ?? error.message;
  } else {
    raw = String(error);
  }

  let sanitized = raw;

  for (const pattern of PATTERNS) {
    if (typeof pattern.replacement === 'string') {
      sanitized = sanitized.replace(pattern.regex, pattern.replacement);
    } else {
      sanitized = sanitized.replace(pattern.regex, pattern.replacement);
    }
  }

  return sanitized;
}
