import { SecurityOptions } from '../types/index.js';

/**
 * Sanitizes a string by stripping HTML/JS tags, neutralizing JavaScript URIs,
 * and escaping SQL injection characters.
 */
export function sanitizeString(val: string, options?: SecurityOptions): string {
  if (!val || typeof val !== 'string') {
    return val;
  }

  let clean = val;

  // 1. Remove script tags and their content aggressively
  clean = clean.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

  // 2. Strip all other HTML tags
  clean = clean.replace(/<\/?[^>]+(>|$)/g, '');

  // 3. Neutralize JavaScript URLs (e.g. javascript:alert(1))
  clean = clean.replace(/javascript\s*:/gi, 'unsafe-protocol:');

  // 4. Escape SQL Injection characters
  // Replace single quotes with double single quotes (standard SQL escaping)
  clean = clean.replace(/'/g, "''");
  // Replace SQL comments `--` and `/*` to prevent query termination/truncation
  clean = clean.replace(/--/g, '__');
  clean = clean.replace(/\/\*/g, '/+').replace(/\*\//g, '+/');

  // 5. Escape HTML angle brackets and double quotes for safety
  clean = clean
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  return clean;
}

/**
 * Deep sanitizes objects, arrays, and primitive values recursively.
 * Removes NoSQL operators (keys starting with $) to prevent injection attacks.
 */
export function sanitize<T>(val: T, options?: SecurityOptions): T {
  if (val === null || val === undefined) {
    return val;
  }

  if (typeof val === 'string') {
    return sanitizeString(val, options) as unknown as T;
  }

  if (Array.isArray(val)) {
    return val.map(item => sanitize(item, options)) as unknown as T;
  }

  if (typeof val === 'object') {
    // Return standard built-in objects without modification
    if (
      val instanceof Date ||
      val instanceof RegExp ||
      val instanceof ArrayBuffer ||
      ArrayBuffer.isView(val)
    ) {
      return val;
    }

    const sanitizedObj: Record<string, any> = {};

    for (const [key, value] of Object.entries(val)) {
      // Block MongoDB operators ($gt, $ne, $where, etc.)
      if (key.startsWith('$')) {
        continue;
      }

      const cleanKey = sanitizeString(key, options);
      sanitizedObj[cleanKey] = sanitize(value, options);
    }

    return sanitizedObj as unknown as T;
  }

  return val;
}

/**
 * Helper to sanitize URL search parameters and return a clean URL string.
 */
export function sanitizeUrl(urlStr: string, options?: SecurityOptions): string {
  try {
    const url = new URL(urlStr);
    const params = new URLSearchParams(url.search);
    const sanitizedParams = new URLSearchParams();

    for (const [key, value] of params.entries()) {
      // Skip NoSQL keys in query string if any contain $
      if (key.includes('$')) {
        continue;
      }
      const cleanKey = sanitizeString(key, options);
      const cleanValue = sanitizeString(value, options);
      sanitizedParams.append(cleanKey, cleanValue);
    }

    url.search = sanitizedParams.toString();
    return url.toString();
  } catch (e) {
    return urlStr;
  }
}
