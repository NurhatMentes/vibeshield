import { safeJsonParse } from '../core/deserialization-protector.js';

/**
 * Middleware or helper to enforce safe JSON parsing on HTTP request bodies.
 * @param bodyText - The raw text of the request body.
 * @param maxDepth - Optional maximum nesting depth limit.
 * @returns The parsed and sanitized JSON object, or an empty object if bodyText is empty.
 */
export function enforceSafeJson(bodyText: string, maxDepth?: number): any {
  if (!bodyText || bodyText.trim() === '') {
    return {};
  }
  return safeJsonParse(bodyText, { maxDepth });
}
