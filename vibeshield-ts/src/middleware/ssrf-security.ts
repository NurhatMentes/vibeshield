import { validateUrl } from '../core/ssrf-protector.js';

/**
 * Custom error thrown when an SSRF validation check fails.
 */
export class VibeShieldSSRFError extends Error {
  public url: string;
  public reason: string;

  constructor(url: string, reason: string) {
    super(`[VibeShield] SSRF Protection: Blocked URL "${url}". Reason: ${reason}`);
    this.name = 'VibeShieldSSRFError';
    this.url = url;
    this.reason = reason;
    Object.setPrototypeOf(this, VibeShieldSSRFError.prototype);
  }
}

/**
 * Enforces that the given URL is safe from SSRF attacks.
 * Throws a VibeShieldSSRFError if the URL is deemed unsafe.
 *
 * @param targetUrl - The target URL to validate.
 * @throws {VibeShieldSSRFError} If the URL is not safe.
 */
export function enforceSafeUrl(targetUrl: string): void {
  const result = validateUrl(targetUrl);
  if (!result.safe) {
    throw new VibeShieldSSRFError(targetUrl, result.reason || 'Blocked by SSRF policy');
  }
}
