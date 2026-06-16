import { ErrorOptions } from '../types/index.js';
import { sanitizeStackTrace } from './stack-sanitizer.js';

/**
 * Generates a tracking ID of format VS-XXXX using uppercase alphanumeric characters.
 */
function generateTrackingId(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let trackingSuffix = '';
  for (let i = 0; i < 4; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    trackingSuffix += chars.charAt(randomIndex);
  }
  return `VS-${trackingSuffix}`;
}

/**
 * Handles unhandled errors by logging them internally and returning a sanitized client-side error.
 * 
 * Server-side logs receive the sanitized stack trace (sensitive paths, IPs, and DB info redacted).
 * Client-side responses receive only a generic error message and a tracking ID.
 */
export function handleError(error: unknown, options?: ErrorOptions): Response {
  const trackingId = generateTrackingId();
  const mask = options?.maskErrors !== false;
  const log = options?.logErrors !== false;

  if (log) {
    // Sanitize the stack trace before logging to prevent accidental leakage in log aggregators
    const sanitizedTrace = error instanceof Error || typeof error === 'string'
      ? sanitizeStackTrace(error)
      : String(error);
    console.error(`[VibeShield] [${trackingId}] Unhandled exception captured:\n${sanitizedTrace}`);
  }

  const rawMessage = error instanceof Error ? error.message : String(error);

  const responseBody = {
    error: 'Internal Server Error',
    message: mask
      ? `An unexpected error occurred. Please contact support with code: ${trackingId}`
      : rawMessage,
    code: 'INTERNAL_SERVER_ERROR',
    trackingId,
  };

  return new Response(JSON.stringify(responseBody), {
    status: 500,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}
