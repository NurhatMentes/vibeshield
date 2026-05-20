import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { handleError } from '../src/core/errorHandler.js';

describe('Global Exception Middleware', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return a masked error response with status 500 by default', async () => {
    const error = new Error('Database password was: secret_db_123');
    const response = handleError(error);

    expect(response.status).toBe(500);
    expect(response.headers.get('Content-Type')).toBe('application/json');

    const body = await response.json();
    expect(body.error).toBe('Internal Server Error');
    expect(body.code).toBe('INTERNAL_SERVER_ERROR');
    expect(body.trackingId).toMatch(/^VS-[A-Z0-9]{4}$/);
    expect(body.message).toContain('An unexpected error occurred. Please contact support with code:');
    expect(body.message).not.toContain('secret_db_123'); // Masked!
  });

  it('should show the raw error message if masking is disabled', async () => {
    const error = new Error('Failed to resolve host');
    const response = handleError(error, { maskErrors: false });

    const body = await response.json();
    expect(body.message).toBe('Failed to resolve host'); // Raw error message is returned
    expect(body.trackingId).toMatch(/^VS-[A-Z0-9]{4}$/);
  });

  it('should log the stack trace to console by default', () => {
    const error = new Error('Test crash');
    handleError(error);

    expect(console.error).toHaveBeenCalled();
    const logCall = (console.error as any).mock.calls[0];
    expect(logCall[0]).toContain('[VibeShield]');
    expect(logCall[0]).toContain('Unhandled exception captured:');
    expect(logCall[1]).toBe(error);
  });

  it('should not log to console if logging is disabled', () => {
    const error = new Error('Test crash');
    handleError(error, { logErrors: false });

    expect(console.error).not.toHaveBeenCalled();
  });
});
