export interface SecurityOptions {
  /**
   * Automatically deep-sanitize the request body (e.g. req.json(), req.formData(), req.text()).
   * @default true
   */
  sanitizeBody?: boolean;

  /**
   * Automatically sanitize the URL query parameters (searchParams).
   * @default true
   */
  sanitizeQuery?: boolean;

  /**
   * Automatically sanitize route parameters (context.params).
   * @default true
   */
  sanitizeParams?: boolean;
}

export interface CacheOptions {
  /**
   * Enable in-memory caching for GET requests.
   * @default false
   */
  enabled?: boolean;

  /**
   * Time-To-Live in seconds for cached responses. Max limit is 60 seconds.
   * @default 60
   */
  ttl?: number;

  /**
   * Maximum number of items in the in-memory cache. Max limit is 500 records.
   * @default 500
   */
  limit?: number;

  /**
   * Custom cache key generator. Falls back to default `method:url` key.
   */
  keyGenerator?: (req: Request) => string;
}

export interface ErrorOptions {
  /**
   * Mask runtime exceptions with a safe error message and custom tracking code (VS-XXXX).
   * @default true
   */
  maskErrors?: boolean;

  /**
   * Log full error stack traces with tracking IDs to the server console.
   * @default true
   */
  logErrors?: boolean;
}

export interface CryptoOptions {
  /**
   * Secret key used for HMAC signing and AES-256 encryption.
   */
  secretKey: string;

  /**
   * List of specific object keys (e.g., "creditCard", "ssn") to automatically encrypt in request bodies and decrypt in responses.
   */
  encryptFields?: string[];
}

export interface VibeShieldOptions {
  security?: SecurityOptions;
  crypto?: CryptoOptions;
  cache?: CacheOptions;
  errors?: ErrorOptions;
}
