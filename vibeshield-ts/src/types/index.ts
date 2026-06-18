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

export type ValidatorType = 'string' | 'number' | 'boolean' | 'object' | 'array';

export interface ValidationRule {
  type: ValidatorType;
  required?: boolean;
  min?: number;
  max?: number;
  format?: 'email' | 'uuid' | 'url' | 'ipv4' | 'ipv6' | 'date' | 'phone';
  pattern?: RegExp;
  enum?: any[];
  schema?: Record<string, ValidationRule>; // For nested objects
  elementSchema?: ValidationRule;          // For arrays containing objects or specific types
  allowNull?: boolean;
  trim?: boolean;
}

export type ValidationSchema = Record<string, ValidationRule>;

export interface LoggingOptions {
  /**
   * Log every request and its precise duration to the console.
   * @default false
   */
  audit?: boolean;

  /**
   * Threshold in milliseconds. If execution time exceeds this, a VIBESHIELD PERFORMANCE WARNING is logged.
   * @default undefined
   */
  performanceThresholdMs?: number;
}

export interface BudgetOptions {
  /**
   * Enable the VibeBudgeter shield for external requests.
   * @default false
   */
  enabled: boolean;

  /**
   * Maximum allowed external API calls per UTC day.
   */
  maxDailyRequests?: number;

  /**
   * Estimated dollar cost per LLM token.
   */
  estimatedCostPerToken?: number;

  /**
   * Maximum estimated dollar amount allowed per UTC day.
   */
  dailyDollarLimit?: number;
}

export interface VibeShieldOptions {
  security?: SecurityOptions;
  crypto?: CryptoOptions;
  cache?: CacheOptions;
  errors?: ErrorOptions;
  validationSchema?: ValidationSchema;
  logging?: LoggingOptions;
  budget?: BudgetOptions;
}
