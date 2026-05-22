import { VibeShieldOptions } from '../types/index.js';
import { sanitize, sanitizeString, sanitizeUrl } from './sanitizer.js';
import { globalCache } from './cache.js';
import { handleError } from './errorHandler.js';
import { processCryptoFields } from './security/crypto.js';

/**
 * Creates a sanitized ES6 Proxy wrapper over the original Request object.
 * Sanitizes req.json(), req.text(), req.formData(), req.url, and NextRequest.nextUrl.searchParams.
 */
function createSanitizedRequest(req: Request, options?: VibeShieldOptions): Request {
  const securityOpts = options?.security;

  // Memoize body parser promises to prevent multiple stream reading errors
  let cachedJsonPromise: Promise<any> | null = null;
  let cachedTextPromise: Promise<string> | null = null;
  let cachedFormDataPromise: Promise<FormData> | null = null;

  const proxyHandler: ProxyHandler<any> = {
    get(target, prop, receiver) {
      // 1. Intercept JSON Body parsing
      if (prop === 'json' && securityOpts?.sanitizeBody !== false) {
        return () => {
          if (!cachedJsonPromise) {
            cachedJsonPromise = target
              .clone()
              .json()
              .then((data: any) => sanitize(data, securityOpts))
              .then((data: any) => {
                if (options?.crypto?.encryptFields && options.crypto.secretKey) {
                  return processCryptoFields(data, options.crypto.encryptFields, true, options.crypto.secretKey);
                }
                return data;
              });
          }
          return cachedJsonPromise;
        };
      }

      // 2. Intercept Text Body parsing
      if (prop === 'text' && securityOpts?.sanitizeBody !== false) {
        return () => {
          if (!cachedTextPromise) {
            cachedTextPromise = target
              .clone()
              .text()
              .then((text: string) => sanitizeString(text, securityOpts));
          }
          return cachedTextPromise;
        };
      }

      // 3. Intercept Form Data parsing
      if (prop === 'formData' && securityOpts?.sanitizeBody !== false) {
        return () => {
          if (!cachedFormDataPromise) {
            cachedFormDataPromise = target
              .clone()
              .formData()
              .then((formData: FormData) => {
                const cleanFormData = new FormData();
                for (const [key, value] of formData.entries()) {
                  if (typeof value === 'string') {
                    cleanFormData.append(key, sanitizeString(value, securityOpts));
                  } else {
                    cleanFormData.append(key, value);
                  }
                }
                return cleanFormData;
              });
          }
          return cachedFormDataPromise;
        };
      }

      // 4. Intercept URL Search query parameters (standard Request.url)
      if (prop === 'url' && securityOpts?.sanitizeQuery !== false) {
        return sanitizeUrl(target.url, securityOpts);
      }

      // 5. Intercept Next.js NextRequest.nextUrl search parameters
      if (prop === 'nextUrl' && securityOpts?.sanitizeQuery !== false && 'nextUrl' in target) {
        const originalNextUrl = target.nextUrl;
        return new Proxy(originalNextUrl, {
          get(nextUrlTarget, nextUrlProp, nextUrlReceiver) {
            if (nextUrlProp === 'searchParams') {
              const originalSearchParams = nextUrlTarget.searchParams;
              return new Proxy(originalSearchParams, {
                get(spTarget, spProp, spReceiver) {
                  if (spProp === 'get') {
                    return (name: string) => {
                      const val = spTarget.get(name);
                      return val ? sanitizeString(val, securityOpts) : null;
                    };
                  }
                  if (spProp === 'getAll') {
                    return (name: string) => {
                      return spTarget
                        .getAll(name)
                        .map((val: string) => sanitizeString(val, securityOpts));
                    };
                  }
                  const spValue = Reflect.get(spTarget, spProp, spReceiver);
                  return typeof spValue === 'function' ? spValue.bind(spTarget) : spValue;
                }
              });
            }
            const nextUrlValue = Reflect.get(nextUrlTarget, nextUrlProp, nextUrlReceiver);
            return typeof nextUrlValue === 'function' ? nextUrlValue.bind(nextUrlTarget) : nextUrlValue;
          }
        });
      }

      // Default property resolution binding functions to original target context
      const value = Reflect.get(target, prop, receiver);
      return typeof value === 'function' ? value.bind(target) : value;
    }
  };

  return new Proxy(req, proxyHandler);
}

/**
 * VibeShield: Zero-configuration interceptor wrapper for Next.js App Router API Routes.
 */
export function vibeShield(
  handler: (req: Request, context?: any) => Promise<Response> | Response,
  options?: VibeShieldOptions
): (req: Request, context?: any) => Promise<Response> {
  return async (req: Request, context?: any): Promise<Response> => {
    const cacheEnabled = options?.cache?.enabled === true;
    const isGet = req.method.toUpperCase() === 'GET';
    let cacheKey = '';

    // 1. In-Memory Cache Lookup (Only for GET routes)
    if (cacheEnabled && isGet) {
      try {
        const generator = options?.cache?.keyGenerator || ((r: Request) => `${r.method}:${r.url}`);
        cacheKey = generator(req);
        const cachedResponse = globalCache.get(cacheKey);
        if (cachedResponse) {
          return cachedResponse;
        }
      } catch (e) {
        // Fallback silently if cache lookup or key generation fails
      }
    }

    try {
      // 2. Route Params Sanitization (Next.js 13/14 object vs Next.js 15 Promise resolution)
      let sanitizedContext = context;
      if (context && typeof context === 'object') {
        sanitizedContext = { ...context };
        if (context.params && options?.security?.sanitizeParams !== false) {
          const paramsVal = context.params;
          // Check if params is a Promise or Promise-like object (Next.js 15)
          if (
            paramsVal instanceof Promise ||
            (typeof paramsVal === 'object' && typeof paramsVal.then === 'function')
          ) {
            const resolvedParams = await paramsVal;
            const cleanParams = sanitize(resolvedParams, options?.security);
            sanitizedContext.params = Promise.resolve(cleanParams);
          } else {
            // Standard plain object params (Next.js 13/14)
            sanitizedContext.params = sanitize(paramsVal, options?.security);
          }
        }
      }

      // 3. Request Interception using Proxy
      const sanitizedReq = createSanitizedRequest(req, options);

      // 4. Handler Execution
      let response = await handler(sanitizedReq, sanitizedContext);

      // 4b. Transparent Response Decryption
      if (options?.crypto?.encryptFields && options.crypto.secretKey) {
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          try {
            const resData = await response.clone().json();
            const decryptedData = processCryptoFields(resData, options.crypto.encryptFields, false, options.crypto.secretKey);
            response = new Response(JSON.stringify(decryptedData), {
              status: response.status,
              statusText: response.statusText,
              headers: response.headers,
            });
          } catch (e) {
            // Silently fallback if JSON parsing fails
          }
        }
      }

      // 5. In-Memory Cache Write (Only for successful GET responses)
      if (cacheEnabled && isGet && response.ok) {
        // Run cache write asynchronously without blocking client transmission
        globalCache.set(cacheKey, response, options?.cache?.ttl).catch(() => {});
      }

      return response;
    } catch (error) {
      // 6. Global Exception Middleware Mapping
      return handleError(error, options?.errors);
    }
  };
}
