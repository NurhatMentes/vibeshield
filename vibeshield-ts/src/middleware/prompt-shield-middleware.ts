import { detectPromptInjection, PromptShieldResult, PromptShieldOptions } from '../core/prompt-shield.js';

export interface PromptShieldMiddlewareOptions extends PromptShieldOptions {
  fields?: string[];
  threshold?: number; // default: 100 (HIGH)
  blockOnDetection?: boolean; // default: true
  onDetection?: (result: PromptShieldResult, req: any) => void;
}

export function promptShieldMiddleware(options?: PromptShieldMiddlewareOptions) {
  const fields = options?.fields || ['prompt', 'message', 'query', 'input', 'text', 'content'];
  const threshold = options?.threshold ?? 100;
  const blockOnDetection = options?.blockOnDetection ?? true;

  return (req: any, res?: any, next?: any) => {
    // Next.js Route Handler Wrapper check: arg1 is a function
    if (typeof req === 'function') {
      const handler = req;
      return async (webReq: any, ...args: any[]) => {
        let body: any = {};
        if (webReq && typeof webReq.json === 'function') {
          try {
            const clone = webReq.clone();
            body = await clone.json();
          } catch (e) {
            body = {};
          }
        }

        let maxScore = 0;
        let worstResult: PromptShieldResult = {
          safe: true,
          score: 0,
          riskLevel: 'none',
          threats: [],
          summary: 'Input is safe'
        };

        // Scan all specified fields in the request body
        for (const field of fields) {
          const val = body[field];
          if (typeof val === 'string' && val) {
            const result = detectPromptInjection(val, options);
            if (result.score > maxScore) {
              maxScore = result.score;
              worstResult = result;
            }
          }
        }

        if (maxScore >= threshold) {
          if (options?.onDetection) {
            options.onDetection(worstResult, webReq);
          }
          if (blockOnDetection) {
            return new Response(
              JSON.stringify({
                error: 'Forbidden',
                message: 'Potential prompt injection or jailbreak detected',
                details: worstResult
              }),
              {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
              }
            );
          }
        }

        // Attach result to request
        (webReq as any).promptShieldResult = worstResult;

        return handler(webReq, ...args);
      };
    }

    // Express middleware
    let maxScore = 0;
    let worstResult: PromptShieldResult = {
      safe: true,
      score: 0,
      riskLevel: 'none',
      threats: [],
      summary: 'Input is safe'
    };

    const body = req.body || {};
    for (const field of fields) {
      const val = body[field];
      if (typeof val === 'string' && val) {
        const result = detectPromptInjection(val, options);
        if (result.score > maxScore) {
          maxScore = result.score;
          worstResult = result;
        }
      }
    }

    if (maxScore >= threshold) {
      if (options?.onDetection) {
        options.onDetection(worstResult, req);
      }
      if (blockOnDetection) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Potential prompt injection or jailbreak detected',
          details: worstResult
        });
      }
    }

    req.promptShieldResult = worstResult;

    if (typeof next === 'function') {
      next();
    }
  };
}
