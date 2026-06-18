import { detectPromptInjection, generateCanaryToken, PromptShieldResult, PromptShieldOptions } from '../core/prompt-shield.js';

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

        // Automatic Canary Token Injection for System Prompt
        let systemPromptField = '';
        if ('systemPrompt' in body) systemPromptField = 'systemPrompt';
        else if ('system_prompt' in body) systemPromptField = 'system_prompt';
        else if ('system' in body) systemPromptField = 'system';

        let canary = '';
        if (systemPromptField) {
          let systemPrompt = body[systemPromptField] || '';
          if (typeof systemPrompt === 'string' && !systemPrompt.includes('CANARY_VIBESHIELD_')) {
            canary = generateCanaryToken();
            systemPrompt = systemPrompt ? `${systemPrompt}\n${canary}` : canary;
            body[systemPromptField] = systemPrompt;
          }
        } else {
          canary = generateCanaryToken();
          body['systemPrompt'] = canary;
        }

        // Intercept webReq json method and attach result/canary
        const interceptedReq = new Proxy(webReq, {
          get(target, prop, receiver) {
            if (prop === 'json') {
              return async () => body;
            }
            if (prop === 'promptShieldResult') {
              return worstResult;
            }
            if (prop === 'promptShieldCanary') {
              return canary;
            }
            return Reflect.get(target, prop, receiver);
          }
        });

        return handler(interceptedReq, ...args);
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

    // Automatic Canary Token Injection for System Prompt
    let systemPromptField = '';
    if ('systemPrompt' in body) systemPromptField = 'systemPrompt';
    else if ('system_prompt' in body) systemPromptField = 'system_prompt';
    else if ('system' in body) systemPromptField = 'system';

    let canary = '';
    if (systemPromptField) {
      let systemPrompt = body[systemPromptField] || '';
      if (typeof systemPrompt === 'string' && !systemPrompt.includes('CANARY_VIBESHIELD_')) {
        canary = generateCanaryToken();
        systemPrompt = systemPrompt ? `${systemPrompt}\n${canary}` : canary;
        body[systemPromptField] = systemPrompt;
      }
    } else {
      canary = generateCanaryToken();
      body['systemPrompt'] = canary;
    }

    req.promptShieldResult = worstResult;
    req.promptShieldCanary = canary;

    if (typeof next === 'function') {
      next();
    }
  };
}
