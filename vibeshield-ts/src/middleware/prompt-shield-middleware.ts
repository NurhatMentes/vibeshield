import { detectPromptInjection, PromptShieldResult, PromptShieldOptions, generateCanaryToken } from '../core/prompt-shield.js';

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

        body = body || {};

        // Auto-inject canary token into system prompt if not present
        const systemPromptFields = ['systemPrompt', 'system_prompt', 'system', 'instructions'];
        let systemPromptField = systemPromptFields.find(f => body[f] !== undefined);
        let canaryToken = '';
        let hasCanary = false;

        if (systemPromptField) {
          const currentSysPrompt = body[systemPromptField];
          if (typeof currentSysPrompt === 'string') {
            const match = currentSysPrompt.match(/CANARY_VIBESHIELD_[a-f0-9]{32}/i);
            if (match) {
              hasCanary = true;
              canaryToken = match[0];
            }
          }
        }

        if (!hasCanary) {
          canaryToken = generateCanaryToken();
          if (systemPromptField) {
            body[systemPromptField] = `${body[systemPromptField]}\n[VS-CANARY-${canaryToken}]`;
          } else {
            systemPromptField = 'systemPrompt';
            body[systemPromptField] = `[VS-CANARY-${canaryToken}]`;
          }
        }

        (webReq as any).promptShieldCanary = canaryToken;
        webReq.json = async () => body;

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
    let body = req.body || {};
    
    // Auto-inject canary token into system prompt if not present
    const systemPromptFields = ['systemPrompt', 'system_prompt', 'system', 'instructions'];
    let systemPromptField = systemPromptFields.find(f => body[f] !== undefined);
    let canaryToken = '';
    let hasCanary = false;

    if (systemPromptField) {
      const currentSysPrompt = body[systemPromptField];
      if (typeof currentSysPrompt === 'string') {
        const match = currentSysPrompt.match(/CANARY_VIBESHIELD_[a-f0-9]{32}/i);
        if (match) {
          hasCanary = true;
          canaryToken = match[0];
        }
      }
    }

    if (!hasCanary) {
      canaryToken = generateCanaryToken();
      if (systemPromptField) {
        body[systemPromptField] = `${body[systemPromptField]}\n[VS-CANARY-${canaryToken}]`;
      } else {
        systemPromptField = 'systemPrompt';
        body[systemPromptField] = `[VS-CANARY-${canaryToken}]`;
      }
    }

    req.promptShieldCanary = canaryToken;
    req.body = body;

    let maxScore = 0;
    let worstResult: PromptShieldResult = {
      safe: true,
      score: 0,
      riskLevel: 'none',
      threats: [],
      summary: 'Input is safe'
    };

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
