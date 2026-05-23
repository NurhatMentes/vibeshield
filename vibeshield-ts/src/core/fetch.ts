import { globalBudgetTracker } from './budget.js';
import { VibeShieldOptions } from '../types/index.js';

/**
 * A drop-in replacement for the native `fetch` API.
 * 
 * If a `budget` is provided in the `VibeShieldOptions`, it acts as a strict
 * financial circuit breaker. Once the daily limit (request count or dollar cost)
 * is exceeded, `vibeFetch` will aggressively short-circuit and block outbound calls
 * to prevent runaway third-party API bills.
 */
export async function vibeFetch(input: RequestInfo | URL, init?: RequestInit, options?: VibeShieldOptions): Promise<Response> {
  const budgetOpts = options?.budget;

  // 1. Pre-Request Circuit Breaker Check
  if (budgetOpts?.enabled) {
    globalBudgetTracker.trackRequest(budgetOpts);
  }

  // 2. Execute External API Call
  const response = await fetch(input, init);

  // 3. Post-Request Cost Tracking (Token Counting)
  if (budgetOpts?.enabled && budgetOpts.estimatedCostPerToken !== undefined) {
    // Clone the response so the developer can still consume the original stream
    const clonedResponse = response.clone();
    
    // We attempt to asynchronously parse the payload for standard LLM token markers
    // without blocking the main execution pipeline.
    clonedResponse.json().then(data => {
      if (data && data.usage && typeof data.usage.total_tokens === 'number') {
        globalBudgetTracker.trackCost(budgetOpts, data.usage.total_tokens);
      }
    }).catch(() => {
      // Ignore JSON parsing errors for non-JSON or streaming endpoints
    });
  }

  return response;
}
