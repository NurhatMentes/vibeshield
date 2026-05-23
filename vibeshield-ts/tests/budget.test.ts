import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { globalBudgetTracker } from '../src/core/budget';
import { vibeFetch } from '../src/core/fetch';

// Mock the native global fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('VibeShield Phase 4: VibeBudgeter (Financial Shield)', () => {
  beforeEach(() => {
    globalBudgetTracker.resetForTest();
    mockFetch.mockReset();
    vi.spyOn(console, 'warn').mockImplementation(() => {}); // Suppress warnings in test output
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Budget Tracker Engine', () => {
    it('should track requests and throw error when maxDailyRequests is exceeded', () => {
      const options = { enabled: true, maxDailyRequests: 2 };
      
      globalBudgetTracker.trackRequest(options); // Req 1
      globalBudgetTracker.trackRequest(options); // Req 2
      
      expect(globalBudgetTracker.getRequests()).toBe(2);
      expect(() => globalBudgetTracker.trackRequest(options)).toThrowError('VIBESHIELD BUDGET EXCEEDED');
    });

    it('should track token costs and throw error when dailyDollarLimit is exceeded', () => {
      const options = { enabled: true, dailyDollarLimit: 1.00, estimatedCostPerToken: 0.01 }; // $0.01 per token
      
      globalBudgetTracker.trackCost(options, 50); // $0.50
      expect(globalBudgetTracker.getCost()).toBe(0.50);
      
      globalBudgetTracker.trackCost(options, 60); // $0.60 -> Total $1.10
      expect(globalBudgetTracker.getCost()).toBe(1.10);
      
      expect(() => globalBudgetTracker.trackRequest(options)).toThrowError('VIBESHIELD BUDGET EXCEEDED');
    });

    it('should do nothing if budget is disabled', () => {
      const options = { enabled: false, maxDailyRequests: 1 };
      globalBudgetTracker.trackRequest(options);
      globalBudgetTracker.trackRequest(options); // Should not throw
      expect(globalBudgetTracker.getRequests()).toBe(0); // Tracking disabled
    });
  });

  describe('vibeFetch Wrapper', () => {
    it('should transparently pass through to fetch if under budget', async () => {
      mockFetch.mockResolvedValueOnce(new Response('ok'));
      const options = { budget: { enabled: true, maxDailyRequests: 5 } };
      
      const res = await vibeFetch('https://api.openai.com/v1/chat', undefined, options);
      expect(res.status).toBe(200);
      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(globalBudgetTracker.getRequests()).toBe(1);
    });

    it('should short-circuit without calling fetch if budget is exceeded', async () => {
      const options = { budget: { enabled: true, maxDailyRequests: 1 } };
      
      mockFetch.mockResolvedValueOnce(new Response('ok 1'));
      await vibeFetch('https://api.test/1', undefined, options);
      
      await expect(vibeFetch('https://api.test/2', undefined, options)).rejects.toThrowError('VIBESHIELD BUDGET EXCEEDED');
      
      expect(mockFetch).toHaveBeenCalledTimes(1); // 2nd fetch was blocked
    });

    it('should dynamically parse LLM token usage asynchronously without blocking', async () => {
      // Mock an LLM API response with usage metrics
      const llmResponse = new Response(JSON.stringify({ usage: { total_tokens: 100 } }), {
        headers: { 'Content-Type': 'application/json' }
      });
      mockFetch.mockResolvedValueOnce(llmResponse);
      
      const options = { budget: { enabled: true, estimatedCostPerToken: 0.01, dailyDollarLimit: 5.00 } };
      
      await vibeFetch('https://api.openai.com', undefined, options);
      
      // Allow async microtasks (the cloned response parsing) to settle
      await new Promise(resolve => setTimeout(resolve, 10));
      
      expect(globalBudgetTracker.getCost()).toBe(1.00); // 100 tokens * $0.01
    });
  });
});
