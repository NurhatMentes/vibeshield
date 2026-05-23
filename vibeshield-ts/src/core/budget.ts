import { BudgetOptions } from '../types/index.js';

export class BudgetTracker {
  private requests: number = 0;
  private currentCost: number = 0;
  private currentDay: number = new Date().getUTCDate();

  private resetIfNeeded() {
    const today = new Date().getUTCDate();
    if (this.currentDay !== today) {
      this.requests = 0;
      this.currentCost = 0;
      this.currentDay = today;
    }
  }

  private logWarning() {
    console.warn('\n⚠️ [VIBESHIELD BUDGET EXCEEDED] ⚠️\nExternal API calls blocked to prevent unexpected cloud bills.\n');
  }

  public trackRequest(options: BudgetOptions): void {
    if (!options.enabled) return;
    this.resetIfNeeded();
    
    if (options.maxDailyRequests !== undefined && this.requests >= options.maxDailyRequests) {
      this.logWarning();
      throw new Error('[VIBESHIELD BUDGET EXCEEDED] External API calls blocked to prevent unexpected cloud bills.');
    }
    if (options.dailyDollarLimit !== undefined && this.currentCost >= options.dailyDollarLimit) {
      this.logWarning();
      throw new Error('[VIBESHIELD BUDGET EXCEEDED] External API calls blocked to prevent unexpected cloud bills.');
    }
    this.requests++;
  }

  public trackCost(options: BudgetOptions, tokens: number): void {
    if (!options.enabled || options.estimatedCostPerToken === undefined || options.dailyDollarLimit === undefined) {
      return;
    }
    this.resetIfNeeded();
    this.currentCost += tokens * options.estimatedCostPerToken;
  }
  
  public getCost(): number { 
    return this.currentCost; 
  }
  
  public getRequests(): number { 
    return this.requests; 
  }

  // Exposed strictly for test-suite isolation/reset
  public resetForTest(): void {
    this.requests = 0;
    this.currentCost = 0;
  }
}

export const globalBudgetTracker = new BudgetTracker();
