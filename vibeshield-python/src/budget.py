import threading
from datetime import datetime, timezone
import logging

logger = logging.getLogger('VibeShield')

class GlobalBudgetTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self.requests = 0
        self.current_cost = 0.0
        self.current_day = datetime.now(timezone.utc).day

    def _reset_if_needed(self):
        today = datetime.now(timezone.utc).day
        if self.current_day != today:
            self.requests = 0
            self.current_cost = 0.0
            self.current_day = today

    def _log_warning(self):
        logger.warning('\n⚠️ [VIBESHIELD BUDGET EXCEEDED] ⚠️\nExternal API calls blocked to prevent unexpected cloud bills.\n')
        print('\n⚠️ [VIBESHIELD BUDGET EXCEEDED] ⚠️\nExternal API calls blocked to prevent unexpected cloud bills.\n')

    def track_request(self, options: dict) -> None:
        if not options.get('enabled', False):
            return

        with self._lock:
            self._reset_if_needed()
            
            max_daily_requests = options.get('maxDailyRequests')
            if max_daily_requests is not None and self.requests >= max_daily_requests:
                self._log_warning()
                raise Exception('[VIBESHIELD BUDGET EXCEEDED] External API calls blocked to prevent unexpected cloud bills.')
            
            daily_dollar_limit = options.get('dailyDollarLimit')
            if daily_dollar_limit is not None and self.current_cost >= daily_dollar_limit:
                self._log_warning()
                raise Exception('[VIBESHIELD BUDGET EXCEEDED] External API calls blocked to prevent unexpected cloud bills.')
                
            self.requests += 1

    def track_cost(self, options: dict, tokens: int) -> None:
        if not options.get('enabled', False):
            return
            
        estimated_cost = options.get('estimatedCostPerToken')
        daily_dollar_limit = options.get('dailyDollarLimit')
        
        if estimated_cost is None or daily_dollar_limit is None:
            return

        with self._lock:
            self._reset_if_needed()
            self.current_cost += (tokens * estimated_cost)

    def get_cost(self) -> float:
        with self._lock:
            return self.current_cost

    def get_requests(self) -> int:
        with self._lock:
            return self.requests

    def reset_for_test(self) -> None:
        with self._lock:
            self.requests = 0
            self.current_cost = 0.0

global_budget_tracker = GlobalBudgetTracker()
