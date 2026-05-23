import urllib.request
import urllib.error
import json
import asyncio
from typing import Tuple, Dict, Any, Optional

from .budget import global_budget_tracker

async def vibe_fetch(url: str, options: dict = None, **kwargs) -> Tuple[int, Dict[str, str], bytes]:
    """
    A dependency-free asynchronous wrapper around urllib.request.
    
    If 'budget' is configured in options, acts as a strict financial circuit breaker.
    """
    budget_opts = options.get("budget", {}) if options else {}

    # 1. Pre-Request Circuit Breaker Check
    if budget_opts.get("enabled"):
        global_budget_tracker.track_request(budget_opts)
        
    req = urllib.request.Request(url, **kwargs)
    
    def _do_req() -> Tuple[int, Dict[str, str], bytes]:
        try:
            with urllib.request.urlopen(req) as response:
                status = response.status
                headers = dict(response.getheaders())
                body = response.read()
                return status, headers, body
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()
        except urllib.error.URLError as e:
            raise Exception(f"Request failed: {e.reason}")

    # Execute standard synchronous urllib in a non-blocking thread pool
    status, headers, body = await asyncio.to_thread(_do_req)

    # 3. Post-Request Cost Tracking (Token Counting)
    if budget_opts.get("enabled") and budget_opts.get("estimatedCostPerToken") is not None:
        try:
            # Safely attempt to parse standard LLM token usage markers
            data = json.loads(body.decode("utf-8"))
            usage = data.get("usage", {})
            total_tokens = usage.get("total_tokens")
            if isinstance(total_tokens, int):
                global_budget_tracker.track_cost(budget_opts, total_tokens)
        except Exception:
            pass # Ignore parsing errors for non-JSON or unsupported endpoints
            
    return status, headers, body
