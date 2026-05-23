import time

def start_audit_timer() -> float:
    """Returns the precise high-resolution start time."""
    return time.perf_counter()

def end_audit_timer(start_time: float) -> float:
    """Returns the duration in milliseconds."""
    end_time = time.perf_counter()
    return (end_time - start_time) * 1000.0

def log_audit(method: str, path: str, status: int, duration_ms: float) -> None:
    """Logs standard audit requests."""
    print(f"[VIBESHIELD AUDIT] {method} {path} - Status: {status} - Duration: {duration_ms:.3f}ms")

def log_performance_warning(method: str, path: str, duration_ms: float, threshold: float) -> None:
    """Logs a prominent warning when the performance threshold is breached."""
    print(
        f"\n⚠️ [VIBESHIELD PERFORMANCE WARNING] ⚠️\n"
        f"Route: {method} {path}\n"
        f"Execution Time: {duration_ms:.3f}ms (exceeds threshold of {threshold}ms)\n"
        f"Action Recommended: Optimize database queries or enable VibeShield caching.\n"
    )
