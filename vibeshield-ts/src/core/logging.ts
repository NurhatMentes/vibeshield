export function startAuditTimer(): bigint {
  return process.hrtime.bigint();
}

export function endAuditTimer(startTime: bigint): number {
  const endTime = process.hrtime.bigint();
  const durationNanos = endTime - startTime;
  // Convert nanoseconds to milliseconds
  return Number(durationNanos) / 1_000_000;
}

export function logAudit(method: string, path: string, status: number, durationMs: number): void {
  console.log(`[VIBESHIELD AUDIT] ${method} ${path} - Status: ${status} - Duration: ${durationMs.toFixed(3)}ms`);
}

export function logPerformanceWarning(method: string, path: string, durationMs: number, threshold: number): void {
  console.warn(
    `\n⚠️ [VIBESHIELD PERFORMANCE WARNING] ⚠️\n` +
    `Route: ${method} ${path}\n` +
    `Execution Time: ${durationMs.toFixed(3)}ms (exceeds threshold of ${threshold}ms)\n` +
    `Action Recommended: Optimize database queries or enable VibeShield caching.\n`
  );
}
