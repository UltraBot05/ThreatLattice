import "server-only";

/**
 * Simple in-memory limiter for sign-in attempts: at most MAX failures per
 * (IP, username) in WINDOW_MS. Good enough for one dev/demo server; a real
 * deployment would keep this in a shared store.
 */
const MAX = 5;
const WINDOW_MS = 15 * 60 * 1000;
const failures = new Map<string, number[]>();

function recent(key: string, now: number): number[] {
  const list = (failures.get(key) ?? []).filter((t) => now - t < WINDOW_MS);
  failures.set(key, list);
  return list;
}

/** Minutes until the key may try again, or 0 if it may try now. */
export function lockedFor(key: string): number {
  const now = Date.now();
  const list = recent(key, now);
  if (list.length < MAX) return 0;
  return Math.ceil((WINDOW_MS - (now - list[0])) / 60000);
}

export function recordFailure(key: string): void {
  recent(key, Date.now()).push(Date.now());
}

export function clearFailures(key: string): void {
  failures.delete(key);
}
