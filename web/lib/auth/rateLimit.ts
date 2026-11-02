import "server-only";

/**
 * Sign-in throttle: at most MAX failed attempts per ACCOUNT (the typed
 * username/email, lower-cased) in WINDOW_MS.
 *
 * Keyed on the account only, not on the client IP: the app has no trusted
 * proxy in front of it, so X-Forwarded-For is whatever the client sends and
 * would let an attacker reset the counter at will. The trade-off is that
 * someone can lock an account for 15 minutes by failing on purpose; for this
 * project that is the safer side. In memory, so it resets when the server
 * restarts (a real deployment would use a shared store).
 */
const MAX = 5;
const WINDOW_MS = 15 * 60 * 1000;
const failures = new Map<string, number[]>();

function recent(key: string, now: number): number[] {
  const list = (failures.get(key) ?? []).filter((t) => now - t < WINDOW_MS);
  if (list.length) failures.set(key, list);
  else failures.delete(key);
  return list;
}

/** Drop idle keys now and then so the map cannot grow without bound. */
function prune(now: number): void {
  if (failures.size < 1000) return;
  for (const [key, list] of failures) {
    if (!list.some((t) => now - t < WINDOW_MS)) failures.delete(key);
  }
}

/** Minutes until this account may try again, or 0 if it may try now. */
export function lockedFor(account: string): number {
  const now = Date.now();
  const list = recent(account, now);
  if (list.length < MAX) return 0;
  return Math.ceil((WINDOW_MS - (now - list[0])) / 60000);
}

export function recordFailure(account: string): void {
  const now = Date.now();
  prune(now);
  const list = recent(account, now);
  list.push(now);
  failures.set(account, list);
}

export function clearFailures(account: string): void {
  failures.delete(account);
}
