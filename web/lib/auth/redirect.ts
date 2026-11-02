/**
 * Where to send the user after signing in. Only same-site paths are allowed,
 * so a crafted link like /login?next=//evil.com or /login?next=/\evil.com
 * (browsers treat "\" as "/") can never bounce a fresh session to another site.
 */
export function safeNext(next: string | null | undefined, fallback = "/dashboard"): string {
  if (!next || !next.startsWith("/") || next.startsWith("//")) return fallback;
  // reject backslashes and control characters outright
  if (/[\\\u0000-\u001f\u007f]/.test(next)) return fallback;
  // and confirm the resolved URL stays on our origin
  const base = "http://threatlattice.local";
  try {
    const url = new URL(next, base);
    if (url.origin !== base) return fallback;
    const out = url.pathname + url.search + url.hash;
    // normalising can turn "/..//evil.com" into "//evil.com": check again
    return out.startsWith("/") && !out.startsWith("//") ? out : fallback;
  } catch {
    return fallback;
  }
}
