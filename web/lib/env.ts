import "server-only";

/** Read a required environment variable or fail loudly (never fall back to a hard-coded secret). */
export function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing environment variable ${name}. Copy .env.example to .env at the repo root.`);
  return v;
}
