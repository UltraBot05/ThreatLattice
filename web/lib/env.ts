import "server-only";
import fs from "node:fs";
import path from "node:path";

/**
 * The whole repo shares ONE settings file: <repo>/.env (docker compose and the
 * Python ETL read it too). Next.js only loads env files from web/, and its
 * env loader caches its first result, so we read the root .env ourselves the
 * first time a server module needs a setting. Variables already set in the
 * real environment always win.
 */
let loaded = false;

function stripInlineComment(value: string): string {
  const v = value.trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1);
  const hash = v.search(/\s#/);
  return (hash === -1 ? v : v.slice(0, hash)).trim();
}

export function ensureRootEnv(): void {
  if (loaded) return;
  loaded = true;
  for (const dir of [path.resolve(process.cwd(), ".."), process.cwd()]) {
    const file = path.join(dir, ".env");
    if (!fs.existsSync(file)) continue;
    for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const eq = line.indexOf("=");
      if (eq <= 0) continue;
      const key = line.slice(0, eq).trim();
      if (process.env[key] === undefined) process.env[key] = stripInlineComment(line.slice(eq + 1));
    }
    return;
  }
}

/** Read a setting, falling back to a default (only for non-secret values like host/port). */
export function env(name: string, fallback: string): string {
  ensureRootEnv();
  return process.env[name] || fallback;
}

/** Read a required setting or fail loudly (never fall back to a hard-coded secret). */
export function requireEnv(name: string): string {
  ensureRootEnv();
  const v = process.env[name];
  if (!v) throw new Error(`Missing environment variable ${name}. Copy .env.example to .env at the repo root.`);
  return v;
}
