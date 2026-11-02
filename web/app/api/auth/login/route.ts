import type { NextRequest } from "next/server";
import { parseBody, route, tooManyRequests, unauthorized } from "@/lib/api";
import { audit } from "@/lib/auth/audit";
import { verifyPassword } from "@/lib/auth/password";
import { clearFailures, lockedFor, recordFailure } from "@/lib/auth/rateLimit";
import { loginSchema } from "@/lib/auth/schemas";
import { createSession } from "@/lib/auth/session";
import { execute, queryOne } from "@/lib/db/mysql";
import type { Role } from "@/lib/types";

/**
 * POST /api/auth/login  { login: username or email, password }
 *
 * - One generic error for unknown user, wrong password and deactivated user,
 *   so the response never reveals which usernames exist.
 * - An unknown user still costs one bcrypt compare (same timing).
 * - 5 failures per IP + login in 15 minutes locks that pair temporarily.
 * - Writes LOGIN / LOGIN_FAIL rows to audit_log and sets last_login_at.
 */
// bcrypt hash of a random throwaway string: makes unknown-user logins take as long as real ones.
const DUMMY_HASH = "$2b$12$wxcqRS5LcVC3muuYsBRl.e2HRPMsd0rVI0JvuGgGPhEj58k6nF.fC";
const GENERIC = "Wrong username or password.";

export const POST = route(async (req: NextRequest) => {
  const body = await parseBody(req, loginSchema);
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "local";
  const key = `${ip}|${body.login.toLowerCase()}`;

  const wait = lockedFor(key);
  if (wait > 0) throw tooManyRequests(`Too many failed attempts. Try again in ${wait} minute${wait === 1 ? "" : "s"}.`);

  const row = await queryOne<{ user_id: number; username: string; role: Role; is_active: number; password_hash: string }>(
    "SELECT user_id, username, role, is_active, password_hash FROM app_user WHERE username = ? OR email = ? LIMIT 1",
    [body.login, body.login.toLowerCase()],
  );
  const ok = await verifyPassword(body.password, row?.password_hash ?? DUMMY_HASH);

  if (!row || !ok || !row.is_active) {
    recordFailure(key);
    await audit("LOGIN_FAIL", "app_user", row ? String(row.user_id) : body.login, row?.user_id ?? null, {
      reason: !row ? "unknown user" : !ok ? "wrong password" : "deactivated",
    });
    throw unauthorized(GENERIC);
  }

  clearFailures(key);
  await execute("UPDATE app_user SET last_login_at = CURRENT_TIMESTAMP WHERE user_id = ?", [row.user_id]);
  await audit("LOGIN", "app_user", String(row.user_id), row.user_id, {});
  const user = { id: row.user_id, username: row.username, role: row.role };
  await createSession(user);
  return Response.json({ user });
});
