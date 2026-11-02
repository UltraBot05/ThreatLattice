import "server-only";
import { cookies } from "next/headers";
import { forbidden, unauthorized } from "@/lib/api";
import { queryOne } from "@/lib/db/mysql";
import type { Role, SessionUser } from "@/lib/types";
import { readSessionToken, SESSION_COOKIE, SESSION_MAX_AGE_S, signSessionToken } from "./token";

/**
 * Sessions: a signed (HS256) JWT in an httpOnly cookie. The token only says
 * who you are; on every protected request requireUser() re-reads the user
 * from MySQL, so a deactivated user or a role change takes effect at once.
 *
 * Every API route except /api/auth/* and /api/health starts with
 * requireUser() or requireRole("admin").
 */

export async function createSession(user: SessionUser): Promise<void> {
  (await cookies()).set(SESSION_COOKIE, await signSessionToken(user), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_MAX_AGE_S,
  });
}

export async function destroySession(): Promise<void> {
  (await cookies()).delete(SESSION_COOKIE);
}

/** Who the cookie says you are (signature + expiry checked), or null. No DB call. */
export async function getSession(): Promise<SessionUser | null> {
  return readSessionToken((await cookies()).get(SESSION_COOKIE)?.value);
}

/** The signed-in, still-active user from the database, or a 401. */
export async function requireUser(): Promise<SessionUser> {
  const s = await getSession();
  if (!s) throw unauthorized();
  const row = await queryOne<{ user_id: number; username: string; role: Role; is_active: number }>(
    "SELECT user_id, username, role, is_active FROM app_user WHERE user_id = ?",
    [s.id],
  );
  if (!row || !row.is_active) throw unauthorized("Your session is no longer valid. Sign in again.");
  return { id: row.user_id, username: row.username, role: row.role };
}

/** Same as requireUser, plus a 403 unless the user has the role. */
export async function requireRole(role: Role): Promise<SessionUser> {
  const user = await requireUser();
  if (user.role !== role) throw forbidden();
  return user;
}
