import "server-only";
import { cookies } from "next/headers";
import { SignJWT, jwtVerify } from "jose";
import { queryOne } from "@/lib/db/mysql";
import { requireEnv } from "@/lib/env";
import { forbidden, unauthorized } from "@/lib/api";
import type { Role, SessionUser } from "@/lib/types";

/**
 * Sessions: a signed (HS256) JWT in an httpOnly cookie. The token only says
 * who you are; on every protected request requireUser() re-reads the user
 * from MySQL, so a deactivated user or a role change takes effect at once.
 *
 * Every API route except /api/auth/* and /api/health starts with
 * requireUser() or requireRole("admin").
 */
const COOKIE = "tl_session";
const MAX_AGE_S = 60 * 60 * 8; // 8 hours

function key(): Uint8Array {
  const secret = requireEnv("AUTH_SECRET");
  if (secret.length < 32) throw new Error("AUTH_SECRET must be at least 32 characters.");
  return new TextEncoder().encode(secret);
}

export async function createSession(user: SessionUser): Promise<void> {
  const token = await new SignJWT({ username: user.username, role: user.role })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(String(user.id))
    .setIssuedAt()
    .setExpirationTime(`${MAX_AGE_S}s`)
    .sign(key());
  (await cookies()).set(COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: MAX_AGE_S,
  });
}

export async function destroySession(): Promise<void> {
  (await cookies()).delete(COOKIE);
}

/** Who the cookie says you are (signature + expiry checked), or null. No DB call. */
export async function getSession(): Promise<SessionUser | null> {
  const token = (await cookies()).get(COOKIE)?.value;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, key(), { algorithms: ["HS256"] });
    const id = Number(payload.sub);
    if (!Number.isInteger(id)) return null;
    return { id, username: String(payload.username), role: payload.role as Role };
  } catch {
    return null;
  }
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
