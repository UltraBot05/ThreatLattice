import "server-only";
import { SignJWT, jwtVerify } from "jose";
import { requireEnv } from "@/lib/env";
import type { Role, SessionUser } from "@/lib/types";

/**
 * Session token: an HS256-signed JWT { sub: user_id, username, role } with an
 * 8-hour expiry. No database access here, so proxy.ts can use it too.
 */
export const SESSION_COOKIE = "tl_session";
export const SESSION_MAX_AGE_S = 60 * 60 * 8;

function key(): Uint8Array {
  const secret = requireEnv("AUTH_SECRET");
  if (secret.length < 32) throw new Error("AUTH_SECRET must be at least 32 characters.");
  return new TextEncoder().encode(secret);
}

export function signSessionToken(user: SessionUser): Promise<string> {
  return new SignJWT({ username: user.username, role: user.role })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(String(user.id))
    .setIssuedAt()
    .setExpirationTime(`${SESSION_MAX_AGE_S}s`)
    .sign(key());
}

/** The user in a token, or null if it is missing, forged or expired. */
export async function readSessionToken(token: string | undefined): Promise<SessionUser | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, key(), { algorithms: ["HS256"] });
    const id = Number(payload.sub);
    const role = payload.role;
    if (!Number.isInteger(id) || (role !== "analyst" && role !== "admin")) return null;
    return { id, username: String(payload.username), role: role as Role };
  } catch {
    return null;
  }
}
