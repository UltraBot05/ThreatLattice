import type { NextRequest } from "next/server";
import { badRequest, parseBody, route } from "@/lib/api";
import { audit } from "@/lib/auth/audit";
import { hashPassword } from "@/lib/auth/password";
import { registerSchema } from "@/lib/auth/schemas";
import { createSession } from "@/lib/auth/session";
import { execute, isMysqlError } from "@/lib/db/mysql";

/**
 * POST /api/auth/register  { username, email, password }
 * Creates an ANALYST account (admins are only made by an admin or the seed
 * script) and signs it in. The database still enforces UNIQUE(username),
 * UNIQUE(email) and the email CHECK even if this validation is bypassed.
 */
export const POST = route(async (req: NextRequest) => {
  const body = await parseBody(req, registerSchema);
  const hash = await hashPassword(body.password);
  let userId: number;
  try {
    const res = await execute(
      "INSERT INTO app_user (username, email, password_hash, role) VALUES (?, ?, ?, 'analyst')",
      [body.username, body.email.toLowerCase(), hash],
    );
    userId = res.insertId;
  } catch (err) {
    if (isMysqlError(err) && err.errno === 1062) {
      throw badRequest(
        err.sqlMessage?.includes("email") ? "That email is already registered." : "That username is taken.",
      );
    }
    throw err;
  }
  await audit("INSERT", "app_user", String(userId), userId, { username: body.username, via: "register" });
  const user = { id: userId, username: body.username, role: "analyst" as const };
  await createSession(user);
  return Response.json({ user }, { status: 201 });
});
