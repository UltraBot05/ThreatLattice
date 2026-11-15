import "server-only";
import { z } from "zod";
import { query } from "@/lib/db/mysql";
import type { Role } from "@/lib/types";

/** Admin user management (B6). Passwords and hashes never leave the server. */
export interface AdminUser {
  user_id: number;
  username: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string; // ISO UTC
  last_login_at: string | null;
  investigations: number;
}

export const userPatch = z
  .object({
    role: z.enum(["analyst", "admin"]).optional(),
    is_active: z.boolean().optional(),
  })
  .refine((v) => v.role !== undefined || v.is_active !== undefined, { message: "Nothing to update." });

type Row = Omit<AdminUser, "is_active" | "created_at" | "last_login_at"> & {
  is_active: number;
  created_s: number;
  login_s: number | null;
};

const iso = (s: number) => new Date(Number(s) * 1000).toISOString();

export async function listUsers(): Promise<AdminUser[]> {
  // Correlated subquery: each user's investigation count (a report talking point next to the JOIN version).
  const rows = await query<Row>(
    `SELECT u.user_id, u.username, u.email, u.role, u.is_active,
            UNIX_TIMESTAMP(u.created_at) AS created_s, UNIX_TIMESTAMP(u.last_login_at) AS login_s,
            (SELECT COUNT(*) FROM investigation i WHERE i.user_id = u.user_id) AS investigations
     FROM app_user u
     ORDER BY u.is_active DESC, u.role = 'admin' DESC, u.username`,
  );
  return rows.map(({ created_s, login_s, is_active, ...r }) => ({
    ...r,
    is_active: is_active === 1,
    investigations: Number(r.investigations),
    created_at: iso(created_s),
    last_login_at: login_s ? iso(login_s) : null,
  }));
}
