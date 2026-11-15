import type { NextRequest } from "next/server";
import { z } from "zod";
import { badRequest, notFound, parseBody, route } from "@/lib/api";
import { audit } from "@/lib/auth/audit";
import { requireRole } from "@/lib/auth/session";
import { isMysqlError, withTransaction, type Tx } from "@/lib/db/mysql";
import { listUsers, userPatch } from "@/lib/users";

/**
 * PATCH /api/admin/users/[id] { role?, is_active? }  (admin only) -> { user }
 *
 * - A role change fires trg_user_au, which writes the ROLE_CHANGE audit row.
 * - Activation changes are not covered by that trigger, so this route writes
 *   an UPDATE audit row itself (actor = the admin, target in details).
 * - Guards: an admin cannot demote or deactivate themselves, and the last
 *   active admin cannot be demoted or deactivated, so nobody is locked out.
 *   The target and all active admins are locked in ONE `SELECT ... ORDER BY
 *   user_id FOR UPDATE`, then counted and updated in the same transaction,
 *   so two admins can't demote each other at once (and can't deadlock).
 * - A deactivated user is signed out at their next request: requireUser()
 *   re-reads is_active from MySQL every time.
 */
export const PATCH = route(async (req: NextRequest, ctx: RouteContext<"/api/admin/users/[id]">) => {
  const me = await requireRole("admin");
  const id = z.coerce.number().int().positive().parse((await ctx.params).id);
  const body = await parseBody(req, userPatch);

  if (id === me.id && (body.role === "analyst" || body.is_active === false)) {
    throw badRequest("You can't remove your own admin access. Ask another admin.");
  }

  // One locking read takes the target AND every active admin, in primary-key
  // order. Two admins demoting each other at once then queue on the same rows
  // in the same order instead of deadlocking (InnoDB would roll one back and
  // the loser would see a 500, found in review). The count is taken from the
  // locked rows, so it can't change before our UPDATE commits.
  const change = (tx: Tx) =>
    withLockedAdmins(tx, id).then(async ({ target, activeAdmins }) => {
      const losesAdmin =
        target.role === "admin" && target.is_active === 1 && (body.role === "analyst" || body.is_active === false);
      if (losesAdmin && activeAdmins <= 1) throw badRequest("This is the last active admin. Make someone else admin first.");

      const sets: string[] = [];
      const params: unknown[] = [];
      if (body.role !== undefined) {
        sets.push("role = ?");
        params.push(body.role);
      }
      if (body.is_active !== undefined) {
        sets.push("is_active = ?");
        params.push(body.is_active);
      }
      await tx.execute(`UPDATE app_user SET ${sets.join(", ")} WHERE user_id = ?`, [...params, id]);
      return target;
    });

  // Belt and braces: if InnoDB still reports a deadlock or lock timeout, retry once.
  let before;
  try {
    before = await withTransaction(change);
  } catch (err) {
    if (!(isMysqlError(err) && (err.errno === 1213 || err.errno === 1205))) throw err;
    before = await withTransaction(change);
  }

  if (body.is_active !== undefined && Boolean(before.is_active) !== body.is_active) {
    await audit("UPDATE", "app_user", String(id), me.id, {
      username: before.username,
      change: body.is_active ? "activated" : "deactivated",
      by: me.username,
    });
  }

  const user = (await listUsers()).find((u) => u.user_id === id);
  return Response.json({ user });
});

type Locked = { user_id: number; username: string; role: string; is_active: number };

async function withLockedAdmins(tx: Tx, id: number): Promise<{ target: Locked; activeAdmins: number }> {
  const rows = await tx.query<Locked>(
    `SELECT user_id, username, role, is_active FROM app_user
     WHERE user_id = ? OR (role = 'admin' AND is_active = TRUE)
     ORDER BY user_id
     FOR UPDATE`,
    [id],
  );
  const target = rows.find((r) => r.user_id === id);
  if (!target) throw notFound("No such user.");
  return { target, activeAdmins: rows.filter((r) => r.role === "admin" && r.is_active === 1).length };
}
