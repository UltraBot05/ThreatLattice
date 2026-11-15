import type { NextRequest } from "next/server";
import { z } from "zod";
import { badRequest, notFound, parseBody, route } from "@/lib/api";
import { audit } from "@/lib/auth/audit";
import { requireRole } from "@/lib/auth/session";
import { withTransaction } from "@/lib/db/mysql";
import { listUsers, userPatch } from "@/lib/users";

/**
 * PATCH /api/admin/users/[id] { role?, is_active? }  (admin only) -> { user }
 *
 * - A role change fires trg_user_au, which writes the ROLE_CHANGE audit row.
 * - Activation changes are not covered by that trigger, so this route writes
 *   an UPDATE audit row itself (actor = the admin, target in details).
 * - Guards: an admin cannot demote or deactivate themselves, and the last
 *   active admin cannot be demoted or deactivated, so nobody is locked out.
 *   The count and the update run in one transaction with the admin rows
 *   locked (FOR UPDATE), so two admins can't demote each other at once.
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

  const before = await withTransaction(async (tx) => {
    const [target] = await tx.query<{ user_id: number; username: string; role: string; is_active: number }>(
      "SELECT user_id, username, role, is_active FROM app_user WHERE user_id = ? FOR UPDATE",
      [id],
    );
    if (!target) throw notFound("No such user.");

    const losesAdmin = target.role === "admin" && target.is_active === 1 && (body.role === "analyst" || body.is_active === false);
    if (losesAdmin) {
      const [{ n }] = await tx.query<{ n: number }>(
        "SELECT COUNT(*) AS n FROM app_user WHERE role = 'admin' AND is_active = TRUE FOR UPDATE",
      );
      if (Number(n) <= 1) throw badRequest("This is the last active admin. Make someone else admin first.");
    }

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
