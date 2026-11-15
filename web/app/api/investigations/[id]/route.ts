import type { NextRequest } from "next/server";
import { parseBody, route } from "@/lib/api";
import { requireUser } from "@/lib/auth/session";
import { execute } from "@/lib/db/mysql";
import { getOwned, idParam, updateSchema } from "@/lib/investigations";

/**
 * GET    /api/investigations/[id]                     -> { investigation }
 * PATCH  /api/investigations/[id] { title?, notes? }  -> { investigation }   (UPDATE: trg_inv_au logs before/after)
 * DELETE /api/investigations/[id]                     -> { ok: true }        (DELETE: trg_inv_ad logs it)
 * Owner or admin only; anyone else gets 404.
 */
type Ctx = RouteContext<"/api/investigations/[id]">;

export const GET = route(async (_req: NextRequest, ctx: Ctx) => {
  const user = await requireUser();
  const inv = await getOwned(user, idParam.parse((await ctx.params).id));
  return Response.json({ investigation: inv }, { headers: { "Cache-Control": "private, no-store" } });
});

export const PATCH = route(async (req: NextRequest, ctx: Ctx) => {
  const user = await requireUser();
  const inv = await getOwned(user, idParam.parse((await ctx.params).id));
  const body = await parseBody(req, updateSchema);
  const sets: string[] = [];
  const params: unknown[] = [];
  if (body.title !== undefined) {
    sets.push("title = ?");
    params.push(body.title);
  }
  if (body.notes !== undefined) {
    sets.push("notes = ?");
    params.push(body.notes === "" ? null : body.notes);
  }
  await execute(`UPDATE investigation SET ${sets.join(", ")} WHERE investigation_id = ?`, [...params, inv.investigation_id]);
  return Response.json({ investigation: await getOwned(user, inv.investigation_id) });
});

export const DELETE = route(async (_req: NextRequest, ctx: Ctx) => {
  const user = await requireUser();
  const inv = await getOwned(user, idParam.parse((await ctx.params).id));
  await execute("DELETE FROM investigation WHERE investigation_id = ?", [inv.investigation_id]);
  return Response.json({ ok: true });
});
