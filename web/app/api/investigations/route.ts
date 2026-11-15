import type { NextRequest } from "next/server";
import { z } from "zod";
import { parseBody, parseQuery, route } from "@/lib/api";
import { requireUser } from "@/lib/auth/session";
import { withConnection } from "@/lib/db/mysql";
import { createSchema, getOwned, listInvestigations } from "@/lib/investigations";

/**
 * GET  /api/investigations?scope=mine|all  -> { items }   (all = admin only; analysts always get their own)
 * POST /api/investigations { title, start_node_type, start_node_id, notes? } -> 201 { investigation }
 *
 * POST calls sp_create_investigation on one connection, then reads its OUT
 * parameter. Not inside withTransaction: the procedure runs its own
 * START TRANSACTION, which would silently commit ours (HANDOFF 9.1). Its
 * SIGNAL messages ("start node CVE-2099-1 does not exist") come back as 400s.
 */
const listSchema = z.object({ scope: z.enum(["mine", "all"]).default("mine") });

export const GET = route(async (req: NextRequest) => {
  const user = await requireUser();
  const { scope } = parseQuery(req, listSchema);
  const items = await listInvestigations(user, scope === "all");
  return Response.json({ items }, { headers: { "Cache-Control": "private, no-store" } });
});

export const POST = route(async (req: NextRequest) => {
  const user = await requireUser();
  const body = await parseBody(req, createSchema);
  const id = await withConnection(async (c) => {
    await c.query("CALL sp_create_investigation(?, ?, ?, ?, ?, @tl_new_inv)", [
      user.id,
      body.title,
      body.start_node_type,
      body.start_node_id,
      body.notes ?? null,
    ]);
    const [row] = await c.query<{ id: number }>("SELECT @tl_new_inv AS id");
    return Number(row.id);
  });
  return Response.json({ investigation: await getOwned(user, id) }, { status: 201 });
});
