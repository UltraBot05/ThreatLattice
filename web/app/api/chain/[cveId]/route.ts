import type { NextRequest } from "next/server";
import { z } from "zod";
import { ids, notFound, parseQuery, route } from "@/lib/api";
import { requireUser } from "@/lib/auth/session";
import { queryOne } from "@/lib/db/mysql";
import { getChain } from "@/lib/graph";

/**
 * GET /api/chain/[cveId]?depth=0|1|2 (default 2)
 * -> ChainGraph { nodes, edges, paths, meta }   (lib/graph.ts)
 *
 * 404 if the CVE is not in MySQL. A CVE that exists but has no CWE is not
 * in the graph: it returns just the CVE node and empty paths, so the page
 * can say "no weakness mapped yet" instead of "not found".
 */
const schema = z.object({ depth: z.coerce.number().int().min(0).max(2).default(2) });

export const GET = route(async (req: NextRequest, ctx: RouteContext<"/api/chain/[cveId]">) => {
  await requireUser();
  const id = ids.cve.parse((await ctx.params).cveId.trim().toUpperCase());
  const { depth } = parseQuery(req, schema);

  const chain = await getChain(id, depth);
  if (chain) return Response.json(chain, { headers: { "Cache-Control": "private, no-store" } });

  const row = await queryOne<{ cve_id: string; cvss_severity: string | null; cvss_base_score: number | null }>(
    "SELECT cve_id, cvss_severity, cvss_base_score FROM cve WHERE cve_id = ?",
    [id],
  );
  if (!row) throw notFound(`${id} is not in the database.`);
  return Response.json(
    {
      nodes: [{ id, type: "CVE", label: id, props: { severity: row.cvss_severity, score: row.cvss_base_score } }],
      edges: [],
      paths: [],
      meta: { cve: id, depth, truncated: false, counts: { cwe: 0, capec: 0, technique: 0 }, tactics: [] },
    },
    { headers: { "Cache-Control": "private, no-store" } },
  );
});
