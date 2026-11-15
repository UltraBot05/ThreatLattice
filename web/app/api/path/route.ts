import type { NextRequest } from "next/server";
import { z } from "zod";
import { notFound, parseQuery, route } from "@/lib/api";
import { requireUser } from "@/lib/auth/session";
import { getShortestPath, typeOfId } from "@/lib/graph";

/**
 * GET /api/path?from=CWE-416&to=T1574.010
 * -> { nodes, edges, hops }: Neo4j shortestPath over our five relationship
 * types, up to 8 hops, direction ignored.
 */
const id = z
  .string()
  .trim()
  .transform((s) => s.toUpperCase())
  .refine((s) => typeOfId(s) !== null, "expected a CVE, CWE, CAPEC or ATT&CK technique id");

const schema = z.object({ from: id, to: id });

export const GET = route(async (req: NextRequest) => {
  await requireUser();
  const { from, to } = parseQuery(req, schema);
  const path = await getShortestPath(from, to);
  if (!path) throw notFound(`No connection between ${from} and ${to} within 8 hops.`);
  return Response.json(path, { headers: { "Cache-Control": "private, no-store" } });
});
