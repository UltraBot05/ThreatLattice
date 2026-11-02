import { NextResponse } from "next/server";
import { connection } from "next/server";
import { queryOne } from "@/lib/db/mysql";
import { neo4jHealthy } from "@/lib/db/neo4j";

/**
 * GET /api/health: public, no auth. Says whether both databases answer and
 * when the CVE data was last refreshed (shown in the sidebar footer).
 * Reveals no secrets and no user data.
 */
export async function GET() {
  await connection(); // always run at request time, never prerender
  let mysql = false;
  let dataAsOf: string | null = null;
  try {
    const row = await queryOne<{ as_of: string | null }>("SELECT MAX(last_modified_date) AS as_of FROM cve");
    mysql = true;
    dataAsOf = row?.as_of ?? null;
  } catch (err) {
    console.error("[health] mysql:", (err as Error).message);
    mysql = false;
  }
  const neo4j = await neo4jHealthy();
  return NextResponse.json(
    { mysql, neo4j, dataAsOf },
    { status: mysql && neo4j ? 200 : 503, headers: { "Cache-Control": "no-store" } },
  );
}
