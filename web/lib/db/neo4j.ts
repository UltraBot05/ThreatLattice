import "server-only";
import neo4j, { type Driver } from "neo4j-driver";
import { requireEnv } from "@/lib/env";

/**
 * Neo4j access for route handlers. Always pass values as $params in Cypher.
 * Integers come back as plain JS numbers (disableLosslessIntegers), which is
 * safe for our counts and ids.
 */
const globalForDriver = globalThis as unknown as { __tlNeo4j?: Driver };

function driver(): Driver {
  if (!globalForDriver.__tlNeo4j) {
    globalForDriver.__tlNeo4j = neo4j.driver(
      process.env.NEO4J_URI ?? "bolt://127.0.0.1:7687",
      neo4j.auth.basic(process.env.NEO4J_USER ?? "neo4j", requireEnv("NEO4J_PASSWORD")),
      { disableLosslessIntegers: true, maxConnectionPoolSize: 20 },
    );
  }
  return globalForDriver.__tlNeo4j;
}

export async function runCypher<T = Record<string, unknown>>(
  cypher: string,
  params: Record<string, unknown> = {},
  mode: "READ" | "WRITE" = "READ",
): Promise<T[]> {
  const session = driver().session({
    defaultAccessMode: mode === "READ" ? neo4j.session.READ : neo4j.session.WRITE,
  });
  try {
    const res = await session.run(cypher, params);
    return res.records.map((r) => r.toObject() as T);
  } finally {
    await session.close();
  }
}

export async function neo4jHealthy(): Promise<boolean> {
  try {
    await driver().verifyConnectivity();
    return true;
  } catch {
    return false;
  }
}
