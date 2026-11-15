import "server-only";
import { runCypher } from "@/lib/db/neo4j";

/**
 * Attack-chain graph for the explorer (B4). Shapes are shared with the page.
 *
 *   (CVE)-[:INSTANCE_OF]->(CWE)-[:CHILD_OF*0..depth]->(CWE)<-[:EXPLOITS]-(CAPEC)-[:ENABLES]->(Technique)
 *
 * Why CHILD_OF*0..depth: CVEs are tagged with specific weaknesses, CAPEC
 * patterns are written against their parents. depth 0 = direct matches
 * only, 2 = up to two parent levels (89% of CVEs reach a technique, vs 36%
 * at depth 0; HANDOFF 9.8). Bounded so the expansion stays small.
 */
export type NodeType = "CVE" | "CWE" | "CAPEC" | "Technique";
export type EdgeType = "INSTANCE_OF" | "CHILD_OF" | "EXPLOITS" | "ENABLES" | "SUBTECHNIQUE_OF";

export interface GraphNode {
  id: string;
  type: NodeType;
  label: string;
  props: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: EdgeType;
}

export interface ChainGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** Each complete CVE -> ... -> Technique path as a list of node ids (for highlighting). */
  paths: string[][];
  meta: {
    cve: string;
    depth: number;
    truncated: boolean;
    counts: { cwe: number; capec: number; technique: number };
    tactics: { tactic: string; techniques: number }[];
  };
}

export const MAX_PATHS = 400;

type Raw = Record<string, unknown> & { id: string; kind: NodeType };

function label(n: Raw): string {
  if (n.kind === "CWE") return String(n.common_name ?? n.name ?? n.id);
  if (n.kind === "CVE") return n.id;
  return String(n.name ?? n.id);
}

function toNode(n: Raw): GraphNode {
  const { id, kind, run: _run, ...rest } = n;
  void _run;
  const props: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(rest)) {
    // Neo4j temporal values (CVE.published) arrive as objects: send "2026-10-21".
    props[k] = v !== null && typeof v === "object" && !Array.isArray(v) ? String(v) : v;
  }
  return { id, type: kind, label: label(n), props };
}

/** Infer the relationship between two neighbours on a chain path. */
function edgeBetween(a: Raw, b: Raw): GraphEdge {
  if (a.kind === "CVE") return { source: a.id, target: b.id, type: "INSTANCE_OF" };
  if (a.kind === "CWE" && b.kind === "CWE") return { source: a.id, target: b.id, type: "CHILD_OF" };
  if (a.kind === "CWE" && b.kind === "CAPEC") return { source: b.id, target: a.id, type: "EXPLOITS" };
  return { source: a.id, target: b.id, type: "ENABLES" }; // CAPEC -> Technique
}

const CHAIN = `
MATCH (v:CVE {id: $id})
OPTIONAL MATCH (v)-[:INSTANCE_OF]->(w:CWE)
WITH v, collect(DISTINCT w) AS cwes
OPTIONAL MATCH p = (v)-[:INSTANCE_OF]->(:CWE)-[:CHILD_OF*0..$depth]->(:CWE)<-[:EXPLOITS]-(:CAPEC)-[:ENABLES]->(:Technique)
WITH v, cwes, p ORDER BY length(p)
WITH v, cwes, collect(p)[0..$max] AS ps, count(p) AS total
RETURN v { .*, kind: 'CVE' } AS cve,
       [w IN cwes | w { .*, kind: 'CWE' }] AS cwes,
       [p IN ps | [n IN nodes(p) | n { .*, kind: labels(n)[0] }]] AS paths,
       total`;

/** The chain for one CVE, or null if the CVE is not in the graph. */
export async function getChain(cveId: string, depth: number): Promise<ChainGraph | null> {
  // Cypher cannot take a parameter inside a variable-length bound, so depth
  // (already validated as 0, 1 or 2) is written into the query text.
  const cypher = CHAIN.replace("$depth", String(depth));
  const rows = await runCypher<{ cve: Raw | null; cwes: Raw[]; paths: Raw[][]; total: number }>(cypher, {
    id: cveId,
    max: MAX_PATHS,
  });
  const row = rows[0];
  if (!row?.cve) return null;

  const nodes = new Map<string, GraphNode>([[row.cve.id, toNode(row.cve)]]);
  const edges = new Map<string, GraphEdge>();
  const addEdge = (e: GraphEdge) => edges.set(`${e.source}|${e.type}|${e.target}`, e);

  for (const w of row.cwes) {
    nodes.set(w.id, toNode(w));
    addEdge({ source: row.cve.id, target: w.id, type: "INSTANCE_OF" });
  }
  const paths: string[][] = [];
  for (const p of row.paths) {
    p.forEach((n) => nodes.has(n.id) || nodes.set(n.id, toNode(n)));
    for (let i = 0; i < p.length - 1; i++) addEdge(edgeBetween(p[i], p[i + 1]));
    paths.push(p.map((n) => n.id));
  }

  const all = [...nodes.values()];
  const techniques = all.filter((n) => n.type === "Technique");
  const tacticCount = new Map<string, number>();
  for (const t of techniques) {
    for (const tac of (t.props.tactics as string[] | undefined) ?? []) {
      tacticCount.set(tac, (tacticCount.get(tac) ?? 0) + 1);
    }
  }

  return {
    nodes: all,
    edges: [...edges.values()],
    paths,
    meta: {
      cve: row.cve.id,
      depth,
      truncated: row.total > MAX_PATHS,
      counts: {
        cwe: all.filter((n) => n.type === "CWE").length,
        capec: all.filter((n) => n.type === "CAPEC").length,
        technique: techniques.length,
      },
      tactics: [...tacticCount].map(([tactic, n]) => ({ tactic, techniques: n })).sort((a, b) => b.techniques - a.techniques),
    },
  };
}

export const LABEL_FOR_ID: [RegExp, NodeType][] = [
  [/^CVE-\d{4}-\d+$/, "CVE"],
  [/^CWE-\d+$/, "CWE"],
  [/^CAPEC-\d+$/, "CAPEC"],
  [/^T\d{4}(\.\d{3})?$/, "Technique"],
];

export function typeOfId(id: string): NodeType | null {
  return LABEL_FOR_ID.find(([re]) => re.test(id))?.[1] ?? null;
}

const SHORTEST = (fromLabel: NodeType, toLabel: NodeType) => `
MATCH (a:${fromLabel} {id: $from}), (b:${toLabel} {id: $to})
MATCH p = shortestPath((a)-[:INSTANCE_OF|CHILD_OF|EXPLOITS|ENABLES|SUBTECHNIQUE_OF*..8]-(b))
RETURN [n IN nodes(p) | n { .*, kind: labels(n)[0] }] AS nodes,
       [r IN relationships(p) | { source: startNode(r).id, target: endNode(r).id, type: type(r) }] AS rels`;

/**
 * Shortest connection between any two catalogue entries (relationship
 * direction ignored, so read it as "how are these connected", not an
 * attack order). null = one end missing or no path within 8 hops.
 */
export async function getShortestPath(
  from: string,
  to: string,
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[]; hops: number } | null> {
  const fl = typeOfId(from);
  const tl = typeOfId(to);
  if (!fl || !tl) return null;
  // Labels come from the fixed whitelist above, never from user text.
  const rows = await runCypher<{ nodes: Raw[]; rels: GraphEdge[] }>(SHORTEST(fl, tl), { from, to });
  const row = rows[0];
  if (!row) return null;
  return { nodes: row.nodes.map(toNode), edges: row.rels, hops: row.rels.length };
}
