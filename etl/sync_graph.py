"""Copy the catalogues from MySQL into Neo4j and add the graph-only links.

Run:  python -m etl.sync_graph          (after the MySQL loaders and etl.neo4j_schema)

MySQL is the source of truth for every row (HANDOFF 4.6); Neo4j holds the
same entities as nodes so the CVE -> CWE -> CAPEC -> Technique chain is one
pattern match instead of a chain of joins.

Nodes (MERGE on id, properties refreshed every run)
  (:CVE {id, score, severity, source, published, is_kev})   only CVEs with >= 1 CWE link
  (:CWE {id, name, common_name, abstraction})
  (:CAPEC {id, name, severity, likelihood, abstraction})
  (:Technique {id, name, tactics, is_sub})

Relationships (rebuilt every run)
  (CVE)-[:INSTANCE_OF]->(CWE)            from cve_cwe
  (CWE)-[:CHILD_OF]->(CWE)               from cwe_relationship
  (CAPEC)-[:EXPLOITS]->(CWE)             CAPEC XML only (not stored in MySQL)
  (CAPEC)-[:ENABLES]->(Technique)        CAPEC XML only (not stored in MySQL)
  (Technique)-[:SUBTECHNIQUE_OF]->(Technique)  from attack_technique.parent_technique_id

Safe to re-run: nodes are MERGEd and stamped with this run's id; nodes not
seen in this run (e.g. a CVE NVD later rejected) are deleted at the end.
Writes go in UNWIND batches of 5,000.
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from pathlib import Path

from etl.common import config
from etl.common.db import get_mysql, get_neo4j
from etl.load_capec import DEFAULT_FILE as CAPEC_FILE
from etl.load_capec import parse as parse_capec

BATCH = 5000
REL_TYPES = ["INSTANCE_OF", "CHILD_OF", "EXPLOITS", "ENABLES", "SUBTECHNIQUE_OF"]


def fetch(cur, sql: str) -> list[dict]:
    cur.execute(sql)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def read_mysql() -> dict[str, list[dict]]:
    conn = get_mysql()
    try:
        cur = conn.cursor()
        return {
            "cwe": fetch(cur, "SELECT cwe_id AS id, name, common_name, abstraction FROM cwe"),
            "cwe_rel": fetch(cur, "SELECT child_cwe_id AS child, parent_cwe_id AS parent FROM cwe_relationship"),
            "cve": fetch(
                cur,
                "SELECT c.cve_id AS id, c.cvss_base_score AS score, c.cvss_severity AS severity, "
                "c.cvss_source AS source, DATE_FORMAT(c.published_date, '%Y-%m-%d') AS published, c.is_kev "
                "FROM cve c WHERE EXISTS (SELECT 1 FROM cve_cwe x WHERE x.cve_id = c.cve_id)",
            ),
            "cve_cwe": fetch(cur, "SELECT cve_id AS cve, cwe_id AS cwe FROM cve_cwe"),
            "capec": fetch(
                cur,
                "SELECT capec_id AS id, name, abstraction, typical_severity AS severity, "
                "likelihood_of_attack AS likelihood FROM capec",
            ),
            "technique": fetch(
                cur,
                "SELECT t.technique_id AS id, t.name, t.is_subtechnique AS is_sub, t.parent_technique_id AS parent, "
                "GROUP_CONCAT(tt.tactic ORDER BY tt.tactic) AS tactics "
                "FROM attack_technique t LEFT JOIN technique_tactic tt ON tt.technique_id = t.technique_id "
                "GROUP BY t.technique_id, t.name, t.is_subtechnique, t.parent_technique_id",
            ),
        }
    finally:
        conn.close()


def batched(driver, cypher: str, rows: list[dict], **params) -> None:
    for i in range(0, len(rows), BATCH):
        driver.execute_query(cypher, rows=rows[i:i + BATCH], **params)


def sync(capec_file: Path) -> dict:
    t0 = time.perf_counter()
    data = read_mysql()
    _, exploits, enables, _ = parse_capec(capec_file)

    # Python-side cleanup so Neo4j gets plain types and only valid endpoints.
    for r in data["cve"]:
        r["score"] = float(r["score"]) if r["score"] is not None else None
        r["is_kev"] = bool(r["is_kev"])
    for r in data["technique"]:
        r["is_sub"] = bool(r["is_sub"])
        r["tactics"] = r["tactics"].split(",") if r["tactics"] else []
    cwe_ids = {r["id"] for r in data["cwe"]}
    capec_ids = {r["id"] for r in data["capec"]}
    tech_ids = {r["id"] for r in data["technique"]}
    exploits_rows = [{"capec": a, "cwe": b} for a, b in exploits if a in capec_ids and b in cwe_ids]
    enables_rows = [{"capec": a, "tech": b} for a, b in enables if a in capec_ids and b in tech_ids]
    sub_rows = [{"child": r["id"], "parent": r["parent"]} for r in data["technique"] if r["parent"]]
    run = uuid.uuid4().hex

    with get_neo4j() as driver:
        # 1. drop every relationship we own; they are fully rebuilt below.
        #    CALL ... IN TRANSACTIONS needs an auto-commit transaction (session.run).
        with driver.session() as session:
            for rel in REL_TYPES:
                session.run(f"MATCH ()-[r:{rel}]->() CALL (r) {{ DELETE r }} IN TRANSACTIONS OF 10000 ROWS").consume()
        # 2. nodes
        batched(driver, "UNWIND $rows AS r MERGE (n:CWE {id: r.id}) "
                "SET n.name = r.name, n.common_name = r.common_name, n.abstraction = r.abstraction, n.run = $run",
                data["cwe"], run=run)
        batched(driver, "UNWIND $rows AS r MERGE (n:CVE {id: r.id}) "
                "SET n.score = r.score, n.severity = r.severity, n.source = r.source, "
                "n.published = date(r.published), n.is_kev = r.is_kev, n.run = $run",
                data["cve"], run=run)
        batched(driver, "UNWIND $rows AS r MERGE (n:CAPEC {id: r.id}) "
                "SET n.name = r.name, n.abstraction = r.abstraction, n.severity = r.severity, "
                "n.likelihood = r.likelihood, n.run = $run",
                data["capec"], run=run)
        batched(driver, "UNWIND $rows AS r MERGE (n:Technique {id: r.id}) "
                "SET n.name = r.name, n.tactics = r.tactics, n.is_sub = r.is_sub, n.run = $run",
                data["technique"], run=run)
        # 3. relationships (MATCH both ends by the unique, indexed id)
        batched(driver, "UNWIND $rows AS r MATCH (a:CVE {id: r.cve}), (b:CWE {id: r.cwe}) MERGE (a)-[:INSTANCE_OF]->(b)",
                data["cve_cwe"])
        batched(driver, "UNWIND $rows AS r MATCH (a:CWE {id: r.child}), (b:CWE {id: r.parent}) MERGE (a)-[:CHILD_OF]->(b)",
                data["cwe_rel"])
        batched(driver, "UNWIND $rows AS r MATCH (a:CAPEC {id: r.capec}), (b:CWE {id: r.cwe}) MERGE (a)-[:EXPLOITS]->(b)",
                exploits_rows)
        batched(driver, "UNWIND $rows AS r MATCH (a:CAPEC {id: r.capec}), (b:Technique {id: r.tech}) MERGE (a)-[:ENABLES]->(b)",
                enables_rows)
        batched(driver, "UNWIND $rows AS r MATCH (a:Technique {id: r.child}), (b:Technique {id: r.parent}) "
                "MERGE (a)-[:SUBTECHNIQUE_OF]->(b)", sub_rows)
        # 4. remove nodes that no longer exist in MySQL
        stale = 0
        for label in ["CVE", "CWE", "CAPEC", "Technique"]:
            recs, _, _ = driver.execute_query(
                f"MATCH (n:{label}) WHERE n.run <> $run OR n.run IS NULL DETACH DELETE n RETURN count(*) AS n", run=run
            )
            stale += recs[0]["n"]
        # 5. counts per label and relationship type
        counts, _, _ = driver.execute_query(
            "CALL () { MATCH (n) RETURN labels(n)[0] AS k, count(*) AS c "
            "UNION ALL MATCH ()-[r]->() RETURN type(r) AS k, count(*) AS c } RETURN k, c ORDER BY k"
        )
    stats = {f"{r['k']}": r["c"] for r in counts}
    stats["stale_nodes_deleted"] = stale
    stats["seconds"] = round(time.perf_counter() - t0, 1)
    return stats


def coverage() -> dict:
    """Share of CVEs (with a CWE) whose chain reaches an ATT&CK technique, directly or via up to 2 CHILD_OF hops."""
    with get_neo4j() as driver:
        recs, _, _ = driver.execute_query(
            "MATCH (v:CVE) WITH count(v) AS total "
            "MATCH (v:CVE) WHERE EXISTS { (v)-[:INSTANCE_OF]->(:CWE)<-[:EXPLOITS]-(:CAPEC)-[:ENABLES]->(:Technique) } "
            "WITH total, count(v) AS direct "
            "MATCH (v:CVE) WHERE EXISTS { (v)-[:INSTANCE_OF]->(:CWE)-[:CHILD_OF*0..2]->(:CWE)<-[:EXPLOITS]-(:CAPEC)-[:ENABLES]->(:Technique) } "
            "RETURN total, direct, count(v) AS with_parents"
        )
    r = recs[0]
    return {
        "cves_with_cwe": r["total"],
        "reach_technique_direct": r["direct"],
        "reach_technique_via_parent_cwes": r["with_parents"],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Sync MySQL catalogues into Neo4j.")
    ap.add_argument("--capec-file", type=Path, default=CAPEC_FILE)
    args = ap.parse_args(argv)
    if not args.capec_file.exists():
        print(f"sync_graph: {args.capec_file} not found. Run python -m etl.download first.", file=sys.stderr)
        return 1
    stats = sync(args.capec_file)
    stats.update(coverage())
    print("sync_graph: done")
    for k, v in stats.items():
        print(f"  {k:36} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
