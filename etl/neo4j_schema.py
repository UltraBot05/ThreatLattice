"""Apply db/neo4j/01_constraints.cypher to Neo4j (idempotent: IF NOT EXISTS).

Run:  python -m etl.neo4j_schema
"""
from __future__ import annotations

import sys

from etl.common import config
from etl.common.db import get_neo4j

SCHEMA_FILE = config.REPO_ROOT / "db" / "neo4j" / "01_constraints.cypher"


def statements(text: str) -> list[str]:
    """Split a .cypher file on ';', dropping // comment lines and blanks."""
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith("//")]
    return [s.strip() for s in "\n".join(lines).split(";") if s.strip()]


def main() -> int:
    stmts = statements(SCHEMA_FILE.read_text(encoding="utf-8"))
    with get_neo4j() as driver:
        for s in stmts:
            driver.execute_query(s)
        records, _, _ = driver.execute_query("SHOW CONSTRAINTS YIELD name, labelsOrTypes, properties RETURN *")
    print(f"neo4j_schema: applied {len(stmts)} statements")
    for r in records:
        print(f"  {r['name']:10} {r['labelsOrTypes']} {r['properties']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
