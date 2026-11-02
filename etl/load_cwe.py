"""Load the CWE catalogue into MySQL: tables `cwe` and `cwe_relationship`.

Input:  data/raw/cwec_latest.xml.zip  (downloaded by etl/download.py)
Run:    python -m etl.load_cwe [--file PATH]

What it loads
- cwe: every Weakness, plus every Grouping (called Category before CWE 5.0).
  NVD sometimes tags a CVE with a grouping/category ID, so without these
  rows load_nvd.py would have to drop those links. Groupings have no
  abstraction level of their own, so they are stored as 'Category'.
  Deprecated/obsolete entries are kept with their status so old CVEs that
  still reference them can join.
- cwe_relationship: one row per (parent, child) from each Weakness's
  Related_Weakness elements with Nature="ChildOf". The same pair is listed
  once per CWE view, so duplicates are dropped. Pairs whose parent or child
  is not in the file are skipped and counted.

Safe to re-run: cwe rows are upserted (INSERT ... ON DUPLICATE KEY UPDATE),
relationships use INSERT IGNORE. Everything runs in one transaction, so a
failure leaves the tables exactly as they were.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

from etl.common import config
from etl.common.db import get_mysql

BATCH_SIZE = 1000
DEFAULT_FILE = Path(getattr(config, "RAW_DIR", Path(__file__).resolve().parents[1] / "data" / "raw")) / "cwec_latest.xml.zip"

# Column limits from db/mysql/01_schema.sql
MAX_NAME = 255

# Multi-row upsert. The `AS new` row alias (MySQL 8.0.19+) replaces the
# deprecated VALUES(col) function in the UPDATE part.
CWE_UPSERT = (
    "INSERT INTO cwe (cwe_id, name, abstraction, status, description) VALUES {rows} "
    "AS new ON DUPLICATE KEY UPDATE "
    "name = new.name, abstraction = new.abstraction, status = new.status, description = new.description"
)
CWE_ROW = "(%s, %s, %s, %s, %s)"

# INSERT IGNORE: a pair that already exists is skipped instead of failing
# the whole batch on the composite primary key.
REL_INSERT = "INSERT IGNORE INTO cwe_relationship (parent_cwe_id, child_cwe_id, relationship_type) VALUES {rows}"
REL_ROW = "(%s, %s, 'ChildOf')"


def clean_text(elem: ET.Element | None) -> str | None:
    """All text inside an element (including nested XHTML), whitespace collapsed."""
    if elem is None:
        return None
    text = re.sub(r"\s+", " ", "".join(elem.itertext())).strip()
    return text or None


def parse(path: Path) -> tuple[list[tuple], list[tuple[str, str]], dict]:
    """Read the zipped XML and return (cwe rows, ChildOf pairs, skip counters)."""
    with zipfile.ZipFile(path) as zf:
        xml_names = [n for n in zf.namelist() if n.endswith(".xml")]
        if len(xml_names) != 1:
            raise ValueError(f"expected one .xml file in {path}, found {xml_names}")
        with zf.open(xml_names[0]) as fh:
            root = ET.parse(fh).getroot()

    # The namespace changes with the schema version (cwe-7, cwe-8, ...),
    # so read it from the root tag instead of hard-coding it.
    ns = root.tag[1:].split("}")[0] if root.tag.startswith("{") else ""

    def q(tag: str) -> str:
        return f"{{{ns}}}{tag}" if ns else tag

    rows: list[tuple] = []
    pairs: set[tuple[str, str]] = set()
    raw_pairs = 0

    for w in root.iterfind(f"{q('Weaknesses')}/{q('Weakness')}"):
        cwe_id = f"CWE-{w.get('ID')}"
        rows.append((cwe_id, w.get("Name")[:MAX_NAME], w.get("Abstraction"), w.get("Status"),
                     clean_text(w.find(q("Description")))))
        for rel in w.iterfind(f"{q('Related_Weaknesses')}/{q('Related_Weakness')}"):
            if rel.get("Nature") == "ChildOf":
                raw_pairs += 1
                pairs.add((f"CWE-{rel.get('CWE_ID')}", cwe_id))  # (parent, child)

    # CWE 5.0 renamed Categories to Groupings; accept either.
    for section, item in (("Groupings", "Grouping"), ("Categories", "Category")):
        for g in root.iterfind(f"{q(section)}/{q(item)}"):
            rows.append((f"CWE-{g.get('ID')}", g.get("Name")[:MAX_NAME], "Category", g.get("Status"),
                         clean_text(g.find(q("Summary")))))

    known = {r[0] for r in rows}
    kept = [(p, c) for p, c in sorted(pairs) if p in known and c in known and p != c]
    skipped = {
        "duplicate_pairs": raw_pairs - len(pairs),
        "missing_endpoint": sum(1 for p, c in pairs if p not in known or c not in known),
        "self_reference": sum(1 for p, c in pairs if p == c and p in known),
    }
    return rows, kept, skipped


def batches(items: list, size: int = BATCH_SIZE):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def run_batched(cur, sql: str, row_sql: str, items: list[tuple]) -> int:
    """Send rows as multi-row INSERTs of BATCH_SIZE (one round trip per batch).

    Built by hand instead of cursor.executemany() so the batching works the
    same with any DB-API driver; values still go through %s placeholders,
    never string formatting.
    """
    affected = 0
    for chunk in batches(items):
        cur.execute(sql.format(rows=", ".join([row_sql] * len(chunk))),
                    [v for row in chunk for v in row])
        affected += cur.rowcount
    return affected


def load(path: Path) -> dict:
    t0 = time.perf_counter()
    rows, pairs, skipped = parse(path)
    weaknesses = sum(1 for r in rows if r[2] != "Category")

    conn = get_mysql()
    try:
        cur = conn.cursor()
        cur.execute("SELECT cwe_id FROM cwe")
        existing = {r[0] for r in cur.fetchall()}
        cur.execute("SELECT COUNT(*) FROM cwe_relationship")
        rel_before = cur.fetchone()[0]

        run_batched(cur, CWE_UPSERT, CWE_ROW, rows)
        run_batched(cur, REL_INSERT, REL_ROW, pairs)

        cur.execute("SELECT COUNT(*) FROM cwe_relationship")
        rel_after = cur.fetchone()[0]
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    new_cwe = sum(1 for r in rows if r[0] not in existing)
    return {
        "cwe_rows": len(rows),
        "weaknesses": weaknesses,
        "categories": len(rows) - weaknesses,
        "cwe_inserted": new_cwe,
        "cwe_refreshed": len(rows) - new_cwe,
        "relationships": len(pairs),
        "relationships_inserted": rel_after - rel_before,
        "relationships_already_present": len(pairs) - (rel_after - rel_before),
        "skipped_duplicate_pairs": skipped["duplicate_pairs"],
        "skipped_missing_endpoint": skipped["missing_endpoint"],
        "skipped_self_reference": skipped["self_reference"],
        "seconds": round(time.perf_counter() - t0, 2),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Load CWE weaknesses and hierarchy into MySQL.")
    ap.add_argument("--file", type=Path, default=DEFAULT_FILE, help=f"CWE zip (default {DEFAULT_FILE})")
    args = ap.parse_args(argv)

    if not args.file.exists():
        print(f"load_cwe: {args.file} not found. Run python -m etl.download first.", file=sys.stderr)
        return 1

    stats = load(args.file)
    print("load_cwe: done")
    for key, value in stats.items():
        print(f"  {key:32} {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
