"""Load the CAPEC catalogue (attack patterns) into MySQL table `capec`.

Input:  data/raw/capec_latest.xml  (downloaded by etl/download.py)
Run:    python -m etl.load_capec [--file PATH]

What it reads (CAPEC XML schema 3.x, namespace taken from the file)
- capec: every Attack_Pattern whose Status is not Deprecated/Obsolete:
  ID, Name, Abstraction (Meta/Standard/Detailed), Description,
  Likelihood_Of_Attack and Typical_Severity. CAPEC uses five levels
  (Very Low .. Very High); they are upper-cased to match the ENUM, and any
  other value becomes NULL (counted).
- Two mappings that exist ONLY in Neo4j (HANDOFF 4.6), returned by parse()
  for etl/sync_graph.py:
    EXPLOITS  CAPEC -> CWE        from Related_Weaknesses/Related_Weakness@CWE_ID
    ENABLES   CAPEC -> Technique  from Taxonomy_Mappings/Taxonomy_Mapping
                                  [@Taxonomy_Name="ATTACK"]/Entry_ID ("1574.010" -> "T1574.010")

Safe to re-run: rows are upserted (INSERT ... AS new ON DUPLICATE KEY UPDATE)
in one transaction.
"""
from __future__ import annotations

import argparse
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from etl.common import config
from etl.common.db import get_mysql
from etl.load_cwe import clean_text, run_batched

DEFAULT_FILE = Path(config.RAW_DIR) / "capec_latest.xml"
SKIP_STATUS = {"Deprecated", "Obsolete"}
LEVELS = {"VERY LOW", "LOW", "MEDIUM", "HIGH", "VERY HIGH"}
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
MAX_NAME = 255

CAPEC_UPSERT = (
    "INSERT INTO capec (capec_id, name, abstraction, likelihood_of_attack, typical_severity, description) "
    "VALUES {rows} AS new ON DUPLICATE KEY UPDATE "
    "name = new.name, abstraction = new.abstraction, likelihood_of_attack = new.likelihood_of_attack, "
    "typical_severity = new.typical_severity, description = new.description"
)
CAPEC_ROW = "(%s, %s, %s, %s, %s, %s)"


def level(text: str | None, counts: dict, field: str) -> str | None:
    """'Very High' -> 'VERY HIGH'; unknown values -> None (and counted)."""
    if not text or not text.strip():
        return None
    v = " ".join(text.split()).upper()
    if v in LEVELS:
        return v
    counts[f"unknown_{field}"] = counts.get(f"unknown_{field}", 0) + 1
    return None


def technique_id(entry: str | None) -> str | None:
    if not entry:
        return None
    t = entry.strip().upper()
    t = t if t.startswith("T") else f"T{t}"
    return t if TECHNIQUE_RE.match(t) else None


def parse(path: Path) -> tuple[list[tuple], list[tuple[str, str]], list[tuple[str, str]], dict]:
    """Return (capec rows, EXPLOITS pairs (capec, cwe), ENABLES pairs (capec, technique), counters)."""
    root = ET.parse(path).getroot()
    ns = root.tag[1:].split("}")[0] if root.tag.startswith("{") else ""

    def q(tag: str) -> str:
        return f"{{{ns}}}{tag}" if ns else tag

    rows: list[tuple] = []
    exploits: set[tuple[str, str]] = set()
    enables: set[tuple[str, str]] = set()
    counts: dict = {"skipped_deprecated": 0, "bad_attack_ids": 0}

    for ap in root.iterfind(f"{q('Attack_Patterns')}/{q('Attack_Pattern')}"):
        if ap.get("Status") in SKIP_STATUS:
            counts["skipped_deprecated"] += 1
            continue
        capec_id = f"CAPEC-{ap.get('ID')}"
        rows.append((
            capec_id,
            (ap.get("Name") or capec_id)[:MAX_NAME],
            ap.get("Abstraction"),
            level(ap.findtext(q("Likelihood_Of_Attack")), counts, "likelihood"),
            level(ap.findtext(q("Typical_Severity")), counts, "severity"),
            clean_text(ap.find(q("Description"))),
        ))
        for rw in ap.iterfind(f"{q('Related_Weaknesses')}/{q('Related_Weakness')}"):
            if rw.get("CWE_ID"):
                exploits.add((capec_id, f"CWE-{rw.get('CWE_ID').strip()}"))
        for tm in ap.iterfind(f"{q('Taxonomy_Mappings')}/{q('Taxonomy_Mapping')}"):
            if (tm.get("Taxonomy_Name") or "").upper() != "ATTACK":
                continue
            tid = technique_id(tm.findtext(q("Entry_ID")))
            if tid:
                enables.add((capec_id, tid))
            else:
                counts["bad_attack_ids"] += 1
    return rows, sorted(exploits), sorted(enables), counts


def load(path: Path) -> dict:
    t0 = time.perf_counter()
    rows, exploits, enables, counts = parse(path)
    conn = get_mysql()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM capec")
        before = cur.fetchone()[0]
        run_batched(cur, CAPEC_UPSERT, CAPEC_ROW, rows)
        cur.execute("SELECT COUNT(*) FROM capec")
        after = cur.fetchone()[0]
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {
        "capec_rows": len(rows),
        "capec_inserted": after - before,
        "exploits_pairs (CAPEC->CWE, Neo4j only)": len(exploits),
        "enables_pairs (CAPEC->Technique, Neo4j only)": len(enables),
        **counts,
        "seconds": round(time.perf_counter() - t0, 2),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Load CAPEC attack patterns into MySQL.")
    ap.add_argument("--file", type=Path, default=DEFAULT_FILE)
    args = ap.parse_args(argv)
    if not args.file.exists():
        print(f"load_capec: {args.file} not found. Run python -m etl.download first.", file=sys.stderr)
        return 1
    stats = load(args.file)
    print("load_capec: done")
    for k, v in stats.items():
        print(f"  {k:44} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
