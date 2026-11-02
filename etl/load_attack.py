"""Load MITRE ATT&CK Enterprise techniques into MySQL:
tables `attack_technique` and `technique_tactic`.

Input:  data/raw/enterprise-attack.json  (STIX 2.1 bundle, downloaded by etl/download.py)
Run:    python -m etl.load_attack [--file PATH]

What it reads
- Every STIX object of type "attack-pattern" that is not revoked and not
  x_mitre_deprecated. Its ATT&CK id (T1190, T1059.001) is the
  external_references entry with source_name "mitre-attack".
- attack_technique: id, name, description, x_mitre_platforms (stored as a
  JSON array: display only), x_mitre_is_subtechnique, and the parent id for
  sub-techniques (T1059.001 -> T1059). Parents are written before
  sub-techniques because of the self foreign key; a sub-technique whose
  parent is not loaded keeps parent NULL (counted).
- technique_tactic: one row per kill_chain_phases entry of the
  "mitre-attack" kill chain. phase_name is already the short form the
  chk_tactic CHECK expects ("initial-access").
- parse() also returns CAPEC references found in ATT&CK
  (external_references with source_name "capec"), a second source for the
  Neo4j-only ENABLES edges next to CAPEC's own Taxonomy_Mappings.

Safe to re-run: techniques are upserted; technique_tactic is rebuilt from
the file. One transaction.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

from etl.common import config
from etl.common.db import get_mysql
from etl.load_cwe import run_batched

DEFAULT_FILE = Path(config.RAW_DIR) / "enterprise-attack.json"
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTIC_RE = re.compile(r"^[a-z]+(-[a-z]+)*$")
CAPEC_RE = re.compile(r"^CAPEC-\d+$")
MAX_NAME = 255
MAX_TEXT_BYTES = 65535

TECH_UPSERT = (
    "INSERT INTO attack_technique (technique_id, name, platforms, is_subtechnique, parent_technique_id, description) "
    "VALUES {rows} AS new ON DUPLICATE KEY UPDATE "
    "name = new.name, platforms = new.platforms, is_subtechnique = new.is_subtechnique, "
    "parent_technique_id = new.parent_technique_id, description = new.description"
)
TECH_ROW = "(%s, %s, %s, %s, %s, %s)"
TACTIC_INSERT = "INSERT INTO technique_tactic (technique_id, tactic) VALUES {rows}"
TACTIC_ROW = "(%s, %s)"


def fit_text(text: str | None) -> str | None:
    """Cut to the MySQL TEXT limit (bytes, not characters) without breaking a character."""
    if not text:
        return None
    raw = text.encode("utf-8")
    return text if len(raw) <= MAX_TEXT_BYTES else raw[:MAX_TEXT_BYTES].decode("utf-8", "ignore")


def attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and TECHNIQUE_RE.match(ref.get("external_id", "")):
            return ref["external_id"]
    return None


def parse(path: Path) -> tuple[list[tuple], list[tuple[str, str]], list[tuple[str, str]], dict]:
    """Return (technique rows, (technique, tactic) pairs, (capec, technique) pairs, counters).

    Rows are ordered parents first, then sub-techniques.
    """
    with open(path, encoding="utf-8") as fh:
        bundle = json.load(fh)

    techs: dict[str, dict] = {}
    counts = {"skipped_revoked_or_deprecated": 0, "skipped_no_attack_id": 0, "bad_tactics": 0}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            counts["skipped_revoked_or_deprecated"] += 1
            continue
        tid = attack_id(obj)
        if not tid:
            counts["skipped_no_attack_id"] += 1
            continue
        techs[tid] = obj

    rows: list[tuple] = []
    tactics: set[tuple[str, str]] = set()
    capec_links: set[tuple[str, str]] = set()
    orphans = 0
    for tid in sorted(techs, key=lambda t: ("." in t, t)):  # parents first
        obj = techs[tid]
        is_sub = "." in tid
        parent = tid.split(".")[0] if is_sub else None
        if parent and parent not in techs:
            parent, orphans = None, orphans + 1
        platforms = obj.get("x_mitre_platforms")
        rows.append((
            tid,
            (obj.get("name") or tid)[:MAX_NAME],
            json.dumps(platforms) if platforms else None,
            is_sub,
            parent,
            fit_text(obj.get("description")),
        ))
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            name = (phase.get("phase_name") or "").strip().lower()
            if TACTIC_RE.match(name):
                tactics.add((tid, name))
            else:
                counts["bad_tactics"] += 1
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "capec" and CAPEC_RE.match(ref.get("external_id", "")):
                capec_links.add((ref["external_id"], tid))
    counts["subtechniques_without_parent"] = orphans
    return rows, sorted(tactics), sorted(capec_links), counts


def load(path: Path) -> dict:
    t0 = time.perf_counter()
    rows, tactics, capec_links, counts = parse(path)
    conn = get_mysql()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM attack_technique")
        before = cur.fetchone()[0]
        parents = [r for r in rows if not r[3]]
        subs = [r for r in rows if r[3]]
        run_batched(cur, TECH_UPSERT, TECH_ROW, parents)
        run_batched(cur, TECH_UPSERT, TECH_ROW, subs)
        cur.execute("DELETE FROM technique_tactic")
        run_batched(cur, TACTIC_INSERT, TACTIC_ROW, tactics)
        cur.execute("SELECT COUNT(*) FROM attack_technique")
        after = cur.fetchone()[0]
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {
        "techniques": len(rows),
        "  of which sub-techniques": sum(1 for r in rows if r[3]),
        "techniques_inserted": after - before,
        "technique_tactic rows": len(tactics),
        "capec_refs (CAPEC->Technique, Neo4j only)": len(capec_links),
        **counts,
        "seconds": round(time.perf_counter() - t0, 2),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Load MITRE ATT&CK Enterprise techniques into MySQL.")
    ap.add_argument("--file", type=Path, default=DEFAULT_FILE)
    args = ap.parse_args(argv)
    if not args.file.exists():
        print(f"load_attack: {args.file} not found. Run python -m etl.download first.", file=sys.stderr)
        return 1
    stats = load(args.file)
    print("load_attack: done")
    for k, v in stats.items():
        print(f"  {k:44} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
