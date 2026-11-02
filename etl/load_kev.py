"""Flag CVEs from the CISA Known Exploited Vulnerabilities (KEV) catalogue.

Input:  data/raw/known_exploited_vulnerabilities.json  (downloaded by etl/download.py)
Run:    python -m etl.load_kev [--file PATH]
Needs:  load_nvd.py first (only CVEs already in `cve` can be flagged).

For every KEV entry whose cveID is in `cve`:
    is_kev = TRUE, kev_date_added = dateAdded,
    kev_ransomware = (knownRansomwareCampaignUse == "Known")
CVEs flagged by an earlier run but no longer in the catalogue (CISA does
remove entries occasionally) are unflagged, so the table always mirrors
the current catalogue.

How: the catalogue goes into a TEMPORARY table, then two multi-table
UPDATEs join it to `cve`. That is two set-based statements instead of
~1,800 single-row UPDATEs, and the join itself skips KEV entries outside
our 2024-2026 CVE range. Everything runs in one transaction: either all
flags change or none do (chk_kev_date is checked on every row).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from etl.common import config
from etl.common.db import get_mysql
from etl.load_cwe import run_batched

DEFAULT_FILE = Path(getattr(config, "RAW_DIR", Path(__file__).resolve().parents[1] / "data" / "raw")) / "known_exploited_vulnerabilities.json"

# Session-only table: other connections cannot see it and MySQL drops it
# when the connection closes. Unlike CREATE TABLE, creating a TEMPORARY
# table does not commit the open transaction.
CREATE_TMP = """
CREATE TEMPORARY TABLE tmp_kev (
    cve_id      VARCHAR(20) PRIMARY KEY,
    date_added  DATE        NOT NULL,
    ransomware  BOOLEAN     NOT NULL
)"""
TMP_INSERT = "INSERT INTO tmp_kev (cve_id, date_added, ransomware) VALUES {rows}"
TMP_ROW = "(%s, %s, %s)"

# Flag (or refresh) every CVE that is in the catalogue. The inner JOIN
# only touches CVEs present in both tables.
FLAG = """
UPDATE cve c
JOIN   tmp_kev k ON k.cve_id = c.cve_id
SET    c.is_kev = TRUE,
       c.kev_date_added = k.date_added,
       c.kev_ransomware = k.ransomware"""

# Unflag CVEs that are flagged but no longer in the catalogue. LEFT JOIN +
# IS NULL is the anti-join "no matching row in tmp_kev". All three columns
# change in one statement, so chk_kev_date and chk_kev_ransomware hold.
UNFLAG = """
UPDATE cve c
LEFT JOIN tmp_kev k ON k.cve_id = c.cve_id
SET    c.is_kev = FALSE,
       c.kev_date_added = NULL,
       c.kev_ransomware = FALSE
WHERE  c.is_kev = TRUE
  AND  k.cve_id IS NULL"""


def parse(path: Path) -> tuple[list[tuple], str]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    rows = {}
    for v in data["vulnerabilities"]:
        rows[v["cveID"]] = (v["cveID"], v["dateAdded"], v.get("knownRansomwareCampaignUse") == "Known")
    return list(rows.values()), data.get("catalogVersion", "?")


def load(path: Path) -> dict:
    t0 = time.perf_counter()
    rows, version = parse(path)

    conn = get_mysql()
    try:
        cur = conn.cursor()
        cur.execute("DROP TEMPORARY TABLE IF EXISTS tmp_kev")
        cur.execute(CREATE_TMP)
        run_batched(cur, TMP_INSERT, TMP_ROW, rows)

        cur.execute("SELECT COUNT(*), COALESCE(SUM(k.ransomware), 0) FROM tmp_kev k JOIN cve c ON c.cve_id = k.cve_id")
        matched, ransomware = cur.fetchone()

        # Count before updating instead of reading cursor.rowcount, whose
        # meaning (rows changed vs rows matched) depends on the driver.
        # '<=>' is NULL-safe: a NULL kev_date_added vs a date counts as different.
        cur.execute("""SELECT COUNT(*) FROM cve c JOIN tmp_kev k ON k.cve_id = c.cve_id
                       WHERE NOT (c.is_kev = TRUE AND c.kev_date_added <=> k.date_added
                                  AND c.kev_ransomware = k.ransomware)""")
        changed = cur.fetchone()[0]
        cur.execute("""SELECT COUNT(*) FROM cve c LEFT JOIN tmp_kev k ON k.cve_id = c.cve_id
                       WHERE c.is_kev = TRUE AND k.cve_id IS NULL""")
        unflagged = cur.fetchone()[0]

        cur.execute(FLAG)
        cur.execute(UNFLAG)

        cur.execute("SELECT COUNT(*) FROM cve WHERE is_kev = TRUE")
        total_flagged = cur.fetchone()[0]
        cur.execute("DROP TEMPORARY TABLE tmp_kev")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "catalog_version": version,
        "kev_entries": len(rows),
        "matched_in_cve": matched,
        "not_in_our_cve_range": len(rows) - matched,
        "ransomware_known": int(ransomware),
        "newly_flagged_or_changed": changed,
        "unflagged_removed_from_kev": unflagged,
        "cve_flagged_total": total_flagged,
        "seconds": round(time.perf_counter() - t0, 2),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Flag CISA KEV entries on the cve table.")
    ap.add_argument("--file", type=Path, default=DEFAULT_FILE, help=f"KEV JSON (default {DEFAULT_FILE})")
    args = ap.parse_args(argv)

    if not args.file.exists():
        print(f"load_kev: {args.file} not found. Run python -m etl.download first.", file=sys.stderr)
        return 1

    stats = load(args.file)
    print("load_kev: done")
    for key, value in stats.items():
        print(f"  {key:30} {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
