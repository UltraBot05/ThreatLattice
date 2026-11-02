"""Load NVD CVE feeds into MySQL: tables `cve`, `cve_cwe`, `cpe`, `cve_cpe`.

Input:  data/raw/nvdcve-2.0-{2024,2025,2026}.json.gz  (downloaded by etl/download.py)
Run:    python -m etl.load_nvd [--years 2024 2025 2026]
Needs:  load_cwe.py first (cve_cwe links are only kept for CWEs in `cwe`).

Parsing rules (HANDOFF 4.7)
- Rejected CVEs (vulnStatus = Rejected) are skipped, and deleted if an
  earlier load stored them.
- CVSS pick order 3.1 -> 4.0 -> 3.0, preferring the NVD's own ("Primary")
  score. Most new CVEs only carry their publisher's ("Secondary") score, so
  if no version has a Primary score the same order is tried again for
  Secondary. Without this fallback about 70% of 2024-2026 CVEs would show
  as unscored. The source used is counted in the output.
- cvss_source records who produced the chosen score: NVD (a Primary
  metric), ADP (a Secondary metric from CISA's Authorized Data Publisher,
  identified by its fixed source id), or CNA (any other Secondary metric:
  the organisation that published the CVE). NULL when unscored.
- cvss_severity is left NULL when NVD gives none; trg_cve_bi derives it.
- CWE from weaknesses[].description[].value. NVD placeholders
  (NVD-CWE-Other, NVD-CWE-noinfo) are skipped, and so are CWE IDs that are
  not in the `cwe` table (counted).
- Products from configurations[].nodes[].cpeMatch[] where vulnerable = true:
  cpe:2.3:part:vendor:product:version:... split on unescaped ':'. A
  version of '*' or '-' is stored as given.

Safe to re-run: cve rows are upserted; each loaded CVE's cve_cwe and
cve_cpe links are deleted and re-inserted, so links NVD removed disappear
too; cpe rows are only added. Each year's file is one transaction.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

from etl.common import config
from etl.common.db import get_mysql
from etl.load_cwe import batches, run_batched

YEARS = (2024, 2025, 2026)
RAW_DIR = Path(getattr(config, "RAW_DIR", Path(__file__).resolve().parents[1] / "data" / "raw"))
CVSS_ORDER = ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30")
MAX_TEXT_BYTES = 65535                     # MySQL TEXT limit (bytes, not characters)
CPE_SPLIT = re.compile(r"(?<!\\):")        # ':' not preceded by a backslash
CPE_UNESCAPE = re.compile(r"\\(.)")        # '\/' -> '/', '\:' -> ':'
CISA_ADP_SOURCE = "134c704f-9b21-4f2e-91b3-4a467353bcc0"   # NVD's source id for CISA-ADP

CVE_UPSERT = (
    "INSERT INTO cve (cve_id, description, published_date, last_modified_date, "
    "cvss_base_score, cvss_severity, cvss_vector, cvss_version, cvss_source) VALUES {rows} "
    "AS new ON DUPLICATE KEY UPDATE "
    "description = new.description, published_date = new.published_date, "
    "last_modified_date = new.last_modified_date, cvss_base_score = new.cvss_base_score, "
    "cvss_severity = new.cvss_severity, cvss_vector = new.cvss_vector, cvss_version = new.cvss_version, "
    "cvss_source = new.cvss_source"
)
CVE_ROW = "(%s, %s, %s, %s, %s, %s, %s, %s, %s)"
# KEV columns are not in the UPDATE list on purpose: load_kev.py owns them,
# so re-loading NVD never wipes the KEV flags.

CWE_LINK = "INSERT INTO cve_cwe (cve_id, cwe_id) VALUES {rows}"
CPE_LINK = "INSERT INTO cve_cpe (cve_id, cpe_id) VALUES {rows}"
PAIR_ROW = "(%s, %s)"
CPE_INSERT = "INSERT IGNORE INTO cpe (vendor, product, version) VALUES {rows}"
CPE_ROW = "(%s, %s, %s)"


def pick_cvss(metrics: dict) -> tuple[dict | None, str | None, str]:
    """Return (cvssData, cvss_source, label for the counts) following the pick
    order, or (None, None, 'none')."""
    for wanted in ("Primary", "Secondary"):
        for key in CVSS_ORDER:
            for entry in metrics.get(key, []):
                if entry.get("type") == wanted:
                    if wanted == "Primary":
                        source = "NVD"
                    elif entry.get("source") == CISA_ADP_SOURCE:
                        source = "ADP"
                    else:
                        source = "CNA"
                    return entry["cvssData"], source, f"{key[-3:].lower()} {source}"
    return None, None, "none"


def parse_cpe(criteria: str) -> tuple[str, str, str] | None:
    parts = CPE_SPLIT.split(criteria)
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    vendor, product, version = (CPE_UNESCAPE.sub(r"\1", p) for p in parts[3:6])
    return vendor, product, version


def english(descriptions: list[dict]) -> str | None:
    for d in descriptions:
        if d.get("lang") == "en":
            text = d["value"].strip()
            raw = text.encode("utf-8")
            if len(raw) > MAX_TEXT_BYTES:
                text = raw[:MAX_TEXT_BYTES].decode("utf-8", "ignore")
            return text
    return None


def parse_year(path: Path, stats: Counter) -> tuple[list[tuple], list[str], dict, dict]:
    """Return (cve rows, rejected ids, {cve_id: set of CWE ids}, {cve_id: set of cpe triples})."""
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        data = json.load(fh)

    rows, rejected, cwes, cpes = [], [], {}, {}
    for item in data["vulnerabilities"]:
        c = item["cve"]
        stats["cves_in_feed"] += 1
        if c.get("vulnStatus") == "Rejected":
            rejected.append(c["id"])
            continue
        desc = english(c.get("descriptions", []))
        if desc is None:
            stats["skipped_no_english_description"] += 1
            continue

        cvss, source, label = pick_cvss(c.get("metrics", {}))
        stats[f"score_from {label}"] += 1
        rows.append((
            c["id"], desc, c["published"][:10], c.get("lastModified", "")[:10] or None,
            cvss["baseScore"] if cvss else None,
            cvss.get("baseSeverity") if cvss else None,
            cvss.get("vectorString") if cvss else None,
            cvss.get("version") if cvss else None,
            source,
        ))

        ids = set()
        for w in c.get("weaknesses", []):
            for d in w.get("description", []):
                if d["value"].startswith("NVD-CWE-"):
                    stats["cwe_skipped_placeholder"] += 1
                else:
                    ids.add(d["value"])
        cwes[c["id"]] = ids

        triples = set()
        for cfg in c.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        t = parse_cpe(match["criteria"])
                        if t:
                            triples.add(t)
                        else:
                            stats["cpe_skipped_unparsable"] += 1
        cpes[c["id"]] = triples
    return rows, rejected, cwes, cpes


def cpe_key(t: tuple[str, str, str]) -> tuple[str, str, str]:
    # The table's collation (utf8mb4_0900_ai_ci) compares case-insensitively,
    # so the cache must too, or 'Apache' and 'apache' would look different
    # here but collide on uq_cpe.
    return tuple(s.lower() for s in t)


def load_cpe_cache(cur) -> dict:
    cur.execute("SELECT cpe_id, vendor, product, version FROM cpe")
    return {cpe_key(r[1:]): r[0] for r in cur.fetchall()}


def load_year(conn, path: Path, known_cwes: set, cpe_cache: dict, stats: Counter, unknown_cwes: Counter) -> None:
    rows, rejected, cwes, cpes = parse_year(path, stats)
    cur = conn.cursor()
    try:
        # Existing ids, to report inserted vs updated.
        loaded_ids = [r[0] for r in rows]
        existing = set()
        for chunk in batches(loaded_ids):
            cur.execute(f"SELECT cve_id FROM cve WHERE cve_id IN ({', '.join(['%s'] * len(chunk))})", chunk)
            existing.update(r[0] for r in cur.fetchall())
        stats["cve_inserted"] += len(loaded_ids) - len(existing)
        stats["cve_updated"] += len(existing)

        for chunk in batches(rejected):
            cur.execute(f"DELETE FROM cve WHERE cve_id IN ({', '.join(['%s'] * len(chunk))})", chunk)
            stats["rejected_deleted_from_db"] += cur.rowcount
        stats["rejected_skipped"] += len(rejected)

        run_batched(cur, CVE_UPSERT, CVE_ROW, rows)

        # New products first, so every link below has a cpe_id.
        new = {}
        for triples in cpes.values():
            for t in triples:
                if cpe_key(t) not in cpe_cache:
                    new.setdefault(cpe_key(t), t)
        if new:
            run_batched(cur, CPE_INSERT, CPE_ROW, list(new.values()))
            stats["cpe_rows_added"] += len(new)
            cpe_cache.update(load_cpe_cache(cur))

        # Replace this load's links: delete, then insert the current set.
        for chunk in batches(loaded_ids):
            ph = ", ".join(["%s"] * len(chunk))
            cur.execute(f"DELETE FROM cve_cwe WHERE cve_id IN ({ph})", chunk)
            cur.execute(f"DELETE FROM cve_cpe WHERE cve_id IN ({ph})", chunk)

        cwe_pairs = []
        for cve_id, ids in cwes.items():
            for cwe_id in sorted(ids):
                if cwe_id in known_cwes:
                    cwe_pairs.append((cve_id, cwe_id))
                else:
                    stats["cwe_skipped_unknown"] += 1
                    unknown_cwes[cwe_id] += 1
        run_batched(cur, CWE_LINK, PAIR_ROW, cwe_pairs)
        stats["cve_cwe_links"] += len(cwe_pairs)

        cpe_pairs = set()
        for cve_id, triples in cpes.items():
            for t in triples:
                cpe_id = cpe_cache.get(cpe_key(t))
                if cpe_id is None:      # e.g. accent-only difference the collation also ignores
                    stats["cpe_skipped_unresolved"] += 1
                else:
                    cpe_pairs.add((cve_id, cpe_id))
        run_batched(cur, CPE_LINK, PAIR_ROW, sorted(cpe_pairs))
        stats["cve_cpe_links"] += len(cpe_pairs)

        conn.commit()
    except Exception:
        conn.rollback()
        raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Load NVD CVE 2.0 yearly feeds into MySQL.")
    ap.add_argument("--years", type=int, nargs="+", default=list(YEARS), help="feed years (default 2024 2025 2026)")
    args = ap.parse_args(argv)

    paths = {y: RAW_DIR / f"nvdcve-2.0-{y}.json.gz" for y in args.years}
    missing = [str(p) for p in paths.values() if not p.exists()]
    if missing:
        print(f"load_nvd: missing {', '.join(missing)}. Run python -m etl.download first.", file=sys.stderr)
        return 1

    t0 = time.perf_counter()
    # Pre-set to 0 so every counter prints, even when nothing happened.
    stats: Counter = Counter(dict.fromkeys((
        "cve_inserted", "cve_updated", "rejected_skipped", "rejected_deleted_from_db",
        "cpe_rows_added", "cve_cwe_links", "cve_cpe_links", "cwe_skipped_placeholder",
        "cwe_skipped_unknown", "cpe_skipped_unparsable", "cpe_skipped_unresolved"), 0))
    unknown_cwes: Counter = Counter()
    conn = get_mysql()
    try:
        cur = conn.cursor()
        cur.execute("SELECT cwe_id FROM cwe")
        known_cwes = {r[0] for r in cur.fetchall()}
        if not known_cwes:
            print("load_nvd: cwe table is empty. Run python -m etl.load_cwe first.", file=sys.stderr)
            return 1
        cpe_cache = load_cpe_cache(cur)
        for year, path in paths.items():
            ty = time.perf_counter()
            load_year(conn, path, known_cwes, cpe_cache, stats, unknown_cwes)
            print(f"load_nvd: {year} done in {time.perf_counter() - ty:.1f}s")
    finally:
        conn.close()

    print("load_nvd: done")
    for key in sorted(k for k in stats if not k.startswith("score_from")) + sorted(k for k in stats if k.startswith("score_from")):
        print(f"  {key:34} {stats[key]}")
    if unknown_cwes:
        print(f"  {'unknown CWE ids (top 5)':34} {', '.join(f'{k} x{v}' for k, v in unknown_cwes.most_common(5))}")
    print(f"  {'seconds':34} {time.perf_counter() - t0:.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
