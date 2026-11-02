"""Download every source catalogue into data/raw/ (RAW_DIR).

Run:  python -m etl.download            # skip files that already exist
      python -m etl.download --force    # re-download everything
      python -m etl.download --only capec_latest.xml

Files are streamed to a .part file and renamed only when complete, so an
interrupted download never leaves a half file that a loader would read.
"""
from __future__ import annotations

import argparse
import sys
import time

import requests

from etl.common import config

HEADERS = {"User-Agent": "ThreatLattice-ETL/1.0 (PES University DBMS project)"}


def fetch(name: str, url: str, force: bool) -> str:
    dest = config.RAW_DIR / name
    if dest.exists() and not force:
        return f"skip   {name} (exists, {dest.stat().st_size / 1e6:.1f} MB)"
    part = dest.with_suffix(dest.suffix + ".part")
    t0 = time.perf_counter()
    with requests.get(url, headers=HEADERS, stream=True, timeout=60) as r:
        r.raise_for_status()
        with open(part, "wb") as fh:
            for chunk in r.iter_content(chunk_size=1 << 20):
                fh.write(chunk)
    part.replace(dest)
    return f"ok     {name} ({dest.stat().st_size / 1e6:.1f} MB, {time.perf_counter() - t0:.1f}s)"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Download CWE, CAPEC, ATT&CK, NVD and KEV source files.")
    ap.add_argument("--force", action="store_true", help="re-download files that already exist")
    ap.add_argument("--only", nargs="*", help="file names to fetch (default: all)")
    args = ap.parse_args(argv)

    config.RAW_DIR.mkdir(parents=True, exist_ok=True)
    targets = {k: v for k, v in config.SOURCES.items() if not args.only or k in args.only}
    failed = 0
    for name, url in targets.items():
        try:
            print(fetch(name, url, args.force))
        except requests.RequestException as exc:
            failed += 1
            print(f"FAILED {name}: {exc}", file=sys.stderr)
    print(f"download: {len(targets) - failed}/{len(targets)} ready in {config.RAW_DIR}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
