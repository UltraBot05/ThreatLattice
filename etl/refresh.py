"""Keep the data current: re-download every source and reload both databases.

Run:  python -m etl.refresh --once              # one full refresh now
      python -m etl.refresh --loop              # forever: refresh when due (docker `refresher` service)
      TL_REFRESH_DAYS=3.5 (default)             # how often, in days

One refresh = download (all 7 files, --force) -> load_cwe -> load_capec ->
load_attack -> load_nvd -> load_kev -> neo4j_schema -> sync_graph.
Every loader is idempotent (upserts, rebuilt links), so a refresh only adds
and updates rows; NVD-rejected CVEs are removed and KEV flags follow CISA.
Users, investigations and the audit log are never touched.

If a download fails, the previous file is kept (download.py writes .part
files and renames only on success) and the run continues with what it has.
If a loader fails, the run stops there and is retried at the next check
(every hour); the state file records why.

State: data/raw/refresh_state.json {last_success, last_attempt, last_error, steps}.
In --loop mode the first refresh runs at once if the database has no CVEs
(fresh volume), otherwise when last_success is older than TL_REFRESH_DAYS.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from etl.common import config

STATE_FILE = Path(config.RAW_DIR) / "refresh_state.json"
CHECK_EVERY_S = 3600


def _steps():
    # Imported lazily so `--help` works without the database drivers loaded.
    from etl import download, load_attack, load_capec, load_cwe, load_kev, load_nvd, neo4j_schema, sync_graph

    return [
        ("download", lambda: download.main(["--force"])),
        ("load_cwe", lambda: load_cwe.main([])),
        ("load_capec", lambda: load_capec.main([])),
        ("load_attack", lambda: load_attack.main([])),
        ("load_nvd", lambda: load_nvd.main([])),
        ("load_kev", lambda: load_kev.main([])),
        ("neo4j_schema", lambda: neo4j_schema.main()),
        ("sync_graph", lambda: sync_graph.main([])),
    ]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def write_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def run_once() -> bool:
    state = read_state()
    state.update(last_attempt=now(), last_error=None, steps={})
    write_state(state)
    print(f"refresh: start {state['last_attempt']}", flush=True)
    for name, step in _steps():
        t0 = time.perf_counter()
        try:
            code = step()
        except Exception as exc:  # keep the loop alive; record and retry later
            traceback.print_exc()
            code, err = 1, f"{name}: {exc}"
        else:
            err = None if code in (0, None) or name == "download" else f"{name} exited with {code}"
        secs = round(time.perf_counter() - t0, 1)
        state["steps"][name] = {"exit": code, "seconds": secs}
        print(f"refresh: {name} exit={code} in {secs}s", flush=True)
        if err:
            state["last_error"] = err
            write_state(state)
            print(f"refresh: STOPPED, {err}", flush=True)
            return False
    state["last_success"] = now()
    write_state(state)
    print(f"refresh: done {state['last_success']}", flush=True)
    return True


def database_empty() -> bool:
    from etl.common.db import get_mysql

    try:
        conn = get_mysql()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM cve")
            return cur.fetchone()[0] == 0
        finally:
            conn.close()
    except Exception as exc:
        print(f"refresh: database not reachable yet ({exc}); will retry", flush=True)
        return False


def due(days: float) -> bool:
    last = read_state().get("last_success")
    if not last:
        return True
    age = datetime.now(timezone.utc) - datetime.fromisoformat(last)
    return age.total_seconds() >= days * 86400


def loop(days: float) -> None:
    print(f"refresh: loop every {days} days, checking hourly; state {STATE_FILE}", flush=True)
    while True:
        if database_empty() or due(days):
            run_once()
        time.sleep(CHECK_EVERY_S)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Re-download all sources and reload MySQL + Neo4j.")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true", help="refresh now and exit")
    mode.add_argument("--loop", action="store_true", help="refresh whenever due (runs forever)")
    ap.add_argument("--days", type=float, default=float(os.getenv("TL_REFRESH_DAYS", "3.5")))
    args = ap.parse_args(argv)
    if args.once:
        return 0 if run_once() else 1
    loop(args.days)
    return 0


if __name__ == "__main__":
    sys.exit(main())
