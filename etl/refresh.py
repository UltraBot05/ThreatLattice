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
If a loader fails, the run stops there; the state file records why and
the loop retries with back-off (1 h, 2 h, 4 h ... capped at 24 h).

State: data/raw/refresh_state.json {last_success, last_attempt, last_error,
failures, steps}. In --loop mode the first refresh runs at once if the
database has no CVEs (fresh volume), otherwise when last_success is older
than TL_REFRESH_DAYS.

Off switch: TL_REFRESH_DAYS=0 pauses the loop (it stays up but never runs;
use it to freeze the data while report numbers and screenshots are taken).
`--once` still works, on purpose.

Only one refresh at a time: a lock file (data/raw/.refresh.lock) stops a
manual `--once` and the loop from loading at the same moment. A lock older
than 6 h is treated as left behind by a crash and taken over.
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
LOCK_FILE = Path(config.RAW_DIR) / ".refresh.lock"
LOCK_STALE_S = 6 * 3600
CHECK_EVERY_S = 3600
MAX_BACKOFF_H = 24


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


def acquire_lock() -> bool:
    """Create the lock file atomically (O_EXCL); take over a stale one."""
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(2):
        try:
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                age = time.time() - LOCK_FILE.stat().st_mtime
            except OSError:
                continue  # removed between our open and stat: try again
            if age < LOCK_STALE_S:
                return False
            print(f"refresh: taking over a stale lock ({age / 3600:.1f} h old)", flush=True)
            LOCK_FILE.unlink(missing_ok=True)
            continue
        with os.fdopen(fd, "w") as fh:
            fh.write(f"{os.getpid()} {now()}\n")
        return True
    return False


def run_once() -> bool:
    if not acquire_lock():
        print(f"refresh: another refresh is running ({LOCK_FILE}); skipped", flush=True)
        return False
    try:
        return _run_locked()
    finally:
        LOCK_FILE.unlink(missing_ok=True)


def _run_locked() -> bool:
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
            state["failures"] = int(state.get("failures") or 0) + 1
            write_state(state)
            print(f"refresh: STOPPED, {err}", flush=True)
            return False
    state["last_success"] = now()
    state["failures"] = 0
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
    """Due when the last success is older than `days`, but after a failure
    wait 1, 2, 4 ... (max 24) hours before trying again."""
    state = read_state()
    current = datetime.now(timezone.utc)
    failures = int(state.get("failures") or 0)
    if failures and state.get("last_attempt"):
        wait_h = min(2 ** (failures - 1), MAX_BACKOFF_H)
        if (current - datetime.fromisoformat(state["last_attempt"])).total_seconds() < wait_h * 3600:
            return False
        return True
    last = state.get("last_success")
    if not last:
        return True
    return (current - datetime.fromisoformat(last)).total_seconds() >= days * 86400


def loop(days: float) -> None:
    if days <= 0:
        print("refresh: paused (TL_REFRESH_DAYS=0); `--once` still works. Idle.", flush=True)
        while True:
            time.sleep(CHECK_EVERY_S)
    print(f"refresh: loop every {days} days, checking hourly; state {STATE_FILE}", flush=True)
    while True:
        if due(days) or database_empty():
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
