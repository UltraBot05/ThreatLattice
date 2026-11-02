"""Create (or reset) the two demo accounts: one admin, one analyst.

Run:  python -m etl.seed_users

Passwords come from SEED_ADMIN_PASSWORD / SEED_ANALYST_PASSWORD in .env.
If one is not set, a random password is generated and printed ONCE, so no
password is ever written into the repository. Only bcrypt hashes are stored
(cost 12, the same format the web app's bcryptjs produces and verifies).

Safe to re-run: existing demo users get their password, role and
is_active reset (INSERT ... ON DUPLICATE KEY UPDATE).
"""
from __future__ import annotations

import os
import secrets
import sys

import bcrypt

from etl.common.db import get_mysql

DEMO_USERS = [
    ("admin", "admin@threatlattice.local", "admin", "SEED_ADMIN_PASSWORD"),
    ("analyst", "analyst@threatlattice.local", "analyst", "SEED_ANALYST_PASSWORD"),
]

UPSERT = (
    "INSERT INTO app_user (username, email, password_hash, role, is_active) "
    "VALUES (%s, %s, %s, %s, TRUE) AS new "
    "ON DUPLICATE KEY UPDATE password_hash = new.password_hash, role = new.role, is_active = TRUE"
)


def main() -> int:
    conn = get_mysql()
    printed = []
    try:
        cur = conn.cursor()
        for username, email, role, env_name in DEMO_USERS:
            password = os.getenv(env_name)
            if not password:
                password = secrets.token_urlsafe(12)
                printed.append((username, password))
            if len(password) < 10:
                print(f"seed_users: {env_name} must be at least 10 characters", file=sys.stderr)
                return 1
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
            cur.execute(UPSERT, (username, email, hashed, role))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    print("seed_users: admin and analyst are ready (sign in at http://localhost:3000/login)")
    for username, password in printed:
        print(f"  {username:8} generated password: {password}   (set SEED_{username.upper()}_PASSWORD in .env to choose your own)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
