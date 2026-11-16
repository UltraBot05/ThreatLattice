#!/usr/bin/env bash
# check_constraints.sh: run constraint_tests.sql and fail unless every
# F-test was rejected and every P-test printed PASS.
#
# The expected counts are read from the test file itself (one "-- Fnn"
# comment per F-test, one "SELECT 'Pnn'" per P-test), so adding a test
# needs no change here.
#
# Usage (repo root, MySQL container running):
#   bash db/mysql/tests/check_constraints.sh [container] [database]
# Defaults: threatlattice-mysql, threatlattice. The root password is read
# from MYSQL_ROOT_PASSWORD inside the container, never from this shell.
set -euo pipefail

CONTAINER="${1:-threatlattice-mysql}"
DATABASE="${2:-threatlattice}"
TESTS="$(dirname "$0")/constraint_tests.sql"

want_f=$(grep -cE '^-- F[0-9]{2}' "$TESTS")
want_p=$(grep -cE "^SELECT 'P[0-9]{2}'" "$TESTS")

out=$(mktemp)
err=$(mktemp)
trap 'rm -f "$out" "$err"' EXIT

# --force keeps going after each expected error; it exits non-zero
# because errors happened, so its exit code is not the verdict.
docker exec -i "$CONTAINER" sh -c "exec mysql --force -uroot -p\"\$MYSQL_ROOT_PASSWORD\" $DATABASE" \
  < "$TESTS" > "$out" 2> "$err" || true

got_f=$(grep -c '^ERROR' "$err" || true)
got_pass=$(grep -cE '^P[0-9]{2}\b.*\bPASS$' "$out" || true)
got_fail=$(grep -cE '^P[0-9]{2}\b.*\bFAIL$' "$out" || true)

echo "F-tests rejected: $got_f / $want_f"
echo "P-tests PASS:     $got_pass / $want_p"
grep -E '^P[0-9]{2}\b' "$out" | sed 's/^/  /' || true

if [ "$got_f" -ne "$want_f" ] || [ "$got_pass" -ne "$want_p" ] || [ "$got_fail" -ne 0 ]; then
  echo "constraint tests FAILED; errors from MySQL:"
  sed 's/^/  /' "$err"
  exit 1
fi
echo "constraint tests passed"
