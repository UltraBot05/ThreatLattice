#!/bin/bash
# 05_grants.sh: least-privilege MySQL account for the Next.js app.
#
# Runs once, inside the mysql container, when the data volume is first created
# (docker-entrypoint runs *.sh and *.sql files in /docker-entrypoint-initdb.d
# in name order). It is a shell script, not .sql, so the password comes from
# the MYSQL_APP_PASSWORD environment variable instead of being written into
# the repository.
#
# Why least privilege: the web app only reads and writes rows and calls our
# procedures/functions. It can never CREATE, ALTER, DROP or GRANT, so a bug or
# an injection in the app cannot change the schema. The ETL scripts use root.
# The entrypoint may *source* this file, so only `set -e` (no -u / exit).
set -e

: "${MYSQL_APP_USER:?MYSQL_APP_USER is not set}"
: "${MYSQL_APP_PASSWORD:?MYSQL_APP_PASSWORD is not set}"
: "${MYSQL_DATABASE:?MYSQL_DATABASE is not set}"

mysql --protocol=socket -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS '${MYSQL_APP_USER}'@'%' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_APP_USER}'@'%';
FLUSH PRIVILEGES;
SQL

echo "05_grants.sh: created ${MYSQL_APP_USER} with SELECT, INSERT, UPDATE, DELETE, EXECUTE on ${MYSQL_DATABASE}.*"
