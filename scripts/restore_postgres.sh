#!/usr/bin/env sh
set -eu

if [ "${1:-}" = "" ]; then
  echo "Usage: scripts/restore_postgres.sh backups/postgres/threat_risk_YYYYMMDDTHHMMSSZ.sql"
  exit 1
fi

container="$(docker compose -f docker-compose.yml ps -q postgres)"
if [ -z "$container" ]; then
  echo "Postgres container is not running. Start the stack first."
  exit 1
fi

docker exec -i "$container" psql -U "${POSTGRES_USER:-app}" -d "${POSTGRES_DB:-threat_risk}" < "$1"
echo "Restored $1"
