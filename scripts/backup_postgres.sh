#!/usr/bin/env sh
set -eu

compose_files="-f docker-compose.yml"
out_dir="${BACKUP_DIR:-backups/postgres}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out_dir"

container="$(docker compose $compose_files ps -q postgres)"
if [ -z "$container" ]; then
  echo "Postgres container is not running. Start the stack first."
  exit 1
fi

docker exec "$container" pg_dump -U "${POSTGRES_USER:-app}" -d "${POSTGRES_DB:-threat_risk}" > "$out_dir/threat_risk_$timestamp.sql"
echo "$out_dir/threat_risk_$timestamp.sql"
