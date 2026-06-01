#!/usr/bin/env sh
set -eu

out_dir="${BACKUP_DIR:-backups/minio}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out_dir/$timestamp"

minio_container="$(docker compose -f docker-compose.yml ps -q minio)"
if [ -z "$minio_container" ]; then
  echo "MinIO container is not running. Start the stack first."
  exit 1
fi

docker run --rm --volumes-from "$minio_container" -v "$(pwd)/$out_dir/$timestamp:/backup" alpine:3.20 sh -c "cp -a /data/. /backup/"
echo "$out_dir/$timestamp"
