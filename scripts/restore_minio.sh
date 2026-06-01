#!/usr/bin/env sh
set -eu

if [ "${1:-}" = "" ]; then
  echo "Usage: scripts/restore_minio.sh backups/minio/YYYYMMDDTHHMMSSZ"
  exit 1
fi

minio_container="$(docker compose -f docker-compose.yml ps -q minio)"
if [ -z "$minio_container" ]; then
  echo "MinIO container is not running. Start the stack first."
  exit 1
fi

docker run --rm --volumes-from "$minio_container" -v "$(pwd)/$1:/restore:ro" alpine:3.20 sh -c "cp -a /restore/. /data/"
echo "Restored $1"
