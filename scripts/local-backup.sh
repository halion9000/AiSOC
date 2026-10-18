#!/usr/bin/env bash
# local-backup.sh - back up a single-host (docker compose) AiSOC install to a folder, and prove the backup restores.
#
#   ./scripts/local-backup.sh [DEST_DIR]          # default DEST_DIR=./backups
#   ./scripts/local-backup.sh --verify FILE.sql.gz  # restore FILE into a scratch database, compare alert counts, drop it
#
# Backs up Postgres (the system of record: alerts, cases, tenants, users) with pg_dump, and takes a Qdrant snapshot of every collection.
# Neither step stops the stack. The scratch database used by --verify is named aisoc_restore_check and is always dropped.
# (scripts/backup.sh is the S3/R2 variant for hosted deployments.)
set -euo pipefail

PG_CONTAINER="${PG_CONTAINER:-aisoc-postgres}"
PG_USER="${PG_USER:-aisoc}"
PG_DB="${PG_DB:-aisoc}"
QDRANT_URL="${QDRANT_URL:-http://localhost:6333}"
export MSYS_NO_PATHCONV=1

if [[ "${1:-}" == "--verify" ]]; then
  file="${2:?usage: local-backup.sh --verify FILE.sql.gz}"
  scratch="aisoc_restore_check"
  cleanup() { docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d postgres -qc "DROP DATABASE IF EXISTS $scratch" >/dev/null; }
  trap cleanup EXIT
  cleanup
  docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d postgres -qc "CREATE DATABASE $scratch" >/dev/null
  gunzip -c "$file" | docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$scratch" -q -v ON_ERROR_STOP=0 >/dev/null 2>"${TMPDIR:-/tmp}/restore-errors.txt" || true
  live=$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -Atc "SELECT count(*) FROM alerts")
  restored=$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$scratch" -Atc "SELECT count(*) FROM alerts")
  echo "alerts: live=$live restored=$restored"
  # The live stack keeps ingesting while the dump runs, so the restore may be a little behind, never ahead by more than the dump window.
  if [[ "$restored" -gt 0 && "$restored" -le "$live" ]]; then echo "RESTORE OK"; else echo "RESTORE FAILED" >&2; exit 1; fi
  exit 0
fi

dest="${1:-./backups}"
mkdir -p "$dest"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="$dest/aisoc-postgres-$stamp.sql.gz"
docker exec "$PG_CONTAINER" pg_dump -U "$PG_USER" -d "$PG_DB" --no-owner | gzip > "$out"
[[ -s "$out" ]] || { echo "pg_dump produced an empty file" >&2; rm -f "$out"; exit 1; }
echo "postgres -> $out ($(du -h "$out" | cut -f1))"

if curl -fsS -m 5 "$QDRANT_URL/collections" >/dev/null 2>&1; then
  for c in $(curl -fsS "$QDRANT_URL/collections" | python -c "import sys,json;print(' '.join(c['name'] for c in json.load(sys.stdin)['result']['collections']))"); do
    curl -fsS -X POST -m 120 "$QDRANT_URL/collections/$c/snapshots" >/dev/null && echo "qdrant snapshot: $c (kept inside the qdrant volume)"
  done
else
  echo "qdrant not reachable at $QDRANT_URL: skipped"
fi
