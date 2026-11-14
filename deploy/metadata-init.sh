#!/bin/sh
set -eu
case "$FG_METADATA_RUNTIME_PASSWORD" in *[!a-f0-9]*|'') exit 1;; esac
psql -q -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE fg_meta_runtime LOGIN PASSWORD '$FG_METADATA_RUNTIME_PASSWORD';
GRANT CONNECT ON DATABASE forkget TO fg_meta_runtime;
SQL
