#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ ! -f operator.env ]; then echo 'Run sh deploy/prepare.sh first.' >&2; exit 1; fi
compose() { docker compose --env-file operator.env --file compose.yaml "$@"; }
case "${1:-}" in
    initialize)
        compose up -d --wait metadata
        compose build
        compose run --rm operator sh -ec 'fg-control migrate; PGPASSWORD="$FG_METADATA_ADMIN_PASSWORD" psql -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -p 15432 -U fg_meta_admin -d forkget -f /opt/forkget/runtime-grants.sql'
        ;;
    up) compose up -d metadata control proxy;;
    down) compose down;;
    operator)
        shift
        case "${1:-}/${2:-}/${3:-}" in
            fg-control/snapshot/import|fg-control/snapshot/retry-cleanup|fg-control/bootstrap/*|fg-control/refresh/*|fg-control/retire/*)
                compose run --rm operator sh -ec 'export FG_META_DSN="$FG_META_MIGRATION_DSN"; exec "$@"' sh "$@"
                ;;
            *) compose run --rm operator "$@";;
        esac
        ;;
    *) echo 'Usage: sh deploy/run.sh initialize|up|down|operator COMMAND...' >&2; exit 1;;
esac
