#!/bin/sh
set -eu

case "${1:-}" in
    health)
        if [ "$FG_PROTOCOL_ENGINE" = mongodb ]; then
            # The runner records this output as the native engine version.
            mongosh --quiet --eval 'db.version()' && exit 0
            exit 1
        fi
        sql='SELECT VERSION()'
        ;;
    observe)
        case "$FG_PROTOCOL_ENGINE" in
            mysql|tidb) sessions="SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER = 'p1_service' AND ID <> CONNECTION_ID()" ;;
            postgresql) sessions="SELECT COUNT(*) FROM pg_catalog.pg_stat_activity WHERE usename = 'p1_service' AND pid <> pg_backend_pid()" ;;
            # MongoDB: no SQL observer; the probe checks its own effects.
            mongodb) echo "0:0"; exit 0 ;;
        esac
        sql="SELECT CONCAT((SELECT COUNT(*) FROM fixture_events), ':', ($sessions))"
        ;;
    '') sql= ;;
    *) exit 2 ;;
esac

if [ -n "${sql:-}" ]; then
    case "$FG_PROTOCOL_ENGINE" in
        mysql|tidb)
            # The TiDB image has no client: the compose client sidecar runs
            # this script against the shared native network.
            MYSQL_PWD="$FG_P1_BACKEND_PASSWORD" mysql --no-defaults --protocol=TCP \
                --host=127.0.0.1 --port="${FG_P1_NATIVE_PORT:-3306}" --user=p1_service \
                --database=p1_native --ssl-mode=VERIFY_IDENTITY \
                --ssl-ca=/p1-tls/backend-ca.pem \
                --batch --skip-column-names --execute="$sql"
            ;;
        postgresql)
            PGPASSWORD="$FG_P1_BACKEND_PASSWORD" PGSSLMODE=verify-full \
                PGSSLROOTCERT=/p1-tls/backend-ca.pem psql -XAt -h localhost \
                -U p1_service -d p1_native -c "$sql"
            ;;
    esac
    exit
fi

case "$FG_PROTOCOL_ENGINE" in
    mysql)
        install -d -o mysql -g mysql -m 0700 /run/p1-native-tls
        install -o mysql -g mysql -m 0600 /p1-tls/backend.key /run/p1-native-tls/
        install -o mysql -g mysql -m 0644 /p1-tls/backend.pem /p1-tls/backend-ca.pem /run/p1-native-tls/
        exec docker-entrypoint.sh mysqld --bind-address=127.0.0.1 \
            --ssl-cert=/run/p1-native-tls/backend.pem --ssl-key=/run/p1-native-tls/backend.key \
            --ssl-ca=/run/p1-native-tls/backend-ca.pem --require-secure-transport=ON
        ;;
    postgresql)
        install -d -o postgres -g postgres -m 0700 /run/p1-native-tls
        install -o postgres -g postgres -m 0600 /p1-tls/backend.key /run/p1-native-tls/
        install -o postgres -g postgres -m 0644 /p1-tls/backend.pem /run/p1-native-tls/
        exec docker-entrypoint.sh postgres -c listen_addresses=127.0.0.1 -c ssl=on \
            -c ssl_cert_file=/run/p1-native-tls/backend.pem -c ssl_key_file=/run/p1-native-tls/backend.key
        ;;
    mongodb)
        # mongo:7 ships mongosh; the image entrypoint handles auth setup.
        exec docker-entrypoint.sh mongod --bind_ip 127.0.0.1
        ;;
    tidb)
        # TiDB takes server TLS only through its config file and has no
        # entrypoint hook; fixture initialization runs from the compose
        # init service.
        mkdir -p /run/p1-native-tls
        install -m 0600 /p1-tls/backend.key /run/p1-native-tls/
        install -m 0644 /p1-tls/backend.pem /p1-tls/backend-ca.pem /run/p1-native-tls/
        cat > /run/p1-native-tls/tidb.toml <<EOF
[security]
ssl-ca = "/run/p1-native-tls/backend-ca.pem"
ssl-cert = "/run/p1-native-tls/backend.pem"
ssl-key = "/run/p1-native-tls/backend.key"
EOF
        exec /tidb-server --config /run/p1-native-tls/tidb.toml \
            --store=unistore --path="" -P 4000 --status=10080 --advertise-address=127.0.0.1
        ;;
esac
