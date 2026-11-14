#!/bin/sh
set -eu
engine=$1
purpose=$2

if [ "$purpose" = health ]; then
    case "$engine" in
        mysql)
            MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql --no-defaults --protocol=TCP \
                -h127.0.0.1 -uroot --ssl-mode=REQUIRED -Nse 'SELECT 1'
            ;;
        postgresql)
            PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=require psql -XAt \
                -h127.0.0.1 -U postgres -d "$POSTGRES_DB" -c 'SELECT 1'
            ;;
        tidb)
            curl -sf http://127.0.0.1:10080/status
            ;;
    esac
    exit
fi

case "$engine" in
    mysql) owner=mysql ;;
    postgresql) owner=postgres ;;
    tidb) owner=root ;;
    *) exit 2 ;;
esac
install -d -o "$owner" -g "$owner" -m 0700 /run/forkget-tls
install -o "$owner" -g "$owner" -m 0600 "/certs/$purpose.key" /run/forkget-tls/server.key
install -o "$owner" -g "$owner" -m 0644 "/certs/$purpose.pem" /run/forkget-tls/server.pem
install -o "$owner" -g "$owner" -m 0644 /certs/backend-ca.pem /run/forkget-tls/ca.pem

case "$engine" in
    mysql)
        exec docker-entrypoint.sh mysqld --bind-address=0.0.0.0 \
            --ssl-cert=/run/forkget-tls/server.pem --ssl-key=/run/forkget-tls/server.key \
            --ssl-ca=/run/forkget-tls/ca.pem --require-secure-transport=ON
        ;;
    postgresql)
        exec docker-entrypoint.sh postgres -c listen_addresses='*' -c ssl=on \
            -c ssl_cert_file=/run/forkget-tls/server.pem -c ssl_key_file=/run/forkget-tls/server.key
        ;;
    tidb)
        # TiDB takes server TLS only through its configuration file.
        cat > /run/forkget-tls/tidb.toml <<EOF
[security]
ssl-ca = "/run/forkget-tls/ca.pem"
ssl-cert = "/run/forkget-tls/server.pem"
ssl-key = "/run/forkget-tls/server.key"
EOF
        exec /tidb-server --config /run/forkget-tls/tidb.toml \
            --store=unistore --path="" -P 4000 --status=10080
        ;;
esac
