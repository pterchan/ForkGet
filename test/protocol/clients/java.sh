#!/bin/sh
set -eu

# TiDB uses the MySQL driver path, including the truststores.
if [ "$1" = mysql ] || [ "$1" = tidb ]; then
    keytool -importcert -noprompt -alias forkget-fixture -storetype PKCS12 \
        -keystore /tmp/frontend.p12 -storepass:env FG_P1_FRONTEND_PASSWORD -file /p1-tls/frontend-ca.pem
    keytool -importcert -noprompt -alias wrong-fixture -storetype PKCS12 \
        -keystore /tmp/backend.p12 -storepass:env FG_P1_FRONTEND_PASSWORD -file /p1-tls/backend-ca.pem
fi

exec java -Duser.timezone=UTC --class-path '/drivers/*' /suite/Probe.java "$1"
