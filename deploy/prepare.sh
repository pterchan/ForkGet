#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
if [ -e operator.env ] || [ -e private ]; then
    echo 'Deployment settings already exist; preserve them and edit operator.env.' >&2
    exit 1
fi
mkdir private
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
    -subj '/CN=Forkget local frontend CA' -keyout private/ca.key -out private/frontend-ca.pem \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -newkey rsa:3072 -nodes -sha256 -subj '/CN=localhost' \
    -keyout private/frontend.key -out private/frontend.csr >/dev/null 2>&1
cat > private/frontend.cnf <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -sha256 -days 365 -in private/frontend.csr \
    -CA private/frontend-ca.pem -CAkey private/ca.key -set_serial 1 \
    -extfile private/frontend.cnf -out private/frontend.pem >/dev/null 2>&1
rm private/frontend.csr
metadata_admin_password=$(openssl rand -hex 24)
metadata_runtime_password=$(openssl rand -hex 24)
owner_token=$(openssl rand -hex 32)
reviewer_token=$(openssl rand -hex 32)
frontend_password=$(openssl rand -hex 24)
internal_token=$(openssl rand -hex 32)
expires_at=$(( $(date +%s) + 31536000 ))
cat > operator.env <<EOF
FG_METADATA_ADMIN_PASSWORD=$metadata_admin_password
FG_METADATA_RUNTIME_PASSWORD=$metadata_runtime_password
FG_META_DSN=postgresql://fg_meta_runtime:$metadata_runtime_password@127.0.0.1:15432/forkget
FG_META_MIGRATION_DSN=postgresql://fg_meta_admin:$metadata_admin_password@127.0.0.1:15432/forkget
FG_OWNER_TOKEN=$owner_token
FG_REVIEWER_TOKEN=$reviewer_token
FG_INTERNAL_TOKEN=$internal_token
FG_PG_PORT=5432
FG_MYSQL_PORT=3306
FG_CONTROL_ACCOUNTS='[{"user":"owner","token":"$owner_token","expires_at":$expires_at,"allowed_classes":["dev","ci","agent","staging"],"policy_admin":true},{"user":"reviewer","token":"$reviewer_token","expires_at":$expires_at,"allowed_classes":[],"policy_admin":true,"approver_for":["owner"]}]'
FG_FRONTEND_ACCOUNTS='[{"user":"owner","password":"$frontend_password","expires_at":$expires_at}]'
FG_BACKEND_DSN='postgresql://fg_service:REPLACE@127.0.0.1:55433/forkget'
FG_BACKEND_GC_DSN='postgresql://fg_gc:REPLACE@127.0.0.1:55433/forkget'
FG_BRANCH_ADMIN_DSN='postgresql://fg_branch_admin:REPLACE@127.0.0.1:55433/forkget'
FG_BACKEND_ADMIN_DSN='postgresql://operator:REPLACE@127.0.0.1:55433/forkget'
FG_BACKEND_CA_HOST=./private/backend-ca.pem
FG_SOURCE_CA_HOST=./private/backend-ca.pem
EOF
echo 'Created private frontend TLS material and operator.env. Configure the dedicated native target connections and CA before starting.'
