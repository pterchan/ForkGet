# Install and run locally

English · [简体中文](install.zh-CN.md)

Choose a tag from [GitHub Releases](https://github.com/pterchan/ForkGet/releases)
and check its [supported engine profiles](support-matrix.md) and
[known limitations](limitations.md) before selecting a workload. Use disposable,
non-production data to evaluate a prerelease.

For local evaluation of an unpublished candidate, build the supplied candidate
checkout with the Compose walkthrough below. Skip the clone and tag checkout
steps and run `sh deploy/prepare.sh` from the supplied checkout's root. For a published tag, use the
guides from that tag.

## Download a release

Use the source archive, binary archive, Console archive and dependency notices
listed for the same tag. Download that tag's `SHA256SUMS` and run the following
command in the download directory before extracting the archives.

```sh
sha256sum --check SHA256SUMS
```

Verify that every downloaded archive is listed and reports `OK`. Retain the
MIT `LICENSE` and accompanying dependency notices. Review the source and
build revision on the release page before running the binaries.

The published Linux binaries target x86_64. Control requires glibc 2.39
and proxy and CLI require glibc 2.34. To use the bundled Console, extract
its separate archive and set `FG_CONSOLE_DIR` to its `build` directory before
starting `fg-control serve`. Check the assets for the chosen tag before
assuming a container image is available.

## Run the downloaded binaries with PostgreSQL

Put the extracted `bin` directory on `PATH`. Use the matching source archive for
the deployment SQL and certificate-generation script. Install OpenSSL, Linux
util-linux (`setpriv`) and the PostgreSQL client tools on the operator host.
For this source version, snapshot commands require `pg_dump` and `pg_restore`
from PostgreSQL 16.15. Check their versions before capture.

Run `sh deploy/prepare.sh` to generate the frontend TLS material and account
settings. Configure the [native serving accounts](../deploy/README.md), a
separate metadata PostgreSQL instance, and a separate
[source backup account](source-backup-roles.md#postgresql-16). Use matching
UTF-8 libc locale settings on the source and serving databases. PostgreSQL
import also needs a native administrator who can create the staging database.
Prepare the metadata migration account with DDL privileges and the
`fg_meta_runtime` login with CONNECT to the dedicated metadata database.
Put secrets in private settings for the process that needs them. Set
host paths and loopback addresses before starting the services.

| Process | Settings |
| --- | --- |
| Metadata migration | `FG_META_MIGRATION_DSN` for the migration account. Apply `deploy/runtime-grants.sql` as the metadata administrator after `fg-control migrate`. |
| Snapshot operator | `FG_META_DSN` and `FG_META_MIGRATION_DSN`, the four native DSNs in the [deployment guide](../deploy/README.md#private-configuration), `FG_BACKEND_CA`, `FG_SOURCE_CA`, `FG_SOURCE_DSN` and `FG_STATE_DIR`. Use the migration DSN as `FG_META_DSN` for import. |
| Control | Restricted `FG_META_DSN`, `FG_BACKEND_GC_DSN`, `FG_BRANCH_ADMIN_DSN`, `FG_BACKEND_CA`, `FG_CONTROL_ACCOUNTS`, `FG_INTERNAL_TOKEN` and an absolute private `FG_STATE_DIR` shared with the operator. Set `FG_CONTROL_LISTEN=127.0.0.1:8081`, `FG_PROXY_CONTROL_URL=http://127.0.0.1:8082` and optional `FG_CONSOLE_DIR`. |
| Proxy | Restricted `FG_BACKEND_DSN`, `FG_BACKEND_CA`, `FG_FRONTEND_ACCOUNTS`, `FG_TLS_CERT`, `FG_TLS_KEY` and the same `FG_INTERNAL_TOKEN`. Set `FG_CONTROL_URL=http://127.0.0.1:8081`, `FG_PROXY_CONTROL_LISTEN=127.0.0.1:8082` and `FG_LISTEN_PG` to a free loopback address and port. |
| Owner CLI | `FG_CONTROL_URL=http://127.0.0.1:8081` and `FG_OWNER_TOKEN`. |

Set the matching role names `FG_BACKEND_SERVICE_USER=fg_service`,
`FG_BACKEND_GC_USER=fg_gc` and `FG_BRANCH_ADMIN_USER=fg_branch_admin` in the
control, proxy and operator environments. Use the dedicated native administrator
and source backup credentials only in the operator environment. TLS paths
must point to the corresponding CA, certificate and key on the host.

With the operator environment set, inspect, capture and import one admitted
source schema. Use a new directory under a private workspace.

```sh
fg-control snapshot inspect --source-env FG_SOURCE_DSN --schema commerce \
  --name commerce-v1 --output /private/commerce-inspection.json
fg-control snapshot capture --source-env FG_SOURCE_DSN --schema commerce \
  --name commerce-v1 --output /private/commerce
FG_META_DSN="$FG_META_MIGRATION_DSN" fg-control snapshot import --input /private/commerce
```

Start `fg-control serve` and `fg-proxy` in their separate environments.
Once both [readiness checks](#wait-for-readiness) return HTTP 204, run
`fg-control doctor` in a temporary environment with the control and proxy
settings. Keep source, native administrator and metadata migration credentials
out of this environment. Run `forkget capabilities` in the owner environment.
Create a workspace with `forkget fork first-task`, wait for it to become active
and follow the
[native connection examples](connecting.md).

## Build from source with Compose

The Compose walkthrough uses Linux x86_64 with Docker Engine and its Compose
plugin, OpenSSL, a POSIX shell, curl and GNU timeout. Windows users can run it
inside WSL with a Linux Docker Engine. It uses host networking and loopback
listeners. Check port availability before starting it.

Extract the verified source archive, or check out the same release tag when
cloning. Set `RELEASE_TAG` to the tag you selected before running these commands.

```sh
git clone https://github.com/pterchan/ForkGet.git
cd ForkGet
git checkout --detach "${RELEASE_TAG:?Set RELEASE_TAG to the selected GitHub release tag}"
sh deploy/prepare.sh
```

Preparation creates private settings and a frontend CA and certificate for
localhost and 127.0.0.1. It preserves existing deployment files. Keep private
keys and `deploy/operator.env` out of version control.

## Configure a dedicated serving backend

The Compose template configures one SQL engine and metadata PostgreSQL. It does
not create the native serving database. Prepare a dedicated PostgreSQL or MySQL
backend and separate native service, collector and branch-administrator accounts
using the [deployment guide](../deploy/README.md). The source database is a
separate input; never configure the production source as the serving backend.
Run the serving database on the same Linux host. Use a loopback host or IP
covered by the serving certificate, and a port distinct from the proxy's
frontend port. The source can use a separate remote endpoint with its own CA.

Replace every placeholder in `deploy/operator.env`. Configure all four native
DSNs for the same serving endpoint, the correct default database and their
separate account identities. Copy its CA to the configured backend CA path.
Configure the source CA separately when it differs. Never print expanded
Compose configuration or publish environment files and captures.

Set `FG_BUILD_REVISION` to the complete revision from the release page when
building an extracted release archive. In a release or candidate Git checkout, run
`export FG_BUILD_REVISION="$(git rev-parse HEAD)"`.

```sh
sh deploy/run.sh initialize
```

Initialization builds the image, starts metadata, applies migrations and
installs restricted metadata-runtime grants. The build packages the Console
and native import tools. A host Node.js server is not required at runtime.
Ubuntu supplies the PostgreSQL client and MySQL Shell packages. Before capture,
check the installed version with `sh deploy/run.sh operator pg_dump --version`
and `sh deploy/run.sh operator pg_restore --version` for PostgreSQL, or
`sh deploy/run.sh operator mysqlsh --version` for MySQL. Snapshot operations
require PostgreSQL tools 16.15 or MySQL Shell 8.0.36, respectively. If the image
has different PostgreSQL tools, the direct-binary walkthrough above supports
locally installed matching tools. Verify the required MySQL Shell version
in the operator image before attempting a MySQL capture.

## Capture and import one application schema

Load `FG_SOURCE_DSN` privately using an independent source backup account. Use a
native DSN scheme, such as `postgresql://` or `mysql://`, rather than an ORM's
`postgresql+psycopg://` scheme. Set the source CA before running capture.

```sh
docker compose --env-file deploy/operator.env -f deploy/compose.yaml run --rm \
  -e FG_SOURCE_DSN operator fg-control snapshot capture \
  --source-env FG_SOURCE_DSN --schema commerce --name commerce-v1 --output /work/commerce
sh deploy/run.sh operator fg-control snapshot import --input /work/commerce
```

Use your real source schema instead of `commerce`. The output path must be new.
Preflight rejects unsupported objects before activation. MySQL uses the pinned
MySQL Shell dump; PostgreSQL uses native dump/restore staging. See
[source backup roles](source-backup-roles.md) for credentials and visibility.
This Compose walkthrough covers MySQL and PostgreSQL. MongoDB has a separate
native capture workflow and requires a quiescent copy or consistent backup.

## Start the Compose services

```sh
sh deploy/run.sh up
```

## Wait for readiness

Use the same loopback endpoints with Compose or direct binaries.

```sh
timeout 30 sh -c '
  while :; do
    control=$(curl --silent --output /dev/null --write-out "%{http_code}" --connect-timeout 1 --max-time 1 http://127.0.0.1:8081/health/ready || :)
    proxy=$(curl --silent --output /dev/null --write-out "%{http_code}" --connect-timeout 1 --max-time 1 http://127.0.0.1:8082/healthz || :)
    if [ "$control" = 204 ] && [ "$proxy" = 204 ]; then exit 0; fi
    sleep 1
  done
' || { echo 'Forkget did not become ready within 30 seconds.' >&2; exit 1; }
```

Stop if the bounded readiness wait fails. Doctor checks the running proxy's
actual audit-delivery health, so run it after both services become ready.

## Connect to the Compose deployment

```sh
sh deploy/run.sh operator fg-control doctor
sh deploy/run.sh operator forkget capabilities
sh deploy/run.sh operator forkget fork first-task
```

Run `sh deploy/run.sh operator forkget status --id <id>` with the returned
branch ID in place of `<id>`. Repeat until the branch is active.
Use [native connection examples](connecting.md), or open the
[Console](console.md) at <http://127.0.0.1:8081/>.

New branches are read-only. Create writable work explicitly:

```sh
sh deploy/run.sh operator forkget fork write-task --write
```

`sh deploy/run.sh down` stops this project and retains its volumes. Back up
metadata, native serving data and capture/result storage coherently. Deliberately
removing Compose volumes destroys retained data. Read the
[audit upgrade and restore procedure](audit-recovery.md) before changing an
existing deployment.
