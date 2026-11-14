# Install and run locally

These instructions build experimental **Forkget 0.0.9** from source for local
evaluation with disposable, non-production data. Read the
[known limitations](limitations.md), including the unresolved TiDB concurrent-
foreign-key failure, before selecting a workload.

The supplied deployment targets Linux x86_64 with Docker Engine, the Compose
plugin, OpenSSL, a POSIX shell, curl and GNU timeout. Windows users can run it
inside WSL with a Linux Docker Engine. It uses host networking and loopback
listeners. Check port availability before starting it.

## Release packages

The [v0.0.9 prerelease](https://github.com/pterchan/ForkGet/releases/tag/v0.0.9)
provides source, Linux x86_64 binaries, Console resources, dependency notices and
`SHA256SUMS`. Verify the downloaded files before extracting them:

```sh
sha256sum --check SHA256SUMS --ignore-missing
```

The control binary requires glibc 2.39; proxy and CLI require glibc 2.34.
The binary package contains `bin/fg-control`, `bin/fg-proxy` and `bin/forkget`.
Put these files on `PATH`, then configure the deployment, TLS and dedicated
native serving backend as described below. Retain the MIT `LICENSE` and the
accompanying dependency notices. The Console package's `build` directory can
be served by setting `FG_CONSOLE_DIR` before `fg-control serve`.

Container images are not distributed in this experimental release. A local
image can be built from the provided source and Dockerfile.

## Build from source

Clone the matching version:

```sh
git clone https://github.com/pterchan/ForkGet.git
cd ForkGet
git checkout v0.0.9
sh deploy/prepare.sh
```

Preparation creates private settings and a frontend CA/certificate without
overwriting an existing deployment. The certificate covers localhost and
127.0.0.1. Keep its private keys and `deploy/operator.env` out of version control.

## Configure a dedicated serving backend

The Compose template configures one SQL engine and metadata PostgreSQL. It does
not create the native serving database. Prepare a dedicated PostgreSQL or MySQL
backend and separate native service, collector and branch-administrator accounts
using the [deployment guide](../deploy/README.md). The source database is a
separate input; never configure the production source as the serving backend.

Replace every placeholder in `deploy/operator.env`. Configure all four native
DSNs for the same serving endpoint, the correct default database and their
separate account identities. Copy its CA to the configured backend CA path.
Configure the source CA separately when it differs. Never print expanded
Compose configuration or publish environment files and captures.

```sh
export FG_BUILD_REVISION="$(git rev-parse HEAD)"
sh deploy/run.sh initialize
```

Initialization builds the image, starts metadata, applies migrations and
installs restricted metadata-runtime grants. The build packages the Console
and pinned native import tools. A host Node.js server is not required at runtime.

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
This Compose walkthrough covers SQL. MongoDB has a separate native capture
workflow and requires a quiescent copy or consistent backup. TiDB's
[concurrent foreign-key blocker](limitations.md) remains unresolved.

## Start, check and connect

```sh
sh deploy/run.sh up
timeout 30 sh -c '
  while :; do
    control=$(curl --silent --output /dev/null --write-out "%{http_code}" --connect-timeout 1 --max-time 1 http://127.0.0.1:8081/health/ready || :)
    proxy=$(curl --silent --output /dev/null --write-out "%{http_code}" --connect-timeout 1 --max-time 1 http://127.0.0.1:8082/healthz || :)
    if [ "$control" = 204 ] && [ "$proxy" = 204 ]; then exit 0; fi
    sleep 1
  done
' || { echo 'Forkget did not become ready within 30 seconds.' >&2; exit 1; }
sh deploy/run.sh operator fg-control doctor
sh deploy/run.sh operator forkget capabilities
sh deploy/run.sh operator forkget fork first-task
```

Stop if the bounded readiness wait fails. Doctor checks the running proxy's
actual audit-delivery health, so run it after both services become ready.
Poll the returned branch ID with `forkget status --id <id>` until active.
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
