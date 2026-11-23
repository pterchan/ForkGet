# Isolated protocol checks

English · [简体中文](README.zh-CN.md)

Run from the repository root with Docker Compose, OpenSSL and Python 3:

```sh
FG_PROTOCOL_REPORT_ROOT="$PWD/target/protocol" make protocol-test ENGINE=all
```

Select `mysql`, `postgresql`, `tidb` or `mongodb` to run a single engine. The
runner builds pinned driver images, creates disposable native services and
starts isolated frontend fixtures on loopback. It generates temporary
credentials/certificates and removes its own containers and volumes.

[drivers.json](drivers.json) defines the pinned client versions and required
cases. SQL checks include verified TLS, authentication, admitted queries,
prepared execution and transaction behavior. Raw checks exercise framing,
error codes, handle ownership, PostgreSQL portal suspension, cancellation and
COPY output. The MongoDB fixture uses its explicitly limited standalone
loopback frontend; its driver checks do not substitute for full branch tests.

The frontend identity is `p1_user`, and the fixture branch is `p1-fixture`.
These are test identities. The runner creates their secrets at execution time.
The SQL service role can read the seed relation and insert into a separate
rollback witness. See [the support matrix](../../doc/support-matrix.md) for
product behavior and [the limitations](../../doc/limitations.md) for boundaries.

## Protocol sources and licenses

The Rust codecs and authentication exchanges implement public protocol
specifications. Independent driver programs run in separate test containers;
the fixture's Rust dependencies are checked by `make license-audit`.

| Area | Primary specification |
|---|---|
| MySQL packets, capabilities, commands and results | [Classic client/server protocol](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html) |
| MySQL caching SHA-2 authentication | [Authentication exchange](https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_caching_sha2_authentication_exchanges.html) |
| PostgreSQL framing, sessions and cancellation | [Message formats](https://www.postgresql.org/docs/16/protocol-message-formats.html), [message flow](https://www.postgresql.org/docs/16/protocol-flow.html) |
| PostgreSQL SCRAM and TLS | [PostgreSQL SASL](https://www.postgresql.org/docs/16/sasl-authentication.html), [RFC 5802](https://www.rfc-editor.org/rfc/rfc5802), [RFC 7677](https://www.rfc-editor.org/rfc/rfc7677) |

TLS uses rustls/tokio-rustls with the ring provider. Existing Rust libraries
provide hashing, HMAC, PBKDF2, constant-time comparisons and system randomness.
Keep required license notices when redistributing dependencies or images.

Logs and version summaries go to `FG_PROTOCOL_REPORT_ROOT`. A protocol fixture
pass covers its fixed admission surface; it does not establish full product
lifecycle, arbitrary client compatibility or production-release qualification.
