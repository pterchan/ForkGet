# Security and credentials

Keep control and drain listeners on loopback. Remote owners use an authenticated
SSH tunnel. The Console's public API alias retains owner authorization; internal
proxy/control routes have no public alias. A deployment has one dedicated native
serving backend. Never point it at the production source database.

Owner API tokens, frontend database passwords, internal tokens, native service
accounts, collectors, branch administrators and migration accounts have different
roles. Keep them separate. Use the same frontend username as the API owner, but
never reuse that owner's token as a database password. Independent approval and
budget review require a different authorized principal.

Verify TLS and hostname identity on both data hops with the correct CA. Do not
disable verification to work around a failed connection. Protect private keys,
environment files, captures and result artifacts with appropriate permissions.
Rotate credentials and certificates before expiry. The Console keeps API tokens
in memory and clears them on reload/sign-out; example mode is explicitly selected.

New branches reject writes by default. Budgets count direct row touches per
transaction; they are not task-wide spending controls. Requests alone authorize
no writes. Expiry, policy changes and grant revocation invalidate effective
transaction context. Begin a fresh transaction after refusal; a later approval
does not resurrect rolled-back work.

A lost response is not proof of rollback. Inspect the native/audit state before
retrying a mutation. Known native success can survive a delivery outage while
new protected writes pause. Only delivery is retried automatically. Use the
[audit recovery procedure](audit-recovery.md) for orphaned attempts and storage
restore; never delete audit facts or rebuild private witnesses by hand.

Before sharing diagnostics, remove credentials, SQL parameters, application data
and physical object details. Audit payloads omit statement/document values, but
exported results contain application data. Do not publish environment dumps,
expanded Compose output or raw native logs. Keep source backup privileges
separate from serving administration; [source recipes](source-backup-roles.md)
include native visibility/backup privileges beyond ordinary data SELECT.

Report a potential vulnerability privately through a maintainer channel available
to you. Do not include secrets in public issues. Experimental version 0.0.9
does not imply an independent security certification or production qualification.
The [TiDB correctness limitation](limitations.md) remains an unresolved blocker
for a qualified four-engine release.
