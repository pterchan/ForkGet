# Web Console

English · [简体中文](console.zh-CN.md)

Compose serves the packaged Console at <http://127.0.0.1:8081/>. For a remote
deployment, keep control on loopback and forward it explicitly:

```sh
ssh -N -L 18081:127.0.0.1:8081 operator@your-host
```

Open <http://127.0.0.1:18081/>. Forward the database frontend separately, and
verify its TLS name and CA. Never expose the control or drain listener as a
public endpoint. The Console's `/api/v1/` endpoints are the existing public
API with the same owner authorization; internal APIs have no `/api` alias.

Sign in with an owner API token. It remains in memory and is cleared on reload
or sign-out. It is never persisted in browser storage. **Explore demo** is an
explicit example mode; live failures never silently switch to example data.

1. Create a branch. Read-only is the default; choose writable explicitly when
   the snapshot and class permit it. Provisioning is asynchronous.
2. Inspect access, storage layout, deadline, lease version, lifecycle phase and
   effective policy. These are independent fields. A legacy MongoDB layout or
   `mode` value alone does not determine actual write permission.
   Temporary budget grants show their own expiry separately from the branch
   deadline; effective limits refresh while a temporary grant is present.
3. Copy a connection example and run it in a POSIX shell (WSL on Windows).
   Set database host, port, frontend user and CA in Preferences. The frontend
   password is distinct from the owner token. MongoDB uses an independent
   direct client pool for each branch, with retryable writes disabled.
4. Inspect typed changes and branch-scoped audit events. A **Diff JSON**
   download is the displayed diff, not a complete replay artifact. Use the
   [result workflow](workflow.md) to save and replay complete changes.
5. Explicit statement approval policies can pause a mutation. A different
   authorized reviewer can inspect the immutable branch ID and approve or deny
   the pending request. Default Agent policies execute within hard budgets.
   Temporary budget increases use the separate `forkget budget` CLI workflow.
6. Inspect audit delivery health. Pending delivery can include a healthy open
   transaction; the separate paused-writes field reports actual backpressure.
   Follow [audit recovery](audit-recovery.md) after an unresolved failure.
7. Inspect expiry and deletion progress. Dropping drains sessions before
   cleanup. A failed cleanup remains visible; deleting a UI record is not proof
   that native objects were reclaimed.

The Console supports English, Simplified/Traditional Chinese, Japanese, Korean,
French, German, Spanish and Italian. Dates use the timezone shown in
Preferences. SQL, object names, IDs and FG codes are preserved. Integer values
retain 64-bit precision. Keyboard dialogs, responsive navigation and delayed
responses are covered by dedicated browser checks.

For standalone binaries, build `apps/console` using `npm ci && npm run build`
and set `FG_CONSOLE_DIR` to `build` before `fg-control serve`. It defaults to
unset, disabling static delivery. Keep that directory read-only for the
service account. Source maps, private files and unbundled source are not served.
