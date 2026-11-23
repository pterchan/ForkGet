# Forkget Console

English · [简体中文](README.zh-CN.md)

The static Console for **Forkget 0.1.1**, served by the control
service. See the
[Console guide](../../doc/console.md) for normal use and
[installation](../../doc/install.md) for packaged deployment. Runtime serving
requires no Vite or Node.js process.

For frontend development, use Node.js 24.19.0 and the committed npm lockfile:

```sh
npm ci
npm run dev
```

Open <http://127.0.0.1:4193/>. `FG_CONSOLE_CONTROL_URL` defaults to
`http://127.0.0.1:8081` and accepts loopback HTTP origins. The development proxy
forwards only admitted public API paths. Remote control uses an SSH tunnel.

```sh
npm run check
npm test
npm run build
npx playwright install chromium
npm run test:browser
```

Static output is `build/`. Set `FG_CONSOLE_DIR` before starting a standalone
control service; unset disables static serving. Keep assets read-only, with no
credentials, captures or source maps in that directory. Preview is a local
review server, not a deployment server.

Tokens stay in memory. Explicit demo mode never replaces a failed live request.
The UI keeps access, layout, leases, policy and audit-delivery health separate.
Diff downloads are inspection views, not complete replay artifacts. Nine language
translations and integer-safe JSON are included.

Ordinary browser checks skip two optional live-fixture cases. A live fixture
must use disposable native databases because it creates, changes and drops
branches. A skipped live case is not a verified backend workflow. Follow the
[contribution guide](../../CONTRIBUTING.md) when changing protocol or write flows.
