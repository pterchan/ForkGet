# Private-config native Dumpling launcher

English · [简体中文](README.zh-CN.md)

`fg-dumpling-run` imports PingCAP's unmodified Dumpling implementation at
TiDB v8.5.8, commit `8b857efa20363d50a8fa2ea7dd9809a85a61b115`.
It configures native snapshot/data-only SQL export without exposing the source
password in a process command line. It does not implement another dump format
or read/write the source through a custom exporter.

Build with Go 1.25.12 using `sh tools/dumpling/build.sh /absolute/output/fg-dumpling-run`.
The script downloads the exact upstream source into the user's cache and builds
inside that module, preserving its `replace` directives and committed `go.sum`.
Install the executable on the operator's PATH. `fg-control snapshot capture`
creates the private configuration; it is not a public connection-file format.
`--version` reports the launcher version and pinned upstream revision.

Native output and diagnostic files contain user data. The parent capture job
creates and retains them in a private directory; never publish captures or
native diagnostic logs. The native Dumpling CLI takes passwords as command
arguments, so it cannot replace this launcher in the authenticated capture path.

Upstream source and license: [PingCAP Dumpling](https://github.com/pingcap/tidb/tree/8b857efa20363d50a8fa2ea7dd9809a85a61b115/dumpling)
(Apache-2.0). Dependency versions and checksums come from that pinned source.
