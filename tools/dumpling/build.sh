#!/bin/sh
# Build inside the pinned upstream module so its own replacements and go.sum
# govern native dependencies; a standalone import loses those replacements.
set -eu
revision=8b857efa20363d50a8fa2ea7dd9809a85a61b115
launcher=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cache="${XDG_CACHE_HOME:-$HOME/.cache}/forkget/native-dumpling/$revision"
source="$cache/source"
mkdir -p "$cache"
if [ ! -f "$source/go.mod" ]; then
    archive="$cache/upstream.tar.gz"
    curl --fail --location --proto '=https' --tlsv1.2 \
        "https://codeload.github.com/pingcap/tidb/tar.gz/$revision" -o "$archive"
    mkdir -p "$source"
    tar -xzf "$archive" --strip-components=1 -C "$source"
fi
mkdir -p "$source/dumpling/forkget-launcher"
cp "$launcher/main.go" "$source/dumpling/forkget-launcher/main.go"
go -C "$source" build -p 2 -trimpath -ldflags="-s -w" -mod=readonly -o "${1:-$launcher/fg-dumpling-run}" ./dumpling/forkget-launcher
