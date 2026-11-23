#!/usr/bin/env bash
set -euo pipefail

TARGET_OS="${1:?usage: build-engine.sh GOOS GOARCH OUTPUT}"
TARGET_ARCH="${2:?usage: build-engine.sh GOOS GOARCH OUTPUT}"
OUTPUT="${3:?usage: build-engine.sh GOOS GOARCH OUTPUT}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)}"
API="${API:-https://api.thelemail.com}"
WEB="${WEB:-https://app.thelemail.com}"
AUTH="${AUTH:-https://auth.thelemail.com}"
CONFIG=github.com/thelemail/migrator/engine/internal/config

cd "$ROOT"
mkdir -p "$(dirname "$OUTPUT")"
case "$OUTPUT" in
  /*) ;;
  *) OUTPUT="../$OUTPUT" ;;
esac

cd engine
CGO_ENABLED=0 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" GOFLAGS=-mod=readonly go build -trimpath -buildvcs=false \
  -ldflags "-s -w -buildid= -X ${CONFIG}.Version=${VERSION} -X ${CONFIG}.API=${API} -X ${CONFIG}.Web=${WEB} -X ${CONFIG}.Auth=${AUTH}" \
  -o "$OUTPUT" .
