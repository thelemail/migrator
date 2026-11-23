#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}"
API="${API:-https://api.thelemail.com}"
WEB="${WEB:-https://app.thelemail.com}"
AUTH="${AUTH:-https://auth.thelemail.com}"
EXE=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;;
esac

cargo build --release --locked
VERSION="$VERSION" API="$API" WEB="$WEB" AUTH="$AUTH" ./scripts/build-engine.sh "$(go env GOOS)" "$(go env GOARCH)" "target/release/migrator-engine${EXE}"
