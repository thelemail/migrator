#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="${1:-$ROOT/dist/engine}"

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"
for target in darwin/arm64 darwin/amd64 linux/amd64 windows/amd64; do
  os="${target%%/*}"
  arch="${target##*/}"
  name="migrator-engine-${os}-${arch}"
  [ "$os" = "windows" ] && name="${name}.exe"
  "$ROOT/scripts/build-engine.sh" "$os" "$arch" "$OUTDIR/$name"
done
(cd "$OUTDIR" && find . -type f -name 'migrator-engine-*' | sed 's|^\./||' | LC_ALL=C sort | xargs shasum -a 256) > "$OUTDIR/ENGINE-SHA256SUMS"
cat "$OUTDIR/ENGINE-SHA256SUMS"
