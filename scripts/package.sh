#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:?set VERSION}"
TARGET="${1:?usage: package.sh linux|windows}"
OUTDIR="${OUTDIR:-dist}"
mkdir -p "$OUTDIR"

case "$TARGET" in
  linux)
    stage="$(mktemp -d)/thelemail-migrator-${VERSION}"
    mkdir -p "$stage"
    cp target/release/thelemail-migrator target/release/migrator-engine "$stage/"
    cp assets/thelemail-migrator.desktop assets/AppIcon.png "$stage/"
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' \
      -C "$(dirname "$stage")" -czf "$OUTDIR/thelemail-migrator-${VERSION}-linux-x86_64.tar.gz" "$(basename "$stage")"
    ;;
  windows)
    stage="$(mktemp -d)/Thelemail Migrator"
    mkdir -p "$stage"
    cp target/release/thelemail-migrator.exe target/release/migrator-engine.exe "$stage/"
    (cd "$(dirname "$stage")" && 7z a -tzip "$OLDPWD/$OUTDIR/thelemail-migrator-${VERSION}-windows-x86_64.zip" "$(basename "$stage")" > /dev/null)
    ;;
  *)
    echo "unknown target $TARGET" >&2
    exit 1
    ;;
esac
ls -l "$OUTDIR"
