#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:?set VERSION}"
TARGET="${1:?usage: package.sh linux|windows}"
OUTDIR="${OUTDIR:-dist}"
mkdir -p "$OUTDIR"

APPIMAGETOOL_URL=https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage
APPIMAGETOOL_SHA256=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
RUNTIME_URL=https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64
RUNTIME_SHA256=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d

fetch() {
  curl -sSfL --proto '=https' -o "$2" "$1"
  echo "$3  $2" | sha256sum -c --quiet -
}

case "$TARGET" in
  linux)
    work="$(mktemp -d)"
    appdir="$work/ThelemailMigrator.AppDir"
    mkdir -p "$appdir/usr/bin"
    cp target/release/thelemail-migrator target/release/migrator-engine "$appdir/usr/bin/"
    cp assets/thelemail-migrator.desktop "$appdir/"
    cp assets/AppIcon.png "$appdir/AppIcon.png"
    ln -s usr/bin/thelemail-migrator "$appdir/AppRun"
    fetch "$APPIMAGETOOL_URL" "$work/appimagetool" "$APPIMAGETOOL_SHA256"
    fetch "$RUNTIME_URL" "$work/runtime" "$RUNTIME_SHA256"
    chmod +x "$work/appimagetool"
    ARCH=x86_64 SOURCE_DATE_EPOCH=0 "$work/appimagetool" --appimage-extract-and-run --no-appstream \
      --runtime-file "$work/runtime" "$appdir" "$OUTDIR/thelemail-migrator-${VERSION}-linux-x86_64.AppImage"
    chmod +x "$OUTDIR/thelemail-migrator-${VERSION}-linux-x86_64.AppImage"
    ;;
  windows)
    iscc="${ISCC:-/c/Program Files (x86)/Inno Setup 6/ISCC.exe}"
    if [ ! -x "$iscc" ]; then
      echo "Inno Setup compiler not found at $iscc; set ISCC" >&2
      exit 1
    fi
    out="$(cd "$OUTDIR" && pwd)"
    "$iscc" /Qp "/DAppVersion=${VERSION}" "/DSourceDir=$(cygpath -w "$PWD/target/release")" \
      "/DOutputDir=$(cygpath -w "$out")" "$(cygpath -w "$PWD/installer/migrator.iss")"
    mkdir -p "$OUTDIR/check"
    cp target/release/migrator-engine.exe "$OUTDIR/check/migrator-engine-windows-amd64.exe"
    ;;
  *)
    echo "unknown target $TARGET" >&2
    exit 1
    ;;
esac
ls -l "$OUTDIR"
