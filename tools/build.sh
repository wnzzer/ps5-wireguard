#!/usr/bin/env bash
# Build out/wireguard.elf: the Go daemon (wgd/) wrapped in the C launcher.
#   tools/build.sh [version]
# Expects (see README): goroot/ (Go 1.27.1 + patches/go1.27.1-ps5.patch),
# toolchain/llvm/ (clang + ld.lld >= 20), toolchain/ps5-payload-sdk/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-0.1.0}"
SDK="$ROOT/toolchain/ps5-payload-sdk"
LLVM="$ROOT/toolchain/llvm/bin"
OUT="$ROOT/out"
mkdir -p "$OUT" "$ROOT/.gocache" "$ROOT/.gotmp"

echo "== go ($VERSION)"
(
  cd "$ROOT/wgd"
  GOROOT="$ROOT/goroot" GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 GOTOOLCHAIN=local \
  GOCACHE="$ROOT/.gocache" GOTMPDIR="$ROOT/.gotmp" \
    "$ROOT/goroot/bin/go" build -buildmode=pie -trimpath \
      -ldflags="-s -w -X main.version=$VERSION" -o "$OUT/wireguard.bin" .
)

echo "== launcher"
PATH="$LLVM:$PATH" SCE_PROSPERO_SDK_DIR="$SDK" "$LLVM/clang" \
  --start-no-unused-arguments \
  -target x86_64-sie-ps5 \
  -fvisibility-nodllstorageclass=default \
  -isysroot "$SDK" -isystem "$SDK/target/include" -L "$SDK/target/lib" \
  -fno-stack-protector -fno-plt -femulated-tls -lc \
  --end-no-unused-arguments \
  -O2 -Wall "-DGO_IMAGE=\"$OUT/wireguard.bin\"" \
  -o "$OUT/wireguard.elf" \
  "$ROOT/launcher/main.c" "$ROOT/launcher/goload.c" "$ROOT/launcher/homeicon.c" "$ROOT/launcher/report.c" \
  --start-no-unused-arguments \
  --sysroot "$SDK" -Wl,--hash-style=gnu \
  -lkernel_web -lSceLibcInternal -lSceNet \
  --end-no-unused-arguments

cp "$OUT/wireguard.elf" "$OUT/wireguard-$VERSION.elf"
ls -la "$OUT/wireguard-$VERSION.elf"
shasum -a 256 "$OUT/wireguard-$VERSION.elf"
