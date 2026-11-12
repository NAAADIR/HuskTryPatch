#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Run on a Mac with the actual iPhoneOS SDK. This does not build or sign an IPA.
set -eu
cd "$(dirname "$0")/.."
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
cc=$(xcrun --sdk iphoneos --find clang)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/husk-oop-ios-check.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
"$cc" --target=aarch64-linux-android29 -c research/arm64-oop/loader_fixture.S -o "$tmp/fixture.o"
python3 research/arm64-oop/pack_loader_fixture.py "$tmp/fixture.o" "$tmp/fixture.bin"
cmp "$tmp/fixture.bin" src/app/Husk/Resources/husk-oop-fixture.bin
for source in src/translation-layer-next/husk-tl-ld.c src/translation-layer-next/husk-jit-arena.c \
              src/translation-layer-next/husk-tl-xmem.c src/translation-layer-next/husk-oop-engine.c \
              src/translation-layer-next/husk-oop-ios.c; do
    "$cc" -target arm64-apple-ios16.0 -isysroot "$sdk" -std=gnu11 -DHUSK_OOP_IOS_DIAG=1 \
        -Isrc/translation-layer -Isrc/translation-layer-next -Werror=implicit-function-declaration -fsyntax-only "$source"
done
xcrun --sdk iphoneos swiftc -typecheck -target arm64-apple-ios16.0 -sdk "$sdk" \
    -D HUSK_OOP_IOS_DIAG -Xcc -DHUSK_OOP_IOS_DIAG=1 -import-objc-header src/app/Husk/HuskBridge.h \
    research/arm64-oop/ios_compile_stubs.swift src/app/Husk/OOPDiagnostic.swift
echo 'iPhoneOS arm64 diagnostic C, Swift view and fixture packaging: PASS'
