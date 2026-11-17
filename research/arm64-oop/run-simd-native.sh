#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Native register-only FP/AdvSIMD execution in the block engine (Apple Silicon).
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d "${TMPDIR:-/tmp}/husk-simd-native.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
clang -std=gnu11 -O2 -DBB_TESTING -Wall -Wextra -Werror -Wno-unused-function \
 research/arm64-oop/block_engine.c research/arm64-oop/simd_native_test.c -lm -o "$tmp/test"
"$tmp/test"
