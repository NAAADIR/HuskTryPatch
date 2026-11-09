#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/husk-resize-test.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
"${HUSK_JDK:+$HUSK_JDK/bin/}javac" --release 8 -d "$OUT" "$ROOT/src/java-framework/src/android/opengl/ResizeMailbox.java" "$ROOT/tests/translation-layer/ResizeMailboxTest.java"
"${HUSK_JDK:+$HUSK_JDK/bin/}java" -cp "$OUT" android.opengl.ResizeMailboxTest
