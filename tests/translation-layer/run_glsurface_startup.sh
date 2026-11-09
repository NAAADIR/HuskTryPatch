#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/husk-gl-start.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
cd "$ROOT"
"${HUSK_JDK:+$HUSK_JDK/bin/}javac" --release 8 -encoding UTF-8 -d "$OUT/stubs" $(find src/java-framework/stubs -name '*.java')
"${HUSK_JDK:+$HUSK_JDK/bin/}javac" --release 8 -encoding UTF-8 -cp "$OUT/stubs" -d "$OUT/classes" $(find src/java-framework/src src/java-framework/gen-src -name '*.java')
"${HUSK_JDK:+$HUSK_JDK/bin/}javac" --release 8 -cp "$OUT/classes:$OUT/stubs" -d "$OUT/classes" tests/translation-layer/java-host/android/util/Log.java tests/translation-layer/java-host/husk/Native.java
"${HUSK_JDK:+$HUSK_JDK/bin/}javac" --release 8 -cp "$OUT/classes:$OUT/stubs" -d "$OUT/classes" tests/translation-layer/GLSurfaceStartupTest.java
"${HUSK_JDK:+$HUSK_JDK/bin/}java" -cp "$OUT/classes:$OUT/stubs" android.opengl.GLSurfaceStartupTest
