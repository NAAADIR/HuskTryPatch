#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/husk-gms-test.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
JAVAC=${HUSK_JDK:+$HUSK_JDK/bin/}javac
JAVA=${HUSK_JDK:+$HUSK_JDK/bin/}java
cd "$ROOT"
"$JAVAC" --release 8 -encoding UTF-8 -d "$OUT/stubs" $(find src/java-framework/stubs -name '*.java')
"$JAVAC" --release 8 -encoding UTF-8 -cp "$OUT/stubs" -d "$OUT/classes" $(find src/java-framework/src src/java-framework/gen-src -name '*.java') tests/translation-layer/GmsCallbackTest.java
"$JAVAC" --release 8 -d "$OUT/classes" tests/translation-layer/java-host/android/util/Log.java
"$JAVA" -cp "$OUT/classes:$OUT/stubs" husk.GmsCallbackTest
