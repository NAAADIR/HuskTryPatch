#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu
cd "$(dirname "$0")/../.."
out=$(mktemp -d "${TMPDIR:-/tmp}/husk-telephony.XXXXXX")
trap 'rm -rf "$out"' EXIT
"${HUSK_JDK:+$HUSK_JDK/bin/}javac" --release 8 -encoding UTF-8 -d "$out/stubs" $(find src/java-framework/stubs -name '*.java')
"${HUSK_JDK:+$HUSK_JDK/bin/}javac" --release 8 -encoding UTF-8 -cp "$out/stubs" -d "$out/classes" $(find src/java-framework/src src/java-framework/gen-src -name '*.java')
"${HUSK_JDK:+$HUSK_JDK/bin/}javac" --release 8 -encoding UTF-8 -cp "$out/classes:$out/stubs" -d "$out/test" tests/translation-layer/TelephonyNoSimTest.java
"${HUSK_JDK:+$HUSK_JDK/bin/}java" -cp "$out/test:$out/classes:$out/stubs" TelephonyNoSimTest
