#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/build"
rm -rf "$OUT"
mkdir -p "$OUT/classes"
EXPORTS=(
  jdk.compiler/com.sun.tools.javac.api
  jdk.compiler/com.sun.tools.javac.code
  jdk.compiler/com.sun.tools.javac.comp
  jdk.compiler/com.sun.tools.javac.main
  jdk.compiler/com.sun.tools.javac.tree
  jdk.compiler/com.sun.tools.javac.util
)
ARGS=()
for x in "${EXPORTS[@]}"; do ARGS+=(--add-exports "$x=ALL-UNNAMED"); done
javac "${ARGS[@]}" -d "$OUT/classes" $(find "$HERE/src" -name '*.java' -print)
cp -R "$HERE/resources"/* "$OUT/classes"/
jar --create --file "$OUT/apk2project-javac-plugin.jar" -C "$OUT/classes" .
echo "$OUT/apk2project-javac-plugin.jar"
