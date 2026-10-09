#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/classes"
rm -rf "$OUT"
mkdir -p "$OUT"
EXPORTS=(
  --add-exports jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED
  --add-exports jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED
  --add-exports jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED
  --add-exports jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED
  --add-exports jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED
  --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED
)
CORE=()
for f in "$HERE"/*.java; do
  [[ "$(basename "$f")" == "DexHybridRebuilder.java" ]] && continue
  CORE+=("$f")
done
javac "${EXPORTS[@]}" -d "$OUT" "${CORE[@]}"
if [[ -n "${DEXLIB_CP:-}" ]]; then
  javac "${EXPORTS[@]}" -cp "$OUT:$DEXLIB_CP" -d "$OUT" "$HERE/DexHybridRebuilder.java"
  echo "Compiled core + direct dexlib runtime helper -> $OUT"
else
  echo "Compiled dexlib-independent core engine -> $OUT"
  echo "Set DEXLIB_CP to the standalone smali-dexlib2 runtime classpath to compile DexHybridRebuilder too."
fi
printf '%s\n' "${EXPORTS[@]}" > "$HERE/add-exports.args"
