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
  # DexHybridRebuilder is intentionally compiled later by hybrid_apk.py after
  # apk2project has resolved its own pinned smali-dexlib2 runtime bundle.
  [[ "$(basename "$f")" == "DexHybridRebuilder.java" ]] && continue
  CORE+=("$f")
done
javac "${EXPORTS[@]}" -d "$OUT" "${CORE[@]}"
echo "Compiled dexlib-independent core engine -> $OUT"
echo "DexHybridRebuilder is compiled on demand by apk2project against its pinned dexlib2 bundle."
printf '%s\n' "${EXPORTS[@]}" > "$HERE/add-exports.args"
