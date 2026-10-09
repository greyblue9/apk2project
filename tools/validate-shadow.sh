#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$#" -lt 2 ]; then
  echo "usage: $0 APK SHADOW_JAR [REPORT_JSON]" >&2
  exit 2
fi
APK="$1"
JAR="$2"
REPORT="${3:-$ROOT/shadow-validation.json}"
"$ROOT/java_engine/build.sh" >/dev/null
# shellcheck disable=SC2207
EXPORTS=( $(cat "$ROOT/java_engine/add-exports.args") )
exec java "${EXPORTS[@]}" -cp "$ROOT/java_engine/classes" \
  apk2project.hybrid.HybridCompiler validate \
  --apk "$APK" --shadow-jar "$JAR" --report "$REPORT"
