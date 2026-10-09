#!/usr/bin/env python3
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
hybrid=(ROOT/'hybrid_apk.py').read_text()
toolchain=(ROOT/'toolchain.py').read_text()
runtime=(ROOT/'java_engine/DexHybridRebuilder.java').read_text()
main=(ROOT/'apk2project.py').read_text()

assert 'smali-dexlib2' in toolchain and 'DEXLIB_REQUIRED_SUFFIXES' in toolchain
assert 'DEXLIB_JAR' not in hybrid
assert '.gradle/caches' not in hybrid and '.m2/repository' not in hybrid
assert '--dexlib-jar' not in hybrid and '--dexlib-jar' not in main
assert 'com.android.tools.smali.dexlib2' in runtime
assert 'org.jf.dexlib2' not in runtime
assert 'Class.forName' not in runtime
assert 'matches("(?:m|mo|f)\\\\d+.*")' in runtime
assert 'refusing unsafe ordinary-source fallback' in main
print('PASS dexlib runtime remains direct public com.android.tools.smali API')
print('PASS v29 removes partial Apktool/cache/env dexlib discovery and per-jar override')
print('PASS Java regex remains correctly escaped')
print('PASS --rebuild-apk hybrid setup remains fail-closed')
