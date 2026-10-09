#!/usr/bin/env python3
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
runtime=(ROOT/'java_engine/DexHybridRebuilder.java').read_text()
main=(ROOT/'apk2project.py').read_text()
hybrid=(ROOT/'hybrid_apk.py').read_text()
toolchain=(ROOT/'toolchain.py').read_text()

assert 'import com.android.tools.smali.dexlib2.Opcodes;' in runtime
assert 'Class.forName' not in runtime
assert 'java.lang.reflect' not in runtime
assert 'Proxy.newProxyInstance' not in runtime
assert 'org.jf.dexlib2' not in runtime
assert 'CallSiteReference' in runtime and 'getExtraArguments()' in runtime
assert 'checkEncodedValue' in runtime and 'checkAnnotations' in runtime
assert 'p.name != "DexHybridRebuilder.java"' in main
assert 'refusing unsafe ordinary-source fallback' in main
assert 'ensure_dexlib_classpath' in hybrid
assert 'DEXLIB_BUNDLE' in toolchain
assert 'probe-dexlib' not in runtime and 'probe-dexlib' not in hybrid
assert 'matches("(?:m|mo|f)\\\\d+.*")' in runtime

print('PASS runtime helper directly imports official com.android.tools.smali dexlib2')
print('PASS reflection/org.jf compatibility shim remains gone')
print('PASS early hybrid/source engine excludes DexHybridRebuilder')
print('PASS call-site/encoded-value/annotation runtime references are covered')
print('PASS pinned dexlib bundle replaces dynamic dexlib probing/overrides')
print('PASS Java alias regex remains correctly escaped')
print('PASS --rebuild-apk source boundary remains fail-closed')
