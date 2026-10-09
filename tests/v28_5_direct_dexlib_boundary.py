#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, tempfile, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('hybrid_apk_v285',ROOT/'hybrid_apk.py')
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)

with tempfile.TemporaryDirectory(prefix='v28.5-dexlib-') as td:
    td=Path(td)
    # Apktool-like partial shading must not qualify.
    partial=td/'apktool_3.0.3.jar'
    with zipfile.ZipFile(partial,'w') as z:
        for suffix in ('Opcodes.class','dexbacked/DexBackedDexFile.class','iface/ClassDef.class'):
            z.writestr('com/android/tools/smali/dexlib2/'+suffix,b'x')
    assert h._jar_dexlib_prefix(partial) is None

    # Official/public API surface qualifies.
    full=td/'smali-dexlib2-3.0.10.jar'
    with zipfile.ZipFile(full,'w') as z:
        for suffix in h.DEXLIB_REQUIRED_SUFFIXES:
            z.writestr('com/android/tools/smali/dexlib2/'+suffix,b'x')
    assert h._jar_dexlib_prefix(full)=='com.android.tools.smali.dexlib2'
    cp=h.find_dexlib_classpath(full,td)
    assert cp[0]==full.resolve()

runtime=(ROOT/'java_engine/DexHybridRebuilder.java').read_text()
main=(ROOT/'apk2project.py').read_text()
hybrid=(ROOT/'hybrid_apk.py').read_text()

assert 'import com.android.tools.smali.dexlib2.Opcodes;' in runtime
assert 'Class.forName' not in runtime
assert 'java.lang.reflect' not in runtime
assert 'Proxy.newProxyInstance' not in runtime
assert 'org.jf.dexlib2' not in runtime
assert 'CallSiteReference' in runtime and 'getExtraArguments()' in runtime
assert 'checkEncodedValue' in runtime and 'checkAnnotations' in runtime
assert 'p.name != "DexHybridRebuilder.java"' in main
assert 'refusing unsafe ordinary-source fallback' in main
assert "runtime DEX helper only after standalone dexlib2 is resolved" in hybrid
assert 'matches("(?:m|mo|f)\\\\d+.*")' in runtime

print('PASS Apktool shading is not accepted as a dexlib distribution')
print('PASS runtime helper directly imports official com.android.tools.smali dexlib2')
print('PASS reflection/org.jf compatibility shim is gone')
print('PASS early hybrid/source engine excludes DexHybridRebuilder')
print('PASS call-site/encoded-value/annotation runtime references are covered')
print('PASS Java alias regex remains correctly escaped')
print('PASS --rebuild-apk source boundary remains fail-closed')
