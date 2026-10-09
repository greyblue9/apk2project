#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, tempfile, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('hybrid_apk',ROOT/'hybrid_apk.py')
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)

with tempfile.TemporaryDirectory(prefix='v28.4-dexlib-') as td:
    td=Path(td)
    partial=td/'apktool_3.0.3.jar'
    with zipfile.ZipFile(partial,'w') as z:
        for suffix in ('Opcodes.class','dexbacked/DexBackedDexFile.class','iface/ClassDef.class'):
            z.writestr('com/android/tools/smali/dexlib2/'+suffix,b'x')
    assert h._jar_dexlib_prefix(partial) is None

    full=td/'smali-dexlib2-3.0.10.jar'
    with zipfile.ZipFile(full,'w') as z:
        for suffix in h.DEXLIB_REQUIRED_SUFFIXES:
            z.writestr('com/android/tools/smali/dexlib2/'+suffix,b'x')
    assert h._jar_dexlib_prefix(full)=='com.android.tools.smali.dexlib2'
    cp=h.find_dexlib_classpath(full,td)
    assert cp[0]==full.resolve()
    assert partial.resolve() not in cp

src=(ROOT/'java_engine/DexHybridRebuilder.java').read_text()
assert 'matches("(?:m|mo|f)\\\\d+.*")' in src
main=(ROOT/'apk2project.py').read_text()
assert 'refusing unsafe ordinary-source fallback' in main
print('PASS partial Apktool dexlib shading is rejected')
print('PASS standalone complete dexlib API is accepted')
print('PASS Java regex remains correctly escaped')
print('PASS --rebuild-apk hybrid setup is fail-closed')
