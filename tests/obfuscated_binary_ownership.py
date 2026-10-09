#!/usr/bin/env python3
import json, runpy, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = [
    '--add-exports','jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED',
    '--add-exports','jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED',
    '--add-exports','jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED',
    '--add-exports','jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED',
    '--add-exports','jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED',
    '--add-exports','java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED',
]

def run(cmd):
    p=subprocess.run(cmd,text=True,capture_output=True)
    if p.returncode:
        raise AssertionError(p.stdout+'\n'+p.stderr)
    return p

run(['bash', str(ROOT/'java_engine/build.sh')])
classes=ROOT/'java_engine/classes'

with tempfile.TemporaryDirectory(prefix='v261-obf-') as td:
    td=Path(td); jr=td/'app/src/main/java'; orig=td/'orig';
    (jr/'com/example/app').mkdir(parents=True)
    (jr/'p001a0').mkdir(parents=True)
    (orig/'smali/a0').mkdir(parents=True)
    (orig/'smali/com/example/app').mkdir(parents=True)
    # Both are deliberately under otherwise app-owned territory/evidence.
    (jr/'p001a0/C0014k.java').write_text('package p001a0; public class C0014k { BROKEN !!! }')
    (jr/'com/example/app/C0099x.java').write_text('package com.example.app; public class C0099x { BROKEN !!! }')
    (jr/'com/example/app/Main.java').write_text('package com.example.app; public class Main { }')
    (orig/'smali/a0/k.smali').write_text('.class public La0/k;\n.super Ljava/lang/Object;\n')
    (orig/'smali/com/example/app/x.smali').write_text('.class public Lcom/example/app/x;\n.super Ljava/lang/Object;\n')
    out=td/'shadow.jar'; own=td/'own.json'; lst=td/'binary.txt'
    package_rx=r'(?:^|\.)p\d+[A-Za-z0-9_$]*(?:\.|$)'
    class_rx=r'(?:^|[.$])(?:Abstract|Interface|Enum)?C\d+[A-Za-z0-9_$]*(?:$|\$)'
    run(['java',*EXPORTS,'-cp',str(classes),'apk2project.hybrid.HybridCompiler','shadow',
         '--java-root',str(jr),'--original',str(orig),'--out',str(out),
         '--ownership',str(own),'--source-list',str(lst),'--app-prefix','com.example.app',
         '--force-binary-regex',package_rx,'--force-binary-regex',class_rx])
    binary=set(lst.read_text().splitlines())
    assert 'p001a0/C0014k.java' in binary
    assert 'com/example/app/C0099x.java' in binary
    assert 'com/example/app/Main.java' not in binary

    mod=runpy.run_path(str(ROOT/'apk2project.py'))
    q=mod['quarantine_hybrid_binary_sources'](td,jr,lst,'move')
    assert q['moved']==2
    assert (jr/'com/example/app/Main.java').exists()
    assert not (jr/'com/example/app/C0099x.java').exists()
    assert not (jr/'p001a0/C0014k.java').exists()
    ar=td/'analysis/hybrid-binary-source-archive/java'
    assert (ar/'com/example/app/C0099x.java').exists()
    assert (ar/'p001a0/C0014k.java').exists()
print('PASS obfuscated ownership preset overrides app package and moves binary source out of active Java tree')
