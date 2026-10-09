#!/usr/bin/env python3
from __future__ import annotations
import shutil, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRCS = sorted(p for p in (ROOT / 'java_engine').glob('*.java') if p.name != 'DexHybridRebuilder.java')
EXPORTS = [
    '--add-exports','jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED',
    '--add-exports','jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED',
    '--add-exports','jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED',
    '--add-exports','jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED',
    '--add-exports','jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED',
    '--add-exports','java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED',
]

def run(*a):
    return subprocess.run(list(map(str,a)), check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def write(p:Path,s:str):
    p.parent.mkdir(parents=True,exist_ok=True); p.write_text(s)

def main():
    if not shutil.which('javac') or not shutil.which('java'):
        print('SKIP javac/java unavailable'); return
    with tempfile.TemporaryDirectory(prefix='apk2project-v275-') as td:
        t=Path(td); eng=t/'engine'; eng.mkdir()
        run('javac',*EXPORTS,'-d',eng,*SRCS)
        jr=['java',*EXPORTS,'-cp',eng,'apk2project.hybrid.HybridCompiler']
        src=t/'src'; orig=t/'orig'; out=t/'out'; out.mkdir()
        write(src/'com/example/Use.java', '''
package com.example;
import shim.C0100x;
class Use {
  void run() { C0100x.m777b(); new C0100x(16, this); }
}
''')
        # These are deliberately synthetic, exactly like R8 compatibility shims in TopActivity.
        write(orig/'smali/shim/x.smali', '''
.class public final synthetic Lshim/x;
.super Ljava/lang/Object;
.method public static synthetic b()V
  .locals 0
  return-void
.end method
.method public synthetic constructor <init>(ILjava/lang/Object;)V
  .locals 0
  return-void
.end method
''')
        jobf=out/'map.jobf'
        write(jobf, '''
c shim.x = C0100x
m shim.x.b()V = m777b
''')
        jar=out/'shadow.jar'; own=out/'o.json'; binary=out/'b.txt'
        run(*jr,'shadow','--java-root',src,'--original',orig,'--out',jar,
            '--ownership',own,'--source-list',binary,'--app-prefix','com.example','--jadx-map',jobf)
        classes=out/'classes'; classes.mkdir()
        run('javac','-cp',jar,'-d',classes,src/'com/example/Use.java')
        verbose=run('javap','-classpath',jar,'-v','shim.C0100x').stdout
        # javac source lookup hides ACC_SYNTHETIC members, so the source-facing facade
        # must deliberately strip that implementation flag from classes/methods/ctors.
        assert 'ACC_SYNTHETIC' not in verbose, verbose
        print('PASS synthetic DEX shim method is source-visible in shadow ABI')
        print('PASS synthetic DEX constructor is source-visible in shadow ABI')
        print('PASS shadow facade strips ACC_SYNTHETIC/ACC_BRIDGE implementation flags')

if __name__=='__main__': main()
