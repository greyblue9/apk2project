#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, sys, json, os, subprocess, tempfile, time, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

spec=importlib.util.spec_from_file_location('hybrid_apk_v29',ROOT/'hybrid_apk.py')
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)

main=(ROOT/'apk2project.py').read_text()
hybrid=(ROOT/'hybrid_apk.py').read_text()
runtime=(ROOT/'java_engine/DexHybridRebuilder.java').read_text()
json_java=(ROOT/'javac_engine/src/apk2project/javac/Json.java').read_text()
build_sh=(ROOT/'java_engine/build.sh').read_text()

assert '--dexlib-jar' not in main and '--dexlib-jar' not in hybrid
assert '--install-tools' not in main
assert 'DEXLIB_JAR' not in hybrid
assert 'DEXLIB_CP' not in build_sh
assert '.gradle/caches' not in hybrid and '.m2/repository' not in hybrid
assert 'shutil.which("apktool")' not in main and 'shutil.which("jadx")' not in main
assert '_jadx_help_text' not in main
assert 'probe-dexlib' not in runtime and 'probe-dexlib' not in hybrid
assert 'java.lang.reflect' not in json_java
assert 'Class.forName' not in runtime and 'Proxy.newProxyInstance' not in runtime
assert 'if z.rebuild_apk and not z.compile:' in main
assert 'z.compile = True' in main
assert '--dump-class-tree' in main and 'DexTreeDumper' in main
print('PASS v29 uses pinned owned toolchain with no per-dexlib-jar/system JADX/Apktool selection')
print('PASS dynamic JADX/dexlib capability probes and remaining Java array reflection are removed')
print('PASS --rebuild-apk implies a known-good compile and class-tree dump option is wired')

with tempfile.TemporaryDirectory(prefix='v29-class-on-demand-') as td:
    t=Path(td); project=t/'project'; work=project/'analysis/hybrid-apk'; work.mkdir(parents=True)
    src=project/'app/src/main/java/io/example/App.java'; src.parent.mkdir(parents=True)
    src.write_text('package io.example; public class App { public int x(){return 1;} }\n')
    wrapper=project/'build-termux.sh'
    wrapper.write_text('''#!/bin/sh\nset -eu\nmkdir -p app/build/intermediates/javac/debug/compileDebugJavaWithJavac/classes\njavac -d app/build/intermediates/javac/debug/compileDebugJavaWithJavac/classes app/src/main/java/io/example/App.java\necho invoked >> analysis/hybrid-apk/fake-gradle-count.txt\n''')
    wrapper.chmod(0o755)
    plan={'runtime':[{'fqcn':'io.example.App','source':'io/example/App.java'}]}
    root=h.ensure_javac_classes(project,plan,work)
    assert (root/'io/example/App.class').is_file()
    assert (work/'fake-gradle-count.txt').read_text().count('invoked')==1
    # Reuse current output without a second compile.
    root2=h.ensure_javac_classes(project,plan,work)
    assert root2==root
    assert (work/'fake-gradle-count.txt').read_text().count('invoked')==1
    # A source edit makes it stale and forces recompilation.
    time.sleep(1.05)
    src.write_text('package io.example; public class App { public int x(){return 2;} }\n')
    h.ensure_javac_classes(project,plan,work)
    assert (work/'fake-gradle-count.txt').read_text().count('invoked')==2
print('PASS hybrid runtime compiles replacement .class output on demand and reuses fresh output')

# Exercise the tree renderer without requiring a prebuilt APK fixture.
with tempfile.TemporaryDirectory(prefix='v29-tree-') as td:
    t=Path(td); classes=t/'classes'; classes.mkdir()
    exports=[
      '--add-exports','jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED',
      '--add-exports','jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED',
      '--add-exports','jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED',
      '--add-exports','jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED',
      '--add-exports','jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED',
      '--add-exports','java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED',
    ]
    core=[str(p) for p in (ROOT/'java_engine').glob('*.java') if p.name!='DexHybridRebuilder.java']
    subprocess.run(['javac',*exports,'-d',classes,*core],check=True)
    harness=t/'TreeHarness.java'
    harness.write_text(r'''package apk2project.hybrid;
import java.util.*;
public class TreeHarness {
  static DexReader.Clazz c(String n,String sup){ DexReader.Clazz c=new DexReader.Clazz(); c.fqcn=n;c.internal=n.replace('.','/');c.superDesc=sup;c.dexEntry="classes.dex";return c; }
  public static void main(String[] a){
    Map<String,DexReader.Clazz> m=new LinkedHashMap<>();
    m.put("x.A",c("x.A","Ljava/lang/Object;"));
    m.put("x.B",c("x.B","Lx/A;"));
    m.put("x.C",c("x.C","Landroid/app/Service;"));
    String t=DexTreeDumper.renderText(m), j=DexTreeDumper.renderJson(m);
    if(!t.contains("x.A")||!t.contains("x.B")||!t.contains("x.C")) throw new AssertionError(t);
    if(!j.contains("\"class_count\": 3")||!j.contains("\"children\":[\"x.B\"]")) throw new AssertionError(j);
    if(!(DexReader.dexEntryNumber("classes.dex") < DexReader.dexEntryNumber("classes2.dex") &&
         DexReader.dexEntryNumber("classes2.dex") < DexReader.dexEntryNumber("classes10.dex")))
      throw new AssertionError("multidex order");
  }
}
''')
    subprocess.run(['javac','-cp',classes,'-d',classes,harness],check=True)
    subprocess.run(['java','-cp',classes,'apk2project.hybrid.TreeHarness'],check=True)
print('PASS DexTreeDumper emits a complete superclass forest plus machine-readable JSON')
