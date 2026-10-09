#!/usr/bin/env python3
"""Regression cases extracted from the real TopActivity v27.2/v27.3 failure."""
import importlib.util, subprocess, tempfile, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / 'java_engine'
CLASSES = ENGINE / 'classes'
EXPORTS = [
    '--add-exports', 'jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED',
    '--add-exports', 'jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED',
    '--add-exports', 'jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED',
    '--add-exports', 'jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED',
    '--add-exports', 'jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED',
    '--add-exports', 'java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED',
]

def run(cmd, **kw):
    return subprocess.run([str(x) for x in cmd], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)

run([ENGINE/'build.sh'])

# 1. A nested DEX class may genuinely be flattened by JADX into a top-level Java
# file. Preserve nesting by default, but observed top-level source is stronger evidence.
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    src = td/'apk2project/hybrid/RealApkBoundaryCheck.java'
    src.parent.mkdir(parents=True)
    src.write_text(r'''
package apk2project.hybrid;
import java.util.*;
public class RealApkBoundaryCheck {
  static HybridCompiler.SmaliClass dex(String fq) {
    HybridCompiler.SmaliClass c = new HybridCompiler.SmaliClass();
    c.rawFqcn=fq; c.rawInternal=fq.replace('.','/'); return c;
  }
  public static void main(String[] args) {
    HybridCompiler.SourceIndex si = new HybridCompiler.SourceIndex();
    HybridCompiler.SourceType flat = new HybridCompiler.SourceType();
    flat.fqcn="androidx.lifecycle.C0174xfdb59cc4"; flat.topLevel=true;
    si.bySource.put(flat.fqcn, flat);
    HybridCompiler.JadxMap jm = new HybridCompiler.JadxMap();
    String raw="androidx.lifecycle.WithLifecycleStateKt$suspendWithStateAtLeastUnchecked$2$observer$1";
    jm.classes.put(raw,"C0174xfdb59cc4");
    Map<String,HybridCompiler.SmaliClass> dex=new LinkedHashMap<>(); dex.put(raw,dex(raw));
    HybridCompiler.reconcileSourceMappings(si,dex,jm);
    String got=si.rawToSource.get(raw);
    if(!flat.fqcn.equals(got)) throw new AssertionError("flattened alias not honored: "+got);
    if(!raw.equals(flat.rawFqcn)) throw new AssertionError("raw owner not attached: "+flat.rawFqcn);

    HybridCompiler.SourceType aux = new HybridCompiler.SourceType();
    aux.fqcn="kotlin.coroutines.jvm.internal.DebugProbesKt"; aux.topLevel=true; aux.appOwned=false;
    si.bySource.put(aux.fqcn, aux);
    String manifest=HybridCompiler.buildAliasManifest(si,dex);
    if(!manifest.contains("S\tkotlin.coroutines.jvm.internal.DebugProbesKt\t"))
      throw new AssertionError("source-only shell provenance missing: "+manifest);
  }
}
''')
    out=td/'classes'; out.mkdir()
    run(['javac', *EXPORTS, '-cp', CLASSES, '-d', out, src])
    run(['java', *EXPORTS, '-cp', f'{CLASSES}:{out}', 'apk2project.hybrid.RealApkBoundaryCheck'])
    print('PASS observed top-level JADX flattening overrides nested JOBF mapping only with source evidence')
    print('PASS intentional source-only shell receives explicit S provenance')

# 2. Library-contributed manifest components must not become source roots merely
# because they occur in the merged manifest.
spec=importlib.util.spec_from_file_location('apk2project_v274', ROOT/'apk2project.py')
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
roots={
    'io.github.ratul.topactivity.App',
    'io.github.ratul.topactivity.services.QuickSettingsTileService',
    'androidx.startup.InitializationProvider',
    'androidx.profileinstaller.ProfileInstallReceiver',
}
got=mod._filter_manifest_roots_to_app_prefixes(roots,['io.github.ratul.topactivity'])
assert got == {
    'io.github.ratul.topactivity.App',
    'io.github.ratul.topactivity.services.QuickSettingsTileService',
}, got
print('PASS merged-manifest AndroidX components do not become app-owned source roots')
