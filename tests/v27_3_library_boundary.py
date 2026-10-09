#!/usr/bin/env python3
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
    return subprocess.run([str(x) for x in cmd], check=True, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, **kw)

# Build the Java engine exactly as the product does.
run([ENGINE/'build.sh'])

with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    jobf=td/'map.jobf'
    jobf.write_text('''\
c p.a0 = C0176a0
c p.a0$a = a
c p.e0 = FragmentC0184e0
c p.e0$a = a
c p.a = C0175a
''')
    src=td/'apk2project/hybrid/NestedJobfCheck.java'
    src.parent.mkdir(parents=True)
    src.write_text('''\
package apk2project.hybrid;
import java.nio.file.Path;
public class NestedJobfCheck {
  public static void main(String[] args) {
    HybridCompiler.JadxMap m = HybridCompiler.loadJadxMap(Path.of(args[0]));
    String a = m.sourceClassName("p.a0$a");
    String e = m.sourceClassName("p.e0$a");
    String top = m.sourceClassName("p.a");
    if (!a.equals("p.C0176a0$a")) throw new AssertionError(a);
    if (!e.equals("p.FragmentC0184e0$a")) throw new AssertionError(e);
    if (!top.equals("p.C0175a")) throw new AssertionError(top);
    if (a.equals(e) || a.equals(top) || e.equals(top)) throw new AssertionError("collision");
  }
}
''')
    out=td/'classes'; out.mkdir()
    run(['javac', *EXPORTS, '-cp', CLASSES, '-d', out, src])
    run(['java', *EXPORTS, '-cp', f'{CLASSES}:{out}', 'apk2project.hybrid.NestedJobfCheck', jobf])
    print('PASS nested JOBF aliases preserve outer identity and cannot flatten/collide')

# Verify generated Gradle integration has a final JavaCompile source filter, not only
# sourceSets exclusion, because AGP/plugins may rebuild the task's source collection.
spec=importlib.util.spec_from_file_location('apk2project', ROOT/'apk2project.py')
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory() as td:
    root=Path(td); (root/'app/libs').mkdir(parents=True); (root/'app').mkdir(exist_ok=True)
    (root/'app/build.gradle').write_text('plugins {}\n')
    shadow=root/'app/libs/apk2project-apk-shadow-abi.jar'; shadow.write_bytes(b'x')
    owned=root/'app/apk2project-binary-sources.txt'; owned.write_text('androidx/foo/Bad.java\n')
    assert mod.configure_hybrid_shadow_gradle(root, shadow, owned)
    g=(root/'app/build.gradle').read_text()
    assert 'android.sourceSets.main.java.exclude' in g
    assert 'task.setSource(task.source.filter' in g
    assert 'apk2projectBinaryOwnedSources.contains(rel)' in g
    print('PASS hybrid ownership is enforced again on final JavaCompile.source')
