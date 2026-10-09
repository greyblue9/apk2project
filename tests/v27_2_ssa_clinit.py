#!/usr/bin/env python3
"""Compile-backed v27.2 tests for JADX SSA LUB recovery and interface <clinit> legalization."""
from __future__ import annotations
import json, shutil, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRCS = sorted(p for p in (ROOT / "java_engine").glob("*.java") if p.name != "DexHybridRebuilder.java")
EXPORTS = [
    "--add-exports", "jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED",
    "--add-exports", "jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED",
    "--add-exports", "jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED",
    "--add-exports", "jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED",
    "--add-exports", "jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED",
    "--add-exports", "java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED",
]

def run(*args, check=True):
    return subprocess.run(list(map(str,args)), check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def write(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)

def normalize(jr, src: Path, report: Path):
    p = run(*jr, "normalize", "--java-root", src, "--report", report)
    return [json.loads(x) for x in report.read_text().splitlines() if x.strip()]

def main():
    if not shutil.which("javac") or not shutil.which("java"):
        print("SKIP: javac/java unavailable"); return
    with tempfile.TemporaryDirectory(prefix="apk2project-v272-") as td:
        t=Path(td); engine=t/"engine"; engine.mkdir()
        run("javac", *EXPORTS, "-d", engine, *SRCS)
        jr=["java",*EXPORTS,"-cp",engine,"apk2project.hybrid.HybridCompiler"]

        # Exact user-shaped case: 3 typed SSA versions + 1 unknown. Unknown is
        # non-vetoing; javac Types.lub(ArrayList,List,List) must produce raw List.
        src=t/"ssa/src"; out=t/"ssa/out"; out.mkdir(parents=True)
        write(src/"X.java", r'''
import java.util.ArrayList;
import java.util.List;
class X { void f(){
/* JADX WARN: Type inference failed for: r0v1, types: [java.util.ArrayList] */
/* JADX WARN: Type inference failed for: r0v2, types: [java.util.List] */
/* JADX WARN: Type inference failed for: r0v3, types: [java.util.List] */
/* JADX WARN: Type inference failed for: r0v4 */
?? r0 = new ArrayList();
r0.add("x");
}}
''')
        facts=normalize(jr,src,out/"report.jsonl")
        text=(src/"X.java").read_text()
        assert "List r0 = new ArrayList()" in text, text
        rec=next(x for x in facts if x.get("kind")=="jadx-ssa-lub")
        assert rec["inferred"]=="java.util.List" and rec["knownVersions"]==3 and rec["unknownVersions"]==1
        run("javac", "-Xlint:none", src/"X.java")
        print("PASS JADX SSA ArrayList/List/List/? -> javac Types.lub = List")
        print("PASS unknown SSA version is non-vetoing when no contradictory source constraint exists")

        # Widen an over-specific legal declaration, again using javac's type lattice.
        src2=t/"widen/src"; out2=t/"widen/out"; out2.mkdir(parents=True)
        write(src2/"X.java", r'''
import java.util.ArrayList;
import java.util.List;
class X { void f(){
/* JADX WARN: Type inference failed for: r0v1, types: [java.util.ArrayList] */
/* JADX WARN: Type inference failed for: r0v2, types: [java.util.List] */
/* JADX WARN: Type inference failed for: r0v3, types: [java.util.List] */
ArrayList r0 = new ArrayList();
r0.add("x");
}}
''')
        normalize(jr,src2,out2/"report.jsonl")
        assert "List r0 = new ArrayList()" in (src2/"X.java").read_text()
        run("javac", "-Xlint:none", src2/"X.java")
        print("PASS over-specific SSA declaration is widened only after receiver-member validation")

        # If source uses a member absent from the LUB, refuse to widen.
        src3=t/"constraint/src"; out3=t/"constraint/out"; out3.mkdir(parents=True)
        original=r'''
import java.util.ArrayList;
import java.util.List;
class X { void f(){
/* JADX WARN: Type inference failed for: r0v1, types: [java.util.ArrayList] */
/* JADX WARN: Type inference failed for: r0v2, types: [java.util.List] */
ArrayList r0 = new ArrayList();
r0.trimToSize();
}}
'''
        write(src3/"X.java",original)
        facts3=normalize(jr,src3,out3/"report.jsonl")
        assert "ArrayList r0" in (src3/"X.java").read_text()
        assert any("candidate lacks observed member trimToSize" in x.get("reason","") for x in facts3)
        print("PASS source-use constraint vetoes LUB when required member exists only on concrete subtype")

        # JVM/DEX <clinit> reconstructed by JADX as an illegal interface static block.
        src4=t/"clinit/src"; out4=t/"clinit/out"; out4.mkdir(parents=True)
        write(src4/"I.java", r'''
interface I {
  Object A;
  int B;
  static {
    A = new Object();
    B = 3;
  }
}
''')
        facts4=normalize(jr,src4,out4/"report.jsonl")
        text4=(src4/"I.java").read_text()
        assert "Object A = new Object();" in text4 and "int B = 3;" in text4
        assert "static {" not in text4
        run("javac", "-Xlint:none", src4/"I.java")
        assert any(x.get("kind")=="interface-clinit-legalized" for x in facts4)
        print("PASS simple interface <clinit> is translated to legal field initializers, not deleted")

        # Complex initializer is preserved rather than destructively dropped.
        src5=t/"complex/src"; out5=t/"complex/out"; out5.mkdir(parents=True)
        complex_src=r'''
interface I {
  Object A;
  static {
    if (System.currentTimeMillis() > 0) A = new Object();
  }
}
'''
        write(src5/"I.java",complex_src)
        facts5=normalize(jr,src5,out5/"report.jsonl")
        assert "static {" in (src5/"I.java").read_text()
        assert any(x.get("kind")=="interface-clinit-unsupported" for x in facts5)
        print("PASS complex interface <clinit> is preserved for binary-shadow/later structured repair")

if __name__ == "__main__": main()
