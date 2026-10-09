#!/usr/bin/env python3
"""Compile-backed v26 tests for the javac-internal APK ABI shadow engine."""
from __future__ import annotations
import json, os, shutil, subprocess, tempfile
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

def run(*args, **kw):
    return subprocess.run(list(map(str,args)), check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)

def write(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)

def main():
    if not shutil.which("javac") or not shutil.which("java"):
        print("SKIP: javac/java unavailable"); return
    with tempfile.TemporaryDirectory(prefix="apk2project-hybrid-v26-") as td:
        t=Path(td); classes=t/"engine"; classes.mkdir()
        run("javac", *EXPORTS, "-d", classes, *SRCS)
        jr=["java",*EXPORTS,"-cp",classes,"apk2project.hybrid.HybridCompiler"]
        java_root=t/"app/src/main/java"; original=t/"original"; out=t/"out"; out.mkdir()
        write(java_root/"com/example/Main.java", '''
package com.example;
import lib.C0001x;
public class Main {
  public int run(C0001x x) {
    int z = x.f99N;
    for (String s : x.m123items()) z += s.length();
    C0001x.C0002y nested = null;
    return z;
  }
}
''')
        # Deliberately broken: if javac ever sees this file, the test fails.
        write(java_root/"lib/C0001x.java", '''
package lib;
public class C0001x {
  public static final int f99N=3;
  public java.util.List<String> m123items(){return null;}
  public static class C0002y {}
  THIS IS INVALID JADX SOURCE
}
''')
        write(original/"smali/lib/x.smali", '''
.class public Llib/x;
.super Ljava/lang/Object;
.field public static final N:I = 0x3
.method public items()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {"()Ljava/util/List<", "Ljava/lang/String;", ">;"}
    .end annotation
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method
.method public constructor <init>()V
    .locals 0
    return-void
.end method
''')
        write(original/"smali/lib/x$y.smali", '''
.class public Llib/x$y;
.super Ljava/lang/Object;
.method public constructor <init>()V
    .locals 0
    return-void
.end method
''')
        jar=out/"shadow.jar"; own=out/"ownership.json"; binary=out/"binary.txt"
        run(*jr,"shadow","--java-root",java_root,"--original",original,"--out",jar,
            "--ownership",own,"--source-list",binary,"--app-prefix","com.example")
        data=json.loads(own.read_text())
        assert "com/example/Main.java" in data["app_sources"]
        assert "lib/C0001x.java" in data["binary_sources"]
        assert binary.read_text().strip()=="lib/C0001x.java"
        # Compile only app source against generated ABI. Generic Signature,
        # ConstantValue, inner metadata and JADX aliases are all required here.
        appclasses=t/"appclasses"; appclasses.mkdir()
        run("javac","-cp",jar,"-d",appclasses,java_root/"com/example/Main.java")
        print("PASS broken non-app JADX source is bypassed by APK ABI shadow")
        print("PASS DEX generic Signature supports typed enhanced-for")
        print("PASS DEX ConstantValue remains a javac constant")
        print("PASS JADX method/field aliases are exported on binary-owned class")
        print("PASS InnerClasses metadata resolves JADX-renamed nested class")

        cp=out/"classpath.txt"; cp.write_text(str(jar)+"\n")
        proc=run(*jr,"analyze","--java-root",java_root,"--source-list",binary,
                 "--classpath-file",cp,"--app-prefix","com.example")
        facts=[json.loads(x) for x in proc.stdout.splitlines() if x.strip()]
        member=[x for x in facts if x.get("kind")=="typed" and x.get("text")=="x.f99N"]
        assert member and member[0]["owner"]=="lib.C0001x" and member[0]["type"]=="int"
        print("PASS javac internals attribute app source against shadow ABI symbols")

        # Structured JCDiagnostic args: actual Type objects, not parsed prose.
        write(java_root/"com/example/Bad.java", 'package com.example; class Bad { void x(){ String s=1; } }')
        # binary list still only excludes lib source, so Bad is analyzed.
        proc=subprocess.run(list(map(str,[*jr,"analyze","--java-root",java_root,"--source-list",binary,
                 "--classpath-file",cp,"--app-prefix","com.example"])), text=True,
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ds=[json.loads(x) for x in proc.stdout.splitlines() if x.strip() and '"kind":"diagnostic"' in x]
        conv=next(x for x in ds if x.get("code")=="compiler.err.prob.found.req")
        raw=conv["args"][0]["args"]
        assert raw[0]["kind"]=="type" and raw[0]["text"]=="int"
        assert raw[1]["kind"]=="type" and raw[1]["text"]=="java.lang.String"
        assert conv["semantic"]["castable"] is False and conv["semantic"]["convertible"] is False
        print("PASS structured JCDiagnostic exposes found/required javac Type objects")
        print("PASS javac Types computes castability/convertibility instead of regex guessing")

        # Missing source provider: an import alone can reveal the inverse JADX alias.
        java2=t/"missing/src"; orig2=t/"missing/original"; out2=t/"missing/out"; out2.mkdir(parents=True)
        write(java2/"com/example/UseMissing.java", """
package com.example;
import p036i1.AbstractC0570m;
class UseMissing { AbstractC0570m value; }
""")
        write(orig2/"smali/i1/m.smali", """
.class public abstract Li1/m;
.super Ljava/lang/Object;
.method public constructor <init>()V
 .locals 0
 return-void
.end method
""")
        jar2=out2/"shadow.jar"; own2=out2/"o.json"; bin2=out2/"b.txt"
        run(*jr,"shadow","--java-root",java2,"--original",orig2,"--out",jar2,
            "--ownership",own2,"--source-list",bin2,"--app-prefix","com.example")
        c2=out2/"classes"; c2.mkdir()
        run("javac","-cp",jar2,"-d",c2,java2/"com/example/UseMissing.java")
        listing=run("jar","tf",jar2).stdout
        assert "p036i1/AbstractC0570m.class" in listing
        print("PASS missing provider source can be resurrected from import alias + smali")

        # v27: arbitrary JADX semantic prefixes before C#### must invert to the raw
        # DEX class, and JADX override aliases use mo####x (not only m####x).
        java3=t/"alias27/src"; orig3=t/"alias27/original"; out3=t/"alias27/out"; out3.mkdir(parents=True)
        write(java3/"com/example/UseWideAlias.java", """
package com.example;
import lib.AbstractComponentCallbacksC0168x;
class UseWideAlias {
  int run(AbstractComponentCallbacksC0168x x) { x.mo154e(); return x.f798P; }
}
""")
        write(java3/"lib/AbstractComponentCallbacksC0168x.java", """
package lib;
public abstract class AbstractComponentCallbacksC0168x {
  public int f798P;
  public void mo154e() {}
}
""")
        # Unrelated class deliberately has the same raw field name P with a different
        # JADX alias.  That alias must NOT be sprayed onto lib.x.
        write(java3/"other/C0002z.java", """
package other; public class C0002z { public String f999P; }
""")
        write(orig3/"smali/lib/x.smali", """
.class public abstract Llib/x;
.super Ljava/lang/Object;
.field public P:I
.method public e()V
 .locals 0
 return-void
.end method
""")
        write(orig3/"smali/other/z.smali", """
.class public Lother/z;
.super Ljava/lang/Object;
.field public P:Ljava/lang/String;
""")
        jar3=out3/"shadow.jar"; own3=out3/"o.json"; bin3=out3/"b.txt"
        run(*jr,"shadow","--java-root",java3,"--original",orig3,"--out",jar3,
            "--ownership",own3,"--source-list",bin3,"--app-prefix","com.example")
        c3=out3/"classes"; c3.mkdir()
        run("javac","-cp",jar3,"-d",c3,java3/"com/example/UseWideAlias.java")
        jv=run("javap","-classpath",jar3,"-p","lib.AbstractComponentCallbacksC0168x").stdout
        assert "mo154e()" in jv and "f798P" in jv
        assert "f999P" not in jv, jv
        print("PASS generalized JADX class alias maps AbstractComponentCallbacksC####x -> raw x")
        print("PASS JADX mo####x override aliases map to raw method names")
        print("PASS member aliases remain owner-scoped; no global suffix fan-out")

        # v27 linker: provider Java can be completely absent.  Caller-side member
        # selections plus the owner type are enough to link a JADX alias to the
        # exact raw member on that owner only.
        java4=t/"uselink/src"; orig4=t/"uselink/original"; out4=t/"uselink/out"; out4.mkdir(parents=True)
        write(java4/"com/example/UseOnly.java", """
package com.example;
import linked.C0042x;
class UseOnly {
  int run(C0042x x) { x.f777n++; return x.m888a(3); }
}
""")
        write(orig4/"smali/linked/x.smali", """
.class public Llinked/x;
.super Ljava/lang/Object;
.field public n:I
.method public a(I)I
 .locals 0
 const/4 v0, 0x0
 return v0
.end method
""")
        jar4=out4/"shadow.jar"; own4=out4/"o.json"; bin4=out4/"b.txt"
        run(*jr,"shadow","--java-root",java4,"--original",orig4,"--out",jar4,
            "--ownership",own4,"--source-list",bin4,"--app-prefix","com.example")
        c4=out4/"classes"; c4.mkdir()
        run("javac","-cp",jar4,"-d",c4,java4/"com/example/UseOnly.java")
        jv4=run("javap","-classpath",jar4,"-p","linked.C0042x").stdout
        assert "f777n" in jv4 and "m888a(int)" in jv4, jv4
        print("PASS caller-only owner-scoped aliases rebuild a missing provider ABI")

        # v27 semantic fixed-point linker: the second alias cannot be linked from
        # syntax alone because its receiver is itself an unresolved field selection.
        # Round 1 links f777n on x; the rebuilt shadow gives f777n its DEX type
        # linked.y; round 2 can then attribute that receiver and link m888a on y.
        java5=t/"semantic-chain/src"; orig5=t/"semantic-chain/original"; out5=t/"semantic-chain/out"; out5.mkdir(parents=True)
        write(java5/"com/example/UseChain.java", """
package com.example;
import linked.C0042x;
class UseChain { int run(C0042x x) { return x.f777n.m888a(3); } }
""")
        write(orig5/"smali/linked/x.smali", """
.class public Llinked/x;
.super Ljava/lang/Object;
.field public n:Llinked/y;
""")
        write(orig5/"smali/linked/y.smali", """
.class public Llinked/y;
.super Ljava/lang/Object;
.method public a(I)I
 .locals 0
 const/4 v0, 0x0
 return v0
.end method
""")
        jar5=out5/"shadow.jar"; own5=out5/"o.json"; bin5=out5/"b.txt"
        run(*jr,"shadow","--java-root",java5,"--original",orig5,"--out",jar5,
            "--ownership",own5,"--source-list",bin5,"--app-prefix","com.example")
        c5=out5/"classes"; c5.mkdir()
        run("javac","-cp",jar5,"-d",c5,java5/"com/example/UseChain.java")
        x5=run("javap","-classpath",jar5,"-p","linked.C0042x").stdout
        y5=run("javap","-classpath",jar5,"-p","linked.y").stdout
        assert "f777n" in x5, x5
        assert "m888a(int)" in y5, y5
        print("PASS iterative javac linker resolves chained aliases across shadow regeneration rounds")

        # v27 exact JOBF linker: aliases that have no C####/m####/f#### shape at all
        # must still be recovered because JADX itself persisted the exact raw owner+descriptor.
        java6=t/"jobf/src"; orig6=t/"jobf/original"; out6=t/"jobf/out"; out6.mkdir(parents=True)
        write(java6/"com/example/UseJobf.java", """
package com.example;
import weird.pretty.Widget;
class UseJobf { int run(Widget w) { w.setTitle("x"); return w.meaningfulCount; } }
""")
        write(orig6/"smali/zz/q/a.smali", """
.class public Lzz/q/a;
.super Ljava/lang/Object;
.field public b:I
.method public c(Ljava/lang/String;)V
 .locals 0
 return-void
.end method
""")
        jobf=out6/"renames.jobf"
        write(jobf, """
p zz.q = weird.pretty
c zz.q.a = Widget
f zz.q.a.b:I = meaningfulCount
m zz.q.a.c(Ljava/lang/String;)V = setTitle
""")
        jar6=out6/"shadow.jar"; own6=out6/"o.json"; bin6=out6/"b.txt"
        run(*jr,"shadow","--java-root",java6,"--original",orig6,"--out",jar6,
            "--ownership",own6,"--source-list",bin6,"--app-prefix","com.example","--jadx-map",jobf)
        c6=out6/"classes"; c6.mkdir()
        run("javac","-cp",jar6,"-d",c6,java6/"com/example/UseJobf.java")
        jv6=run("javap","-classpath",jar6,"-p","weird.pretty.Widget").stdout
        assert "meaningfulCount" in jv6 and "setTitle(java.lang.String)" in jv6, jv6
        print("PASS exact JADX JOBF class/package/member mappings override alias heuristics")

        # v27.1: same raw method name + same arity must not receive one alias on
        # every overload. javac-attributed argument types choose the exact descriptor.
        java7=t/"overload/src"; orig7=t/"overload/original"; out7=t/"overload/out"; out7.mkdir(parents=True)
        write(java7/"com/example/UseOverload.java", """
package com.example;
import linked.C0099x;
class UseOverload { int run(C0099x x) { return x.m777a("hello"); } }
""")
        write(orig7/"smali/linked/x.smali", """
.class public Llinked/x;
.super Ljava/lang/Object;
.method public a(I)I
 .locals 0
 const/4 v0, 0x0
 return v0
.end method
.method public a(Ljava/lang/String;)I
 .locals 0
 const/4 v0, 0x0
 return v0
.end method
""")
        jar7=out7/"shadow.jar"; own7=out7/"o.json"; bin7=out7/"b.txt"
        run(*jr,"shadow","--java-root",java7,"--original",orig7,"--out",jar7,
            "--ownership",own7,"--source-list",bin7,"--app-prefix","com.example")
        c7=out7/"classes"; c7.mkdir()
        run("javac","-cp",jar7,"-d",c7,java7/"com/example/UseOverload.java")
        jv7=run("javap","-classpath",jar7,"-p","linked.C0099x").stdout
        assert "m777a(java.lang.String)" in jv7, jv7
        assert "m777a(int)" not in jv7, jv7
        print("PASS javac argument attribution selects one exact overloaded DEX descriptor for an alias")

if __name__ == "__main__": main()
