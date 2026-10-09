#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, shutil, sys, tempfile, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import hybrid_apk

def write(p:Path,b:bytes|str):
    p.parent.mkdir(parents=True,exist_ok=True)
    if isinstance(b,str):p.write_text(b)
    else:p.write_bytes(b)

def main():
  with tempfile.TemporaryDirectory(prefix='apk2project-v28-') as td:
    t=Path(td); project=t/'project'; (project/'analysis').mkdir(parents=True)
    own={
      'app_sources':['io/example/App.java','io/example/R.java','io/example/Worker.java'],
      'source_to_raw':{'io.example.App':'io.example.App','io.example.R':'io.example.R','io.example.Worker':'io.example.Worker'},
    }
    write(project/'analysis/hybrid-source-ownership.json',json.dumps(own))
    inv={'dex':{'classes.dex':['Lio/example/App;','Lio/example/Worker;','Lio/example/BinaryOnly;']}}
    p=hybrid_apk.plan_replacements(project,inv)
    assert [x['fqcn'] for x in p['runtime']]==['io.example.App','io.example.Worker'],p
    assert p['scaffolding'][0]['fqcn']=='io.example.R',p
    print('PASS runtime plan excludes R.java and preserves binary-only classes')

    # Compiled-class collector takes each runtime owner plus javac-generated nested classes,
    # but never unrelated R/BuildConfig output.
    cr=t/'classes'
    for n in ['io/example/App.class','io/example/App$1.class','io/example/Worker.class','io/example/R.class','io/example/BinaryOnly.class']:
      write(cr/n,n.encode())
    copied=hybrid_apk.collect_replacement_classes(cr,p,t/'input')
    names=sorted(str(x.relative_to(t/'input')) for x in copied)
    assert names==['io/example/App$1.class','io/example/App.class','io/example/Worker.class'],names
    print('PASS compiled replacement set includes owner companions but excludes scaffolding/unowned classes')

    # Compiled R integer constants must match the original public.xml universe because
    # the hybrid APK preserves the original resources.arsc and javac inlines these ints.
    rsrc=t/'rsrc/io/example/R.java'; rclasses=t/'rclasses'
    write(rsrc,'package io.example; public final class R { public static final class string { public static final int hello=0x7f120001; } }')
    subprocess = __import__('subprocess')
    subprocess.run(['javac','-d',rclasses,rsrc],check=True)
    public=project/'analysis/resource-backups/values/public.xml'
    write(public,'<?xml version="1.0"?><resources><public type="string" name="hello" id="0x7f120001"/></resources>')
    rid=hybrid_apk.validate_r_constants(project,rclasses,t/'rid-work')
    assert rid['checked_constants']==1 and not rid['mismatches'],rid
    write(public,'<?xml version="1.0"?><resources><public type="string" name="hello" id="0x7f120002"/></resources>')
    try:
      hybrid_apk.validate_r_constants(project,rclasses,t/'rid-work-bad')
      raise AssertionError('resource mismatch should have been fatal')
    except RuntimeError as e:
      assert 'resource IDs' in str(e)
    write(public,'<?xml version="1.0"?><resources><public type="string" name="hello" id="0x7f120001"/></resources>')
    print('PASS compiled R constants are gated against the original resource-ID universe')

    # APK ZIP rewrite preserves every non-DEX logical payload byte and removes old signatures.
    orig=t/'orig.apk'
    with zipfile.ZipFile(orig,'w') as z:
      z.writestr('classes.dex',b'OLDDEX',compress_type=zipfile.ZIP_DEFLATED)
      z.writestr('AndroidManifest.xml',b'BINARY-MANIFEST',compress_type=zipfile.ZIP_DEFLATED)
      z.writestr('resources.arsc',b'RESOURCES',compress_type=zipfile.ZIP_STORED)
      z.writestr('assets/a.bin',b'ASSET',compress_type=zipfile.ZIP_DEFLATED)
      z.writestr('lib/arm64-v8a/libx.so',b'ELF',compress_type=zipfile.ZIP_STORED)
      z.writestr('META-INF/OLD.SF',b'sig')
      z.writestr('META-INF/OLD.RSA',b'sig')
      z.writestr('META-INF/keep.version',b'1')
    dex=t/'dex';dex.mkdir();write(dex/'classes.dex',b'NEWDEX');write(dex/'classes2.dex',b'REPLACEMENTDEX')
    out=t/'out.apk';hybrid_apk.repack_apk(orig,dex,out)
    with zipfile.ZipFile(orig) as a,zipfile.ZipFile(out) as b:
      assert b.read('classes.dex')==b'NEWDEX' and b.read('classes2.dex')==b'REPLACEMENTDEX'
      for n in ['AndroidManifest.xml','resources.arsc','assets/a.bin','lib/arm64-v8a/libx.so','META-INF/keep.version']:
        assert a.read(n)==b.read(n),n
      assert 'META-INF/OLD.SF' not in b.namelist() and 'META-INF/OLD.RSA' not in b.namelist()
    print('PASS APK repack preserves manifest/resources/assets/native payload and drops obsolete signatures')

    # v29 keeps the direct public dexlib boundary but owns the exact pinned bundle.
    # There is no user-supplied jar, Apktool shading fallback, or Gradle/Maven cache search.
    hybrid_src=(ROOT/'hybrid_apk.py').read_text()
    tool_src=(ROOT/'toolchain.py').read_text()
    assert '--dexlib-jar' not in hybrid_src
    assert 'DEXLIB_JAR' not in hybrid_src and '.gradle/caches' not in hybrid_src
    assert 'DEXLIB_BUNDLE' in tool_src and 'smali-dexlib2' in tool_src
    print('PASS hybrid runtime uses apk2project-owned pinned dexlib bundle with no per-jar override')

    # Runtime dealiasing: javac-facing class/member aliases must become exact raw
    # DEX names before D8.  Include an app-owned method alias from JOBF as well as
    # a binary-owner method alias from the shadow provenance manifest.
    src=t/'src'; fac=t/'facade'; compiled=t/'compiled'
    write(fac/'human/lib/AbstractC1.java','package human.lib; public class AbstractC1 { public static void m200y(String x) {} }')
    write(fac/'human/lib/Func.java','package human.lib; public interface Func { void m300z(String x); }')
    write(src/'io/example/App.java','package io.example; import human.lib.*; public class App { public void m100x(){ AbstractC1.m200y("x"); Func f = s -> AbstractC1.m200y(s); f.m300z("y"); } }')
    import subprocess
    subprocess.run(['javac','-d',compiled,fac/'human/lib/AbstractC1.java',fac/'human/lib/Func.java',src/'io/example/App.java'],check=True)
    inp=t/'dealias-in'; write(inp/'io/example/App.class',(compiled/'io/example/App.class').read_bytes())
    own2={
      'app_sources':['io/example/App.java'],
      'source_to_raw':{'io.example.App':'raw.app.a','human.lib.AbstractC1':'raw.lib.a','human.lib.Func':'raw.lib.f'},
      'jadx_map':str(t/'map.jobf'),
    }
    write(project/'analysis/hybrid-source-ownership.json',json.dumps(own2))
    write(t/'map.jobf','m raw.app.a.a()V = m100x\n')
    shadow=t/'shadow.jar'
    with zipfile.ZipFile(shadow,'w') as z:
      z.writestr('META-INF/apk2project-shadow-classes.tsv','#raw_owner\tshadow_owner\nraw.app.a\tio.example.App\nraw.lib.a\thuman.lib.AbstractC1\nraw.lib.f\thuman.lib.Func\n')
      z.writestr('META-INF/apk2project-shadow-aliases.tsv','#kind\tshadow_owner\traw_owner\traw_name\traw_desc\talias\tshadow_desc\nM\thuman.lib.AbstractC1\traw.lib.a\tb\t(Ljava/lang/String;)V\tm200y\t(Ljava/lang/String;)V\nM\thuman.lib.Func\traw.lib.f\ta\t(Ljava/lang/String;)V\tm300z\t(Ljava/lang/String;)V\n')
    wm=t/'dealias-work'; wm.mkdir()
    mp,mr=hybrid_apk.build_runtime_dealias_map(project,shadow,wm)
    engine=hybrid_apk.ensure_core_engine(ROOT,project)
    rawdir,dr=hybrid_apk.run_dealias(engine,inp,mp,wm)
    assert dr['output_classes']==['Lraw/app/a;'],dr
    rawcls=rawdir/'raw/app/a.class'; assert rawcls.is_file()
    jp=subprocess.run(['javap','-p','-c','-s',str(rawcls)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=True).stdout
    assert 'void a();' in jp,jp
    assert 'raw/lib/a.b:(Ljava/lang/String;)V' in jp,jp
    assert 'public void a();' in jp and 'm200y' not in jp and 'm300z' not in jp,jp
    jpv=subprocess.run(['javap','-p','-v',str(rawcls)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=True).stdout
    assert 'InvokeDynamic' in jpv and 'raw/lib/f' in jpv,jpv
    # The LambdaMetafactory call-site name itself must be raw 'a', not the source alias m300z.
    assert 'm300z' not in jpv,jpv
    print('PASS bytecode dealiaser rewrites app definitions and binary references to raw DEX ABI')
    print('PASS invokedynamic lambda SAM name is dealiased with its functional-interface ABI')

    # Structural ABI gate catches missing framework-visible/non-private members even
    # when no retained DEX instruction explicitly references them. Private implementation
    # details are warnings because a recompilation may legitimately eliminate them.
    harness=t/'AbiCompatHarness.java'
    write(harness,r'''package apk2project.hybrid;
import java.util.*;
public class AbiCompatHarness {
  public static void main(String[] a){
    DexReader.Clazz old=new DexReader.Clazz(); old.fqcn="x.A"; old.internal="x/A"; old.superDesc="Ljava/lang/Object;"; old.access=1;
    DexReader.Method pub=new DexReader.Method(); pub.name="onCreate"; pub.desc="()V"; pub.access=1; old.methods.add(pub);
    DexReader.Method priv=new DexReader.Method(); priv.name="secret"; priv.desc="()V"; priv.access=2; old.methods.add(priv);
    DexReader.Clazz now=new DexReader.Clazz(); now.fqcn="x.A"; now.internal="x/A"; now.superDesc="Ljava/lang/Object;"; now.access=1;
    Map<String,DexReader.Clazz> o=new HashMap<>(), n=new HashMap<>(); o.put("x.A",old); n.put("x.A",now);
    RuntimeAbiValidator.AbiCompat r=RuntimeAbiValidator.validateReplacementAbi(o,n,List.of("Lx/A;"));
    if(r.errors.size()!=1 || !r.errors.get(0).contains("onCreate")) throw new AssertionError(r.errors.toString());
    if(r.warnings.size()!=1 || !r.warnings.get(0).contains("secret")) throw new AssertionError(r.warnings.toString());
  }
}
''')
    hclasses=t/'hclasses'; hclasses.mkdir()
    subprocess.run(['javac','-cp',str(engine),'-d',hclasses,harness],check=True)
    subprocess.run(['java','-cp',str(hclasses)+__import__('os').pathsep+str(engine),'apk2project.hybrid.AbiCompatHarness'],check=True)
    print('PASS replacement ABI gate makes missing non-private members fatal and private omissions visible')

if __name__=='__main__':main()
