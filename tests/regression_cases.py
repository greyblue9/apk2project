#!/usr/bin/env python3
from __future__ import annotations
import subprocess, tempfile, sys, textwrap
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from source_repair import SourceRepairSession

def javac(src):
    files=[str(p.relative_to(src)) for p in src.rglob('*.java')]
    return subprocess.run(['javac','-Xlint:none','-nowarn',*files],cwd=src,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)

def repair_until(src, ana, max_rounds=10, mode='aggressive'):
    s=SourceRepairSession(src,ana,mode=mode,min_confidence=.65,max_rounds=max_rounds,logger=lambda x: None)
    p=javac(src)
    for _ in range(max_rounds+3):
        if p.returncode==0: return s,p
        r=s.repair(p.stdout)
        if not r.changed_files:
            return s,p
        p2=javac(src)
        s.observe_build(p2.stdout, build_succeeded=(p2.returncode == 0))
        p=p2
    return s,p

def write(base, rel, txt):
    p=base/rel; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(textwrap.dedent(txt)); return p

def scenario(name, files, assert_text=None):
    with tempfile.TemporaryDirectory(prefix='v21-'+name+'-') as td:
        src=Path(td)/'src'; ana=Path(td)/'analysis'; src.mkdir()
        paths={rel:write(src,rel,txt) for rel,txt in files.items()}
        before=javac(src)
        assert before.returncode!=0, f'{name}: unexpectedly compiled before repair'
        s,after=repair_until(src,ana)
        if after.returncode!=0:
            print('\nFAILED',name,'\n',after.stdout)
            for rel,p in paths.items(): print('---',rel,'---\n',p.read_text())
            raise SystemExit(1)
        if assert_text:
            rel, needle=assert_text
            assert needle in paths[rel].read_text(), (name, paths[rel].read_text())
        print('PASS',name)

scenario('lost-local',{
'p/T.java':'''package p; class T { void x(boolean b) { if (b) { Exception e2=new Exception(); e=e2; } else { RuntimeException e4=new RuntimeException(); e=e4; } System.out.println(e); } }'''
},('p/T.java','Exception e = null;'))

scenario('constructor-overload',{
'p/E.java':'''package p; class E extends RuntimeException { E() {} }''',
'p/T.java':'''package p; class T { void x(){ throw new E("msg"); } }'''
},('p/E.java','public E(String arg0) { this(); }'))

scenario('impossible-cast',{
'p/A.java':'''package p; class A {}''',
'p/B.java':'''package p; class B { void z(){} }''',
'p/H.java':'''package p; class H { A f; }''',
'p/T.java':'''package p; class T { H h=new H(); void x(){ ((B) h.f).z(); } }'''
},('p/T.java','(B) (Object)'))

scenario('enhanced-for',{
'p/A.java':'''package p; class A {}''',
'p/U.java':'''package p; class U { static Iterable<Object> items(){ return java.util.List.of(); } }''',
'p/T.java':'''package p; class T { void x(){ for (A a : U.items()) { System.out.println(a); } } }'''
},('p/T.java','(java.lang.Iterable<A>) (Object)'))

scenario('enum-compat',{
'p/EnumC1.java':'''package p; class EnumC1 { static final EnumC1 A=new EnumC1(); static final EnumC1 B=new EnumC1(); }''',
'p/T.java':'''package p; class T { int x(EnumC1 e, EnumC1 f){ return e.ordinal()+e.compareTo(f); } }'''
},('p/EnumC1.java','public int ordinal()'))

scenario('missing-field-add',{
'p/R.java':'''package p; class R {}''',
'p/T.java':'''package p; class T { void x(R r){ r.f1103t0.add(new Object()); } }'''
},('p/R.java','ArrayList<Object> f1103t0'))

scenario('missing-field-assign',{
'p/P.java':'''package p; class P {}''',
'p/T.java':'''package p; class T { Object f; void x(){ ((P)f).f989T = Integer.MAX_VALUE; } }'''
},('p/P.java','int f989T'))

print('ALL REGRESSION CASES PASS')
