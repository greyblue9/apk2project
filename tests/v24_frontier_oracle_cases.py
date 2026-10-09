#!/usr/bin/env python3
from pathlib import Path
import tempfile, textwrap, sys, subprocess, shutil
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import source_repair as sr


def apply(text, edits):
    for e in sorted(edits, key=lambda x:(x.start,x.end), reverse=True):
        text=text[:e.start]+e.replacement+text[e.end:]
    return text


def test_smali_oracle():
    root=Path(tempfile.mkdtemp()); java=root/'app/src/main/java'; ana=root/'analysis'
    pkg=java/'androidx/recyclerview/widget'; pkg.mkdir(parents=True)
    rv=pkg/'RecyclerView.java'; rv.write_text('package androidx.recyclerview.widget;\npublic class RecyclerView {\n}\n')
    (pkg/'AbstractC0391b1.java').write_text('package androidx.recyclerview.widget; public abstract class AbstractC0391b1 {}\n')
    caller=java/'x/T.java'; caller.parent.mkdir(parents=True)
    caller.write_text('package x; import androidx.recyclerview.widget.*; class T { void f(android.view.View v){ AbstractC0391b1 h=RecyclerView.m814I(v); } }\n')
    sm=root/'original/smali/androidx/recyclerview/widget'; sm.mkdir(parents=True)
    (sm/'RecyclerView.smali').write_text(textwrap.dedent('''
        .class public Landroidx/recyclerview/widget/RecyclerView;
        .super Ljava/lang/Object;
        .field public t0:Ljava/util/ArrayList;
        .method public static I(Landroid/view/View;)Landroidx/recyclerview/widget/b1;
        .end method
    '''))
    idx=sr.ProjectIndex.build(java); helper=sr.JavaAstHelper(ana); oracle=sr.SmaliOracle(java,idx)
    model=sr.SourceModel(caller, caller.read_text(), helper.analyze(caller))
    d=sr.JavacDiagnostic(str(caller),1,None,'error','cannot find symbol','method','m814I(View)','class RecyclerView',())
    e=sr._smali_oracle_member_edit(d,model,idx,oracle)
    assert e and 'static AbstractC0391b1 m814I(android.view.View p0)' in e.replacement
    print('PASS smali oracle reconstructs JADX-aliased RecyclerView method signature')


def test_binary_nested():
    p=Path(tempfile.mkdtemp())/'T.java'
    txt='import android.view.WindowInsetsAnimation$Callback;\nclass T extends WindowInsetsAnimation$Callback {}\n'
    p.write_text(txt)
    m=sr.SourceModel(p,txt,[])
    d=sr.JavacDiagnostic(str(p),1,None,'error','cannot find symbol','class','WindowInsetsAnimation$Callback',None,())
    e=sr._binary_nested_name_edit(d,m)
    assert e and e.replacement=='android.view.WindowInsetsAnimation.Callback'
    print('PASS JVM $ nested class spelling normalized to Java source syntax')


def test_constructor_chain():
    root=Path(tempfile.mkdtemp()); p=root/'C.java'
    txt=textwrap.dedent('''
        class C {
          C(byte[] b, java.util.Map m, java.util.List l, boolean z) {}
          C(byte[] b, java.util.List l, boolean z) {
            java.util.Map treeMap = null;
            treeMap = java.util.Collections.EMPTY_MAP;
            treeMap = new java.util.TreeMap(String.CASE_INSENSITIVE_ORDER);
            this(b, treeMap, l, z);
          }
        }
    ''')
    p.write_text(txt); helper=sr.JavaAstHelper(root/'a'); model=sr.SourceModel(p,txt,helper.analyze(p)); idx=sr.ProjectIndex.build(root)
    line=7
    d=sr.JavacDiagnostic(str(p),line,None,'error','call to this must be first statement in constructor',None,None,None,())
    e=sr._constructor_chain_first_edit(d,model,idx)
    assert e and 'this(' in e.replacement and 'new java.util.TreeMap' in e.replacement
    fixed=apply(txt,[e]); p.write_text(fixed)
    javac=shutil.which('javac'); r=subprocess.run([javac,str(p)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    assert r.returncode==0, r.stdout
    print('PASS pre-this() decompiler temporaries inlined into first constructor statement')


def test_numeric():
    p=Path(tempfile.mkdtemp())/'T.java'; txt='class T { boolean b; void f(){ b = 1; } }\n'; p.write_text(txt)
    m=sr.SourceModel(p,txt,[])
    d=sr.JavacDiagnostic(str(p),1,None,'error','incompatible types: int cannot be converted to boolean',None,None,None,())
    e=sr._numeric_sentinel_edit(d,m,'aggressive')
    assert e and e.replacement=='true'
    print('PASS int-to-boolean DEX lowering repair')


def test_alias_inverse():
    assert sr.jadx_alias_to_raw_fqcn('p036i1.AbstractC0570m')=='i1.m'
    assert sr.jadx_alias_to_raw_fqcn('androidx.emoji2.text.C0115w')=='androidx.emoji2.text.w'
    assert sr.jadx_member_to_raw('m814I','method')=='I'
    assert sr.jadx_member_to_raw('f1103t0','field')=='t0'
    print('PASS inverse JADX alias mapping')

if __name__=='__main__':
    test_alias_inverse(); test_smali_oracle(); test_binary_nested(); test_constructor_chain(); test_numeric()
    print('ALL V24 FRONTIER/ORACLE CASES PASS')

def test_frontier_expansion_commit():
    root=Path(tempfile.mkdtemp()); src=root/'src'; src.mkdir(); ana=root/'analysis'; changed=src/'A.java'; changed.write_text('class A {}\n')
    s=sr.SourceRepairSession(src,ana,mode='aggressive')
    before='\n'.join(f'{changed}:{i+1}: error: call to this must be first statement in constructor' for i in range(3))+'\n'
    # register as if an external high-confidence blocker fix changed A.java
    backup=root/'A.bak'; backup.write_text(changed.read_text())
    assert s.register_external_transaction(before,backups={str(changed):str(backup)},changed_files=[str(changed)],label='frontier-test')
    after_lines=[]
    for i in range(100):
        f=src/f'B{i%20}.java'
        after_lines.append(f'{f}:{i+1}: error: cannot find symbol')
        after_lines.append('  symbol:   variable x')
        after_lines.append('  location: class B')
    r=s.observe_build('\n'.join(after_lines)+'\n')
    assert r.committed and not r.rolled_back, r
    assert s.frontier_epoch==1
    print('PASS blocker repair may advance compiler frontier even when newly visible error count rises')

# Re-run when invoked directly after the earlier block. This deliberately lives at
# the end so older Python test runners that import the file are unaffected.
if __name__=='__main__':
    test_frontier_expansion_commit()

def test_provider_rescue():
    root=Path(tempfile.mkdtemp()); java=root/'app/src/main/java'; ana=root/'analysis'; java.mkdir(parents=True)
    caller=java/'androidx/emoji2/text/C.java'; caller.parent.mkdir(parents=True)
    caller.write_text('package androidx.emoji2.text; import androidx.recyclerview.widget.RecyclerView; class C { void f(android.view.View v){ RecyclerView.m814I(v); } }\n')
    removed=root/'removed-library-sources/androidx/recyclerview/widget'; removed.mkdir(parents=True)
    (removed/'RecyclerView.java').write_text('package androidx.recyclerview.widget; public class RecyclerView { public static Object m814I(Object v){ return null; } }\n')
    sm=root/'original/smali/androidx/recyclerview/widget'; sm.mkdir(parents=True)
    (sm/'RecyclerView.smali').write_text('.class public Landroidx/recyclerview/widget/RecyclerView;\n.super Ljava/lang/Object;\n.method public static I(Landroid/view/View;)Ljava/lang/Object;\n.end method\n')
    sess=sr.SourceRepairSession(java,ana,mode='aggressive')
    out=f'{caller}:1: error: cannot find symbol\n  symbol:   method m814I(View)\n  location: class RecyclerView\n'
    rr=sess.repair(out)
    restored=java/'androidx/recyclerview/widget/RecyclerView.java'
    assert restored.is_file() and rr.edits and rr.edits[0].kind=='restore-smali-provider-source'
    print('PASS missing APK-private member resurrects over-pruned whole provider source')

if __name__=='__main__':
    test_provider_rescue()

def test_bulk_provider_surface():
    root=Path(tempfile.mkdtemp()); java=root/'app/src/main/java'; ana=root/'analysis'
    provider=java/'androidx/recyclerview/widget/RecyclerView.java'; provider.parent.mkdir(parents=True)
    provider.write_text('package androidx.recyclerview.widget; public class RecyclerView {}\n')
    caller=java/'x/T.java'; caller.parent.mkdir(parents=True)
    caller.write_text(textwrap.dedent('''
        package x;
        import androidx.recyclerview.widget.RecyclerView;
        class T { void f(Object v, RecyclerView rv) { RecyclerView.m814I(v); rv.f1103t0.add(null); } }
    '''))
    sm=root/'original/smali/androidx/recyclerview/widget'; sm.mkdir(parents=True)
    (sm/'RecyclerView.smali').write_text(textwrap.dedent('''
        .class public Landroidx/recyclerview/widget/RecyclerView;
        .super Ljava/lang/Object;
        .field public t0:Ljava/util/ArrayList;
        .method public static I(Ljava/lang/Object;)Ljava/lang/Object;
        .end method
    '''))
    out='\n'.join([
        f'{caller}:3: error: cannot find symbol',
        '  symbol:   method m814I(Object)',
        '  location: class RecyclerView',
        f'{caller}:3: error: cannot find symbol',
        '  symbol:   variable f1103t0',
        '  location: variable rv of type RecyclerView',
    ])+'\n'
    sess=sr.SourceRepairSession(java,ana,mode='aggressive',tree_trace='off')
    rr=sess.repair(out)
    text=provider.read_text()
    assert rr.changed_files and 'm814I' in text and 'f1103t0' in text, (rr,text)
    assert sess.pending and sess.pending.get('smali_provider_bulk')
    print('PASS bulk smali provider surface repairs multiple exact missing members before caller ownership filtering')

if __name__=='__main__':
    test_bulk_provider_surface()

def test_smali_field_type_correction():
    root=Path(tempfile.mkdtemp()); java=root/'app/src/main/java'; ana=root/'analysis'; pkg=java/'p'; pkg.mkdir(parents=True)
    target=pkg/'C0002y.java'; target.write_text('package p; public class C0002y {}\n')
    wrong=pkg/'C0003z.java'; wrong.write_text('package p; public class C0003z {}\n')
    owner=pkg/'C0001x.java'; owner.write_text(textwrap.dedent('''
        package p;
        public class C0001x {
          public C0003z f1a;
          void f() { this.f1a = new C0002y(); }
        }
    '''))
    sm=root/'original/smali/p'; sm.mkdir(parents=True)
    (sm/'x.smali').write_text(textwrap.dedent('''
        .class public Lp/x;
        .super Ljava/lang/Object;
        .field public a:Lp/y;
    '''))
    idx=sr.ProjectIndex.build(java); helper=sr.JavaAstHelper(ana,trace_level='off'); oracle=sr.SmaliOracle(java,idx)
    model=sr.SourceModel(owner,owner.read_text(),helper.analyze(owner))
    d=sr.JavacDiagnostic(str(owner),5,None,'error','incompatible types: C0002y cannot be converted to C0003z',None,None,None,())
    e=sr._smali_oracle_field_type_edit(d,model,idx,helper,oracle)
    assert e and e.replacement=='C0002y', e
    print('PASS exact DEX field descriptor corrects a poisoned reconstructed field type at the provider')

if __name__=='__main__':
    test_smali_field_type_correction()

def test_error_island_quarantine_primitive():
    root=Path(tempfile.mkdtemp()); p=root/'T.java'; ana=root/'analysis'
    p.write_text(textwrap.dedent('''
        class T {
          int a() { return 1; }
          void b() { System.out.println("x"); }
        }
    '''))
    helper=sr.JavaAstHelper(ana,trace_level='off'); model=sr.SourceModel(p,p.read_text(),helper.analyze(p))
    method=next(m for m in model.methods if m.get('name')=='a')
    d=sr.JavacDiagnostic(str(p),3,None,'error','cannot find symbol','variable','r6','class T',())
    e=sr._quarantine_error_method(d,model,method,80)
    assert e and 'UnsupportedOperationException' in e.replacement and e.destructive
    print('PASS distributed toxic-class fallback can quarantine one failing method body transactionally')

if __name__=='__main__':
    test_error_island_quarantine_primitive()
