#!/usr/bin/env python3
from __future__ import annotations
import json, tempfile, sys, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from source_repair import SourceRepairSession
from apk2project import snapshot_resume_checkpoint

def errs(path,n,prefix='E'):
    out=[]
    for i in range(n):
        out += [f'{path}:{i+1}: error: cannot find symbol', f'  symbol:   variable {prefix}{i}', '  location: class T']
    return '\n'.join(out)+'\n'

with tempfile.TemporaryDirectory(prefix='v23-resume-') as td:
    root=Path(td); java=root/'app/src/main/java'; java.mkdir(parents=True)
    f=java/'T.java'; good='class T { int good = 1; }\n'; f.write_text(good)
    (root/'app/build.gradle').write_text('dependencies {}\n')
    ana=root/'analysis'; ana.mkdir()
    s=SourceRepairSession(java,ana,mode='balanced',logger=lambda x: None)
    baseline=errs(f,3,'B')
    s.repair(baseline)  # records best cost even if it finds no useful edit
    backup=ana/'pre-targeted.java'; backup.write_text(good)
    f.write_text('class T { BROKEN }\n')
    assert s.register_external_transaction(baseline,backups={str(f.resolve()):str(backup)},changed_files=[str(f.resolve())],label='targeted-jadx')
    # A resource failure must not be interpreted as zero Java errors.
    r=s.observe_build('Execution failed for task :app:processDebugResources\nAndroid resource linking failed\n',build_succeeded=False)
    assert not r.had_pending and s.pending is not None
    # A real 1000-error javac result must restore exact pre-targeted bytes.
    r=s.observe_build(errs(f,1000,'A'),build_succeeded=False)
    assert r.rolled_back and f.read_text()==good
    # State/history must survive a second Python process/session.
    h1=json.loads((ana/'source-repair/history.json').read_text())
    s2=SourceRepairSession(java,ana,mode='balanced',logger=lambda x: None)
    assert len(s2.history)==len(h1) and s2.best_cost[0]==3
    # Emergency resume snapshot includes source + classpath config.
    z=snapshot_resume_checkpoint(root,keep=2)
    with zipfile.ZipFile(z) as q: names=set(q.namelist())
    assert 'app/src/main/java/T.java' in names and 'app/build.gradle' in names
    print('PASS 3-to-1000 targeted JADX rollback')
    print('PASS pre-javac failure does not validate source transaction')
    print('PASS blacklist/history state persists across sessions')
    print('PASS resume safety snapshot')
