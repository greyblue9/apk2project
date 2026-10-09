#!/usr/bin/env python3
import importlib.util, sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('apk2project',ROOT/'apk2project.py')
apk=importlib.util.module_from_spec(spec); sys.modules[spec.name]=apk; spec.loader.exec_module(apk)

def main():
    with tempfile.TemporaryDirectory(prefix='v27-shadow-tx-') as td:
        root=Path(td); java=root/'app/src/main/java'; java.mkdir(parents=True)
        (java/'X.java').write_text('class X {}\n')
        (root/'app').mkdir(exist_ok=True); (root/'app/build.gradle').write_text('plugins {}\n')
        original=root/'original'; original.mkdir(); analysis=root/'analysis'; analysis.mkdir()
        live=root/'app/libs/apk2project-apk-shadow-abi.jar'; live.parent.mkdir(parents=True); live.write_bytes(b'KNOWN_GOOD')
        own=analysis/'hybrid-source-ownership.json'; own.write_text('KNOWN_GOOD_OWN')
        bl=root/'app/apk2project-binary-sources.txt'; bl.write_text('old.java\n')
        fake_apk=root/'app.apk'; fake_apk.write_bytes(b'not-used-by-mock')
        engine=root/'engine'; engine.mkdir()

        old_ensure=apk.ensure_hybrid_java_engine; old_run=apk.run; old_sub=apk.subprocess.run
        try:
            apk.ensure_hybrid_java_engine=lambda project_root: engine
            def fake_run(cmd, check=False, capture=False, **kw):
                cmd=list(map(str,cmd))
                def val(flag): return Path(cmd[cmd.index(flag)+1])
                out=val('--out'); o=val('--ownership'); s=val('--source-list')
                out.parent.mkdir(parents=True,exist_ok=True); out.write_bytes(b'POISON_CANDIDATE')
                o.parent.mkdir(parents=True,exist_ok=True); o.write_text('POISON_OWN')
                s.parent.mkdir(parents=True,exist_ok=True); s.write_text('poison.java\n')
                return SimpleNamespace(returncode=0,stdout='candidate generated\n')
            apk.run=fake_run
            apk.subprocess.run=lambda *a,**k: SimpleNamespace(returncode=3,stdout='validator rejected candidate\n')
            try:
                apk.build_hybrid_shadow(root,java,original,['example'],apk_path=fake_apk)
                raise AssertionError('expected validator rejection')
            except RuntimeError:
                pass
            assert live.read_bytes()==b'KNOWN_GOOD'
            assert own.read_text()=='KNOWN_GOOD_OWN'
            assert bl.read_text()=='old.java\n'
            print('PASS rejected shadow candidate cannot overwrite last known-good live checkpoint')

            apk.subprocess.run=lambda *a,**k: SimpleNamespace(returncode=0,stdout='validator accepted candidate\n')
            shadow,ownership,binary=apk.build_hybrid_shadow(root,java,original,['example'],apk_path=fake_apk)
            assert shadow.read_bytes()==b'POISON_CANDIDATE'  # promoted because mock validator accepted it
            assert ownership.read_text()=='POISON_OWN'
            assert binary.read_text()=='poison.java\n'
            print('PASS validated shadow candidate is atomically promoted with ownership/source-list checkpoint')
        finally:
            apk.ensure_hybrid_java_engine=old_ensure; apk.run=old_run; apk.subprocess.run=old_sub

if __name__=='__main__': main()
