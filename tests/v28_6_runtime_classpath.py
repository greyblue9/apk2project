#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, os, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('hybrid_apk_v286',ROOT/'hybrid_apk.py')
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)

with tempfile.TemporaryDirectory(prefix='v28.6-runtime-cp-') as td:
    td=Path(td)
    engine=td/'engine-classes'; engine.mkdir()
    dexlib=td/'smali-dexlib2-3.0.10.jar'; dexlib.write_bytes(b'jar')
    guava=td/'guava-31.1-android.jar'; guava.write_bytes(b'jar')
    seen=[]

    class Result:
        returncode=0
        stdout='ok\n'

    def fake_run(cmd, *, cwd=None, capture=False, check=True):
        seen.append(([str(x) for x in cmd], capture, check))
        return Result()

    h._run=fake_run
    h.run_dex_helper(engine,[dexlib,guava],'probe-dexlib',capture=True)
    cmd,capture,check=seen[-1]
    assert cmd[:2]==['java','-cp']
    assert cmd[2]==os.pathsep.join(map(str,[engine,dexlib,guava]))
    assert cmd[3:]==['apk2project.hybrid.DexHybridRebuilder','probe-dexlib']
    assert capture is True and check is True

    work=td/'work'; work.mkdir()
    original=td/'app.apk'; original.write_bytes(b'apk')
    def fake_helper(actual_engine, actual_cp, *args, capture=False, check=True):
        assert actual_engine==engine
        assert actual_cp==[dexlib,guava]
        assert args[0]=='inventory'
        report=Path(args[args.index('--report')+1])
        report.write_text('{"dex": {"classes.dex": []}}')
        return Result()
    h.run_dex_helper=fake_helper
    inv=h.inventory_apk(original,engine,[dexlib,guava],work)
    assert inv=={'dex':{'classes.dex':[]}}

source=(ROOT/'hybrid_apk.py').read_text()
# All launches of the directly linked helper must flow through run_dex_helper.
assert source.count("'apk2project.hybrid.DexHybridRebuilder'")==1
assert 'inv=inventory_apk(original_apk,engine,dexlib_cp,work)' in source

print('PASS DexHybridRebuilder runtime classpath includes engine + complete dexlib bundle')
print('PASS inventory uses the canonical runtime helper launcher')
print('PASS probe/inventory/merge cannot independently drop dexlib from -cp')
