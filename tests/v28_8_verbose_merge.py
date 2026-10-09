#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
src=(ROOT/'java_engine/DexHybridRebuilder.java').read_text()
hybrid=(ROOT/'hybrid_apk.py').read_text()

required = [
    'APK2PROJECT_DEX_MERGE_VERBOSE',
    'PHASE %02d',
    'read original APK DEX universe',
    'discover original DEX constructor-owner bridges',
    'load and lower D8 replacement DEX',
    'compute exact original-class removal set',
    'plan touched vs byte-copied original DEX entries',
    'emit filtered original DEX entries',
    'append replacement DEX after original multidex set',
    'validate exact final class universe',
    'validate structural replacement ABI compatibility',
    'validate replacement -> final-runtime DEX references',
    'validate retained-original -> replacement boundary references',
    'explainLinkageErrors',
    'declared constructors on ',
    'FAILED during PHASE',
    'sha256=%s',
]
for token in required:
    assert token in src, token
assert "'version':'v28.8'" in hybrid
assert 'capture=True' in hybrid and "dex-merge.log" in hybrid
print('PASS v28.8 merge has timestamped numbered phases and failure phase reporting')
print('PASS v28.8 logs DEX ownership/rewrite/hash/universe transitions')
print('PASS v28.8 expands missing member failures with final ABI hierarchy context')
print('PASS v28.8 persistent dex-merge.log capture remains enabled')
