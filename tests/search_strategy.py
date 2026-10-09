#!/usr/bin/env python3
from __future__ import annotations
import tempfile, sys
from dataclasses import asdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from source_repair import SourceRepairSession, Edit, parse_javac_diagnostics, diagnostic_cost, diagnostic_fingerprint, _batch_signature

def diag_text(n:int, prefix='E') -> str:
    out=[]
    for i in range(n):
        out += [f'/tmp/T{i}.java:{i+1}: error: cannot find symbol', f'  symbol:   variable {prefix}{i}', '  location: class T']
    return '\n'.join(out)+'\n'

with tempfile.TemporaryDirectory(prefix='v22-search-') as td:
    base=Path(td); src=base/'src'; ana=base/'analysis'; src.mkdir(); ana.mkdir()
    f=src/'T.java'; f.write_text('class T { int x; }\n')
    s=SourceRepairSession(src,ana,mode='aggressive',min_confidence=.5,max_rounds=20,logger=lambda x: None)

    before=diag_text(33,'B')
    edits=[Edit(str(f),0,0,f'/*e{i}*/','test-rule',.9,f'test {i}',{'file':str(f),'line':i+1,'message':'cannot find symbol','symbol_kind':'variable','symbol_name':f'B{i}'}) for i in range(4)]
    backup=ana/'backup.java'; backup.write_text(f.read_text())
    f.write_text('BROKEN\n')
    s.pending={
      'round':1,'before_error_count':33,'before_fingerprint':diagnostic_fingerprint(parse_javac_diagnostics(before)),
      'before_cost':list(diagnostic_cost(parse_javac_diagnostics(before))),
      'before_keys':sorted(repr(d.key()) for d in parse_javac_diagnostics(before)),
      'backups':{str(f):str(backup)},'edit_signatures':[e.signature() for e in edits],
      'strategy_keys':[e.strategy_key() for e in edits], 'batch_signature':_batch_signature(edits),
      'changed_files':[str(f)],'edits':[asdict(e) for e in edits]
    }
    outcome=s.observe_build(diag_text(100,'A'))
    assert outcome.rolled_back and not outcome.committed, outcome
    assert f.read_text()=='class T { int x; }\n'
    assert len(s.retry_batches)==2, s.retry_batches
    assert not any(e.signature() in s.rejected for e in edits), 'mixed batch should be bisected, not blacklist all edits'
    print('PASS 33-to-100 unconditional rollback + batch bisection')

    # A singleton regression is precise enough to blacklist that candidate.
    s.retry_batches.clear()
    e=edits[0]; backup.write_text(f.read_text()); f.write_text('BROKEN2\n')
    s.pending={
      'round':2,'before_error_count':33,'before_fingerprint':diagnostic_fingerprint(parse_javac_diagnostics(before)),
      'before_cost':list(diagnostic_cost(parse_javac_diagnostics(before))),
      'before_keys':sorted(repr(d.key()) for d in parse_javac_diagnostics(before)),
      'backups':{str(f):str(backup)},'edit_signatures':[e.signature()], 'strategy_keys':[e.strategy_key()],
      'batch_signature':_batch_signature([e]),'changed_files':[str(f)],'edits':[asdict(e)]
    }
    outcome=s.observe_build(diag_text(34,'C'))
    assert outcome.rolled_back and e.signature() in s.rejected
    print('PASS singleton regression blacklists exact candidate')

    # Fewer errors is always accepted even when the diagnostic identities change.
    e2=edits[1]; backup.write_text(f.read_text()); f.write_text('BETTER\n')
    s.pending={
      'round':3,'before_error_count':33,'before_fingerprint':diagnostic_fingerprint(parse_javac_diagnostics(before)),
      'before_cost':list(diagnostic_cost(parse_javac_diagnostics(before))),
      'before_keys':sorted(repr(d.key()) for d in parse_javac_diagnostics(before)),
      'backups':{str(f):str(backup)},'edit_signatures':[e2.signature()], 'strategy_keys':[e2.strategy_key()],
      'batch_signature':_batch_signature([e2]),'changed_files':[str(f)],'edits':[asdict(e2)]
    }
    outcome=s.observe_build(diag_text(32,'N'))
    assert outcome.committed and not outcome.rolled_back
    print('PASS monotonic improvement commits lower error count')
