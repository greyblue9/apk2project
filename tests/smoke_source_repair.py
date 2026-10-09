#!/usr/bin/env python3
from __future__ import annotations
import subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from source_repair import SourceRepairSession


def javac(src: Path):
    files = [str(p.relative_to(src)) for p in src.rglob('*.java')]
    return subprocess.run(['javac', *files], cwd=src, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)


def main():
    with tempfile.TemporaryDirectory(prefix='apk2project-repair-test-') as td:
        base = Path(td); src = base/'src'; ana = base/'analysis'; (src/'p').mkdir(parents=True)
        (src/'p/Foo.java').write_text('package p; class Foo { void bar() {} }\n')
        test = src/'p/Test.java'
        test.write_text('''package p;
class Test {
  void x() {
    Object r0 = new Foo();
    r0.bar();
  }
}
''')
        before = javac(src)
        assert before.returncode != 0 and 'cannot find symbol' in before.stdout
        session = SourceRepairSession(src, ana, mode='balanced', logger=lambda s: print('[repair]', s))
        result = session.repair(before.stdout)
        assert result.changed_files, 'repair engine made no edit'
        assert 'Foo r0 = new Foo()' in test.read_text(), test.read_text()
        after = javac(src)
        outcome = session.observe_build(after.stdout, build_succeeded=(after.returncode == 0))
        assert after.returncode == 0, after.stdout
        assert outcome.committed and not outcome.rolled_back
        print('PASS: Object -> Foo inference, source edit, compile validation, transaction commit')


if __name__ == '__main__':
    main()
