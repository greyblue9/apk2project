#!/usr/bin/env python3
from __future__ import annotations
import json
import tempfile
import sys
import collections
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from binary_islands import BinaryIslandManager
import apk2project as apk


def write_java(root: Path, fq: str, body: str):
    pkg, _, cls = fq.rpartition('.')
    p = root / Path(*pkg.split('.')) / f"{cls}.java"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"package {pkg};\npublic class {cls} {{\n{body}\n}}\n")
    return p


def test_glob_binary_island():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        java = root / "app/src/main/java"
        analysis = root / "analysis"
        a = write_java(java, "com.google.common.cache.RemovalCause", "  C13853(String s, int i) {}")
        b = write_java(java, "com.google.common.collect.BoundType", "  C14051(String s, int i) {}")
        c = write_java(java, "com.google.common.reflect.TypeToken", "  public Object okay(){ return null; }")
        app = write_java(java, "example.App", "  public void ok() {}")
        artifact = {
            "gav": ("com.google.guava", "guava", "33.4.8-android"),
            "type": "jar", "file": "/tmp/guava.jar", "transitive": True,
            "classes": {
                "com.google.common.cache.RemovalCause",
                "com.google.common.collect.BoundType",
                "com.google.common.reflect.TypeToken",
            },
        }
        out = (
            f"{a}:3: error: invalid method declaration; return type required\n"
            f"{b}:3: error: invalid method declaration; return type required\n"
        )
        mgr = BinaryIslandManager(root, java, analysis, [artifact], mode="safe")
        result = mgr.repair(out)
        assert result.changed
        assert len(result.changed_files) == 3, result.changed_files
        assert not a.exists() and not b.exists() and not c.exists()
        assert app.exists()
        assert result.plan.artifact.startswith("com.google.guava:guava:")
        print("PASS binary island expands two failing Guava classes to complete artifact/source overlap")


def test_alias_risk_retained_safe():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        java = root / "app/src/main/java"
        analysis = root / "analysis"
        p = write_java(
            java, "androidx.recyclerview.widget.RecyclerView",
            "  Object f1103t0; Object f1091n0; void m814I() {} void m867y() {}"
        )
        artifact = {
            "gav": ("androidx.recyclerview", "recyclerview", "1.4.0"),
            "type": "aar", "file": "/tmp/recyclerview.aar",
            "classes": {"androidx.recyclerview.widget.RecyclerView"},
        }
        out = f"{p}:3: error: cannot find symbol\n"
        mgr = BinaryIslandManager(root, java, analysis, [artifact], mode="safe")
        result = mgr.repair(out)
        assert not result.changed
        assert p.exists()
        print("PASS safe binary islands retain APK/R8 alias-heavy provider source")


def test_runtime_artifact_parser_includes_jars():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        jar = td / "guava.jar"; jar.write_bytes(b"x")
        aar = td / "appcompat.aar"; aar.write_bytes(b"x")
        raw = (
            f"APK2PROJECT_ARTIFACT\tcom.google.guava\tguava\t33.4.8-android\tjar\t{jar}\n"
            f"APK2PROJECT_ARTIFACT\tandroidx.appcompat\tappcompat\t1.7.1\taar\t{aar}\n"
        )
        got = apk.parse_gradle_runtime_artifacts(raw)
        assert {x['type'] for x in got} == {'jar','aar'}, got
        assert any(x['gav'][0] == 'com.google.guava' for x in got)
        print("PASS complete Gradle runtime inventory includes transitive JARs as well as AARs")



def test_emergency_dependency_promotion_logic():
    # No network: monkeypatch the resolver helpers so the test proves the scoring,
    # exact-class verification, and Gradle insertion behavior deterministically.
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        fakejar = td / 'guava.jar'; fakejar.write_bytes(b'not-a-real-jar-needed-by-mocks')
        old = {
            'package_index_candidates': apk.package_index_candidates,
            'google_candidates': apk.google_candidates,
            'central_class': apk.central_class,
            'validate_pom': apk.validate_pom,
            'artifact': apk.artifact,
            'classes_in': apk.classes_in,
            'package_similarity': apk.package_similarity,
            'pin': apk.pin,
        }
        try:
            gav = ('com.google.guava','guava','33.4.8-android')
            apk.package_index_candidates = lambda fq: []
            apk.google_candidates = lambda fq: []
            apk.central_class = lambda fq, rows=12: [{'g':gav[0],'a':gav[1],'v':gav[2]}]
            class H:
                ok=True; reason='synthetic valid POM'
            apk.validate_pom = lambda x: H()
            apk.artifact = lambda g,a,v,cache: (fakejar,'jar','https://repo1.maven.org/maven2')
            allclasses = {
                'com.google.common.cache.RemovalCause',
                'com.google.common.collect.BoundType',
                'com.google.common.reflect.TypeToken',
            }
            apk.classes_in = lambda p,t,tmp: set(allclasses)
            apk.package_similarity = lambda fq, gav: 1.0 if fq.startswith('com.google.common.') else 0.0
            apk.pin = lambda x: x
            rec, ev = apk.discover_binary_artifact_for_error_sources(
                collections.Counter({
                    'com.google.common.cache.RemovalCause': 3,
                    'com.google.common.collect.BoundType': 2,
                }), [], td, td, app_package='example.app'
            )
            assert rec and tuple(rec['gav']) == gav, rec
            assert len(rec['covers_error_classes']) == 2

            project = td / 'project'; (project/'app').mkdir(parents=True)
            (project/'app/build.gradle').write_text('dependencies {\n}\n')
            assert apk.ensure_gradle_dependency(project, gav)
            txt=(project/'app/build.gradle').read_text()
            assert 'com.google.guava:guava:33.4.8-android' in txt
            print('PASS javac-driven emergency promotion can discover exact library binary and inject Gradle dependency')
        finally:
            for k,v in old.items(): setattr(apk,k,v)

def test_resume_gradle_helper_injection():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); (root/'app').mkdir(parents=True)
        bg=root/'app/build.gradle'
        original='plugins { id "com.android.application" }\ndependencies {\n  implementation "x:y:1"\n}\n'
        bg.write_text(original)
        assert apk.ensure_runtime_artifact_inventory_task(root)
        text=bg.read_text()
        assert 'implementation "x:y:1"' in text
        assert 'apk2projectResolvedArtifacts' in text
        assert not apk.ensure_runtime_artifact_inventory_task(root)
        assert bg.read_text() == text
        print('PASS resume mode can append read-only runtime inventory without rewriting dependency classpath')

if __name__ == '__main__':
    test_glob_binary_island()
    test_alias_risk_retained_safe()
    test_runtime_artifact_parser_includes_jars()
    test_emergency_dependency_promotion_logic()
    test_resume_gradle_helper_injection()
    print('ALL BINARY ISLAND CASES PASS')
