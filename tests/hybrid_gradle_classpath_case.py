#!/usr/bin/env python3
import importlib.util
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("apk2project", ROOT / "apk2project.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "app/libs").mkdir(parents=True)
    (root / "app/build.gradle").write_text('plugins { id "com.android.application" }\n')
    shadow = root / "app/libs/apk2project-apk-shadow-abi.jar"
    shadow.write_bytes(b"not-a-real-jar-needed-for-config-test")
    binary = root / "app/apk2project-binary-sources.txt"
    binary.write_text("lib/C0001x.java\n")

    assert mod.configure_hybrid_shadow_gradle(root, shadow, binary)
    text = (root / "app/build.gradle").read_text()

    assert 'classpath = files("libs/apk2project-apk-shadow-abi.jar") + classpath' not in text
    assert 'doFirst {' in text
    assert 'def agpClasspath = task.classpath ?: project.files()' in text
    assert 'task.classpath = project.files(file("libs/apk2project-apk-shadow-abi.jar"), agpClasspath)' in text
    assert 'replace(java.io.File.separator, "/")' in text
    assert "replace('\\\\', '/')" not in text
    print("PASS hybrid shadow classpath injection tolerates AGP null classpath during configuration")
