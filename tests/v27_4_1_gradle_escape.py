#!/usr/bin/env python3
import importlib.util, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('apk2project_v2741', ROOT/'apk2project.py')
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory() as td:
    root=Path(td); (root/'app/libs').mkdir(parents=True)
    broken='''plugins { id "com.android.application" }\n// APK2PROJECT_V26_HYBRID_BEGIN\ndef bad = "x".replace('\\', '/')\n// APK2PROJECT_V26_HYBRID_END\n'''
    (root/'app/build.gradle').write_text(broken)
    shadow=root/'app/libs/apk2project-apk-shadow-abi.jar'; shadow.write_bytes(b'x')
    owned=root/'app/apk2project-binary-sources.txt'; owned.write_text('androidx/Foo.java\n')
    assert mod.configure_hybrid_shadow_gradle(root, shadow, owned)
    text=(root/'app/build.gradle').read_text()
    assert "replace('\\', '/')" not in text, text
    assert 'replace(java.io.File.separator, "/")' in text, text
    assert text.count('// APK2PROJECT_V26_HYBRID_BEGIN') == 1
    assert text.count('// APK2PROJECT_V26_HYBRID_END') == 1
print('PASS rerun repairs an already-malformed marked hybrid Gradle block before Gradle parses it')
