#!/usr/bin/env python3
"""v28 hybrid APK runtime rebuilder.

Preserves the original APK resource/manifest/native-file payload, replaces only
validated source-owned DEX classes, and uses the official standalone Google
smali-dexlib2 API to rewrite touched DEX entries. Runtime DEX tooling is resolved
and compiled only after the validated app javac boundary succeeds. Untouched DEX
entries are byte-copied.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, subprocess, tempfile, zipfile, urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

DEX_RE = re.compile(r"^classes(?:\d+)?\.dex$")
SIG_RE = re.compile(r"^META-INF/[^/]+\.(?:RSA|DSA|EC|SF)$", re.I)
DEXLIB_PREFIX = "com/android/tools/smali/dexlib2"
DEXLIB_VERSION = "3.0.10"
DEXLIB_REQUIRED_SUFFIXES = (
    "Opcodes.class",
    "dexbacked/DexBackedDexFile.class",
    "iface/ClassDef.class",
    "iface/DexFile.class",
    "writer/pool/DexPool.class",
)

# Official Google smali artifact plus runtime dependencies.  Keep this independent
# of Apktool's fat/shaded jar: Apktool is free to shrink or alter its private copy.
DEXLIB_BUNDLE = (
    (f"smali-dexlib2-{DEXLIB_VERSION}.jar",
     f"https://dl.google.com/dl/android/maven2/com/android/tools/smali/smali-dexlib2/{DEXLIB_VERSION}/smali-dexlib2-{DEXLIB_VERSION}.jar"),
    ("guava-31.1-android.jar",
     "https://repo1.maven.org/maven2/com/google/guava/guava/31.1-android/guava-31.1-android.jar"),
    ("failureaccess-1.0.1.jar",
     "https://repo1.maven.org/maven2/com/google/guava/failureaccess/1.0.1/failureaccess-1.0.1.jar"),
    ("listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
     "https://repo1.maven.org/maven2/com/google/guava/listenablefuture/9999.0-empty-to-avoid-conflict-with-guava/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar"),
    ("jsr305-3.0.2.jar",
     "https://repo1.maven.org/maven2/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar"),
    ("checker-qual-3.12.0.jar",
     "https://repo1.maven.org/maven2/org/checkerframework/checker-qual/3.12.0/checker-qual-3.12.0.jar"),
    ("error_prone_annotations-2.11.0.jar",
     "https://repo1.maven.org/maven2/com/google/errorprone/error_prone_annotations/2.11.0/error_prone_annotations-2.11.0.jar"),
    ("j2objc-annotations-1.3.jar",
     "https://repo1.maven.org/maven2/com/google/j2objc/j2objc-annotations/1.3/j2objc-annotations-1.3.jar"),
)

JAVA_RUNTIME_EXPORTS = [
    '--add-exports', 'java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED',
]



def _run(cmd, *, cwd=None, capture=False, check=True):
    p = subprocess.run([str(x) for x in cmd], cwd=cwd, text=True,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None)
    if check and p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(map(str,cmd))}\n{p.stdout or ''}")
    return p


def _sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1<<20), b''): h.update(b)
    return h.hexdigest()


def _jar_dexlib_prefix(path: Path) -> str|None:
    """Return the dexlib namespace only when the jar exposes the *complete* API.

    Apktool 3.x is a fat/shaded application jar, not a supported dexlib2 library
    distribution.  Some releases contain DexBackedDexFile/ClassDef but omit
    DexFile/DexPool or alter APIs.  A marker-only probe therefore gives false
    positives.
    """
    try:
        with zipfile.ZipFile(path) as z:
            names=set(z.namelist())
    except Exception:
        return None
    if all(f"{DEXLIB_PREFIX}/{suffix}" in names for suffix in DEXLIB_REQUIRED_SUFFIXES):
        return DEXLIB_PREFIX.replace('/', '.')
    return None


def _valid_jar(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as z:
            return any(not x.endswith('/') for x in z.namelist())
    except Exception:
        return False


def _download_atomic(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True,exist_ok=True)
    tmp=dest.with_name(dest.name+'.part')
    req=urllib.request.Request(url,headers={'User-Agent':'apk2project-v28.8','Accept':'*/*'})
    try:
        with urllib.request.urlopen(req,timeout=60) as r, tmp.open('wb') as out:
            shutil.copyfileobj(r,out)
        if not _valid_jar(tmp):
            raise RuntimeError(f'downloaded file is not a valid jar: {url}')
        tmp.replace(dest)
    finally:
        try:
            if tmp.exists(): tmp.unlink()
        except Exception:
            pass


def _standalone_bundle(tools_dir: Path) -> list[Path]:
    bundle=Path(tools_dir).expanduser()/f'dexlib2-{DEXLIB_VERSION}'
    bundle.mkdir(parents=True,exist_ok=True)
    result=[]
    for filename,url in DEXLIB_BUNDLE:
        p=bundle/filename
        if not _valid_jar(p):
            print(f'[*] v28: downloading standalone dexlib dependency {filename}')
            _download_atomic(url,p)
        result.append(p)
    primary=result[0]
    if _jar_dexlib_prefix(primary) is None:
        raise RuntimeError(f'standalone dexlib jar is incomplete or unexpected: {primary}')
    return result


def _dependency_jars_near(primary: Path) -> list[Path]:
    """Return sibling jars that may satisfy smali-dexlib2 runtime dependencies."""
    dep_prefixes=(
        'guava-','failureaccess-','listenablefuture-','jsr305-',
        'checker-qual-','error_prone_annotations-','j2objc-annotations-'
    )
    return sorted(
        x.resolve() for x in primary.parent.glob('*.jar')
        if x.resolve()!=primary.resolve() and x.name.startswith(dep_prefixes)
    )


def _gradle_cached_dependency_jars(home: Path) -> list[Path]:
    base=home/'.gradle/caches/modules-2/files-2.1'
    coords=(
        ('com.google.guava','guava'),
        ('com.google.guava','failureaccess'),
        ('com.google.guava','listenablefuture'),
        ('com.google.code.findbugs','jsr305'),
        ('org.checkerframework','checker-qual'),
        ('com.google.errorprone','error_prone_annotations'),
        ('com.google.j2objc','j2objc-annotations'),
    )
    out=[]
    for group,artifact in coords:
        root=base/group/artifact
        if not root.is_dir():
            continue
        jars=sorted(root.glob('*/*/*.jar'), key=lambda x:x.stat().st_mtime, reverse=True)
        if jars:
            out.append(jars[0].resolve())
    return out


def find_dexlib_classpath(explicit: Path|None=None, tools_dir: Path|None=None) -> list[Path]:
    """Resolve the official Google smali-dexlib2 runtime classpath.

    v28.8 keeps the v28.5 direct-dexlib architecture and v28.7 constructor lowering and stops adapting Apktool's private/shaded dexlib copy and
    stops carrying an org.jf reflection compatibility layer.  The runtime helper
    directly imports the public com.android.tools.smali API.  If no complete
    standalone distribution is already available, apk2project bootstraps its own
    pinned bundle under the tools directory.
    """
    tools_dir=Path(tools_dir or (Path.home()/'.local/share/apk2project/tools')).expanduser()
    candidates=[]
    explicit_dir=None
    if explicit:
        e=Path(explicit).expanduser()
        if e.is_dir():
            explicit_dir=e.resolve()
            candidates += sorted(e.glob('smali-dexlib2*.jar'), reverse=True)
            candidates += sorted(e.glob('*dexlib2*.jar'), reverse=True)
        else:
            candidates.append(e)
    candidates += sorted(tools_dir.glob('dexlib2-*/*smali-dexlib2*.jar'), reverse=True)
    candidates += sorted(tools_dir.glob('smali-dexlib2*.jar'), reverse=True)
    env=os.environ.get('DEXLIB_JAR')
    if env:
        candidates.append(Path(env).expanduser())
    home=Path.home()
    candidates += sorted(
        (home/'.gradle/caches/modules-2/files-2.1/com.android.tools.smali/smali-dexlib2').glob('*/*/*.jar'),
        reverse=True,
    )
    candidates += sorted(
        (home/'.m2/repository/com/android/tools/smali/smali-dexlib2').glob('*/*.jar'),
        reverse=True,
    )

    seen=set()
    for p in candidates:
        try: p=p.resolve()
        except Exception: pass
        if p in seen or not p.is_file():
            continue
        seen.add(p)
        ns=_jar_dexlib_prefix(p)
        if not ns:
            continue
        deps=_dependency_jars_near(p)
        # Gradle's module cache stores each artifact in a different directory.
        # Add cached transitive jars opportunistically; the Java probe is the
        # final authority on whether the resulting classpath is actually usable.
        deps += [x for x in _gradle_cached_dependency_jars(home) if x not in deps]
        cp=[p,*deps]
        print(f'[*] v28.8: using standalone dexlib2 from {p} ({ns})')
        return cp

    return _standalone_bundle(tools_dir)


def _engine_exports() -> list[str]:
    return [
        '--add-exports','jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED',
        '--add-exports','jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED',
        '--add-exports','jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED',
        '--add-exports','jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED',
        '--add-exports','jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED',
        '--add-exports','java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED',
    ]


def ensure_core_engine(script_dir: Path, project: Path) -> Path:
    """Compile dexlib-independent ownership/dealias/raw-ABI helpers."""
    src=script_dir/'java_engine'
    core_java=sorted(p for p in src.glob('*.java') if p.name!='DexHybridRebuilder.java')
    if not core_java:
        raise FileNotFoundError(f"missing Java engine sources under {src}")
    out=project/'analysis/java-engine/classes'
    marker=out/'apk2project/hybrid/HybridCompiler.class'
    javac=shutil.which('javac')
    if not javac:
        raise RuntimeError('javac is required to compile the v28.8 Java helper')
    out.mkdir(parents=True,exist_ok=True)
    newest=max(x.stat().st_mtime for x in core_java)
    if not marker.exists() or marker.stat().st_mtime<newest:
        _run([javac,*_engine_exports(),'-d',out,*core_java])
    if not marker.exists():
        raise RuntimeError('v28.8 core Java helper did not compile')
    return out


def ensure_engine(script_dir: Path, project: Path, dexlib_cp: list[Path]) -> Path:
    """Compile the runtime DEX helper only after standalone dexlib2 is resolved.

    This is the architectural boundary that keeps dexlib2 out of source/JADX
    ownership and shadow compilation. A runtime-tool failure can stop APK rebuild,
    but it cannot reactivate quarantined decompiler/library source.
    """
    src=script_dir/'java_engine'
    runtime_src=src/'DexHybridRebuilder.java'
    if not runtime_src.is_file():
        raise FileNotFoundError(f"missing runtime DEX helper: {runtime_src}")
    out=ensure_core_engine(script_dir,project)
    runtime_marker=out/'apk2project/hybrid/DexHybridRebuilder.class'
    javac=shutil.which('javac')
    inputs=[runtime_src,*dexlib_cp]
    newest=max(Path(x).stat().st_mtime for x in inputs if Path(x).exists())
    if not runtime_marker.exists() or runtime_marker.stat().st_mtime<newest:
        _run([javac,*_engine_exports(),'-cp',java_cp(out,*dexlib_cp),'-d',out,runtime_src])
    if not runtime_marker.exists():
        raise RuntimeError('v28.8 runtime DEX helper did not compile')
    return out


def java_cp(*paths: Path) -> str:
    return os.pathsep.join(str(Path(x)) for x in paths if x)


def run_dex_helper(engine: Path, dexlib_cp: list[Path], *args, capture: bool=False, check: bool=True):
    """Invoke DexHybridRebuilder with the one canonical runtime classpath.

    DexHybridRebuilder directly links against standalone smali-dexlib2, so *every*
    subcommand must run with both the compiled engine directory and the full
    dexlib runtime bundle. Centralizing the launch here prevents individual
    inventory/merge/probe call sites from accidentally dropping those jars.
    """
    if not dexlib_cp:
        raise RuntimeError('DexHybridRebuilder requires a non-empty standalone dexlib2 classpath')
    return _run(['java','-cp',java_cp(engine,*dexlib_cp),
                 'apk2project.hybrid.DexHybridRebuilder',*args], capture=capture, check=check)


def inventory_apk(original_apk: Path, engine: Path, dexlib_cp: list[Path], work: Path) -> dict:
    report=work/'original-dex-inventory.json'
    run_dex_helper(engine,dexlib_cp,'inventory',
                   '--apk',original_apk,'--report',report,capture=True)
    return json.loads(report.read_text())


def _source_fqcn(rel: str) -> str:
    rel=rel.replace('\\','/')
    assert rel.endswith('.java')
    return rel[:-5].replace('/','.')


def plan_replacements(project: Path, inventory: dict) -> dict:
    project=Path(project)
    own_path=project/'analysis/hybrid-source-ownership.json'
    if not own_path.is_file(): raise FileNotFoundError(f"missing {own_path}; v28 requires a validated hybrid-shadow build")
    own=json.loads(own_path.read_text())
    original={d for vals in inventory.get('dex',{}).values() for d in vals}
    src_to_raw=own.get('source_to_raw') or {}
    runtime=[]; scaffolding=[]
    for rel in own.get('app_sources') or []:
        fq=_source_fqcn(rel)
        simple=fq.rsplit('.',1)[-1]
        raw=src_to_raw.get(fq,fq)
        raw_desc='L'+raw.replace('.','/')+';'
        if simple in {'R','BuildConfig'} or re.fullmatch(r'R\$.*',simple):
            scaffolding.append({'source':rel,'fqcn':fq,'reason':'compile-time-generated/scaffolding'})
            continue
        if raw_desc in original:
            runtime.append({'source':rel,'fqcn':fq,'raw':raw,'descriptor':raw_desc})
        else:
            scaffolding.append({'source':rel,'fqcn':fq,'reason':'no matching original DEX class'})
    if not runtime: raise RuntimeError('no source-owned runtime classes found in the original APK')
    return {'runtime':runtime,'scaffolding':scaffolding,'ownership':str(own_path)}



def _read_shadow_manifests(shadow: Path) -> tuple[dict[str,str], list[list[str]]]:
    """Return raw->source-facing class map and exact alias provenance rows."""
    if not shadow.is_file():
        raise FileNotFoundError(f"missing validated shadow JAR: {shadow}")
    with zipfile.ZipFile(shadow) as z:
        try:
            ctext=z.read('META-INF/apk2project-shadow-classes.tsv').decode('utf-8','replace')
            atext=z.read('META-INF/apk2project-shadow-aliases.tsv').decode('utf-8','replace')
        except KeyError as e:
            raise RuntimeError(f"shadow JAR lacks v27+ provenance manifest: {e}")
    raw_to_source={}
    for line in ctext.splitlines():
        if not line or line.startswith('#'): continue
        q=line.split('\t')
        if len(q)>=2:
            raw,src=q[0].strip(),q[1].strip()
            if raw and src:
                old=raw_to_source.setdefault(raw,src)
                if old!=src: raise RuntimeError(f"shadow class provenance collision for {raw}: {old} vs {src}")
    aliases=[]
    for line in atext.splitlines():
        if not line or line.startswith('#'): continue
        q=line.split('\t')
        if q and q[0] in {'F','M'} and len(q)>=7: aliases.append(q[:7])
    return raw_to_source,aliases


def _remap_desc_raw_to_source(desc: str, raw_to_source: dict[str,str]) -> str:
    out=[]; i=0
    while i<len(desc):
        if desc[i]!='L': out.append(desc[i]); i+=1; continue
        semi=desc.find(';',i)
        if semi<0: out.append(desc[i:]); break
        raw=desc[i+1:semi].replace('/','.')
        src=raw_to_source.get(raw,raw)
        out.append('L'+src.replace('.','/')+';'); i=semi+1
    return ''.join(out)


def _iter_jobf_members(path: Path):
    """Yield (kind, raw_owner, raw_name, raw_desc, alias) from JADX JOBF."""
    if not path or not path.is_file(): return
    for rawline in path.read_text(errors='replace').splitlines():
        line=rawline.strip()
        if not line or line.startswith('#'): continue
        if line.startswith('f '):
            body=line[2:].strip()
            if ' = ' not in body or ':' not in body: continue
            lhs,alias=body.split(' = ',1); before,desc=lhs.split(':',1)
            if '.' not in before: continue
            owner,name=before.rsplit('.',1)
            yield 'F',owner,name,desc.strip(),alias.strip()
        elif line.startswith('m '):
            body=line[2:].strip()
            if ' = ' not in body or '(' not in body: continue
            lhs,alias=body.split(' = ',1); par=lhs.find('(')
            head,desc=lhs[:par],lhs[par:]
            if '.' not in head: continue
            owner,name=head.rsplit('.',1)
            yield 'M',owner,name,desc.strip(),alias.strip()


def build_runtime_dealias_map(project: Path, shadow: Path, work: Path) -> tuple[Path,dict]:
    """Build the exact source/JADX -> raw DEX class/member rewrite table."""
    ownership_path=project/'analysis/hybrid-source-ownership.json'
    own=json.loads(ownership_path.read_text())
    raw_to_source, alias_rows=_read_shadow_manifests(shadow)
    # Ownership contains classes intentionally omitted from the compile-only shadow too
    # (notably app-owned classes), so fold its exact source->raw links back in.
    for src,raw in (own.get('source_to_raw') or {}).items():
        if raw:
            prior=raw_to_source.get(raw)
            if prior is None or src in {_source_fqcn(x) for x in own.get('app_sources',[]) if x.endswith('.java')}:
                raw_to_source[raw]=src

    classes={}
    def add_class(src,raw):
        si=src.replace('.','/'); ri=raw.replace('.','/')
        old=classes.setdefault(si,ri)
        if old!=ri: raise RuntimeError(f"runtime class dealias collision: {si} -> {old} / {ri}")
    for raw,src in raw_to_source.items(): add_class(src,raw)
    for src,raw in (own.get('source_to_raw') or {}).items(): add_class(src,raw)

    members={}
    def add_member(kind,src_owner,alias,src_desc,raw_name,raw_desc,origin):
        key=(kind,src_owner.replace('.','/'),alias,src_desc)
        val=(raw_name,raw_desc,origin)
        old=members.get(key)
        if old and old[0]!=raw_name:
            raise RuntimeError(f"runtime member dealias collision {key}: {old} vs {val}")
        members[key]=val

    # The validated shadow manifest includes use-site aliases that JOBF itself may not
    # know (and therefore is the strongest source for binary-owned references).
    for kind,shadow_owner,raw_owner,raw_name,raw_desc,alias,shadow_desc in alias_rows:
        add_member(kind,shadow_owner,alias,shadow_desc,raw_name,raw_desc,'shadow')

    # JOBF is required for definitions/self-references of app-owned classes, which are
    # deliberately absent from the compile-only shadow class bodies.
    jobf=Path(own.get('jadx_map') or project/'analysis/jadx-renames.jobf')
    if not jobf.is_file(): jobf=project/'analysis/jadx-renames.jobf'
    jobf_count=0
    for kind,raw_owner,raw_name,raw_desc,alias in _iter_jobf_members(jobf) or ():
        src_owner=raw_to_source.get(raw_owner,raw_owner)
        src_desc=_remap_desc_raw_to_source(raw_desc,raw_to_source)
        add_member(kind,src_owner,alias,src_desc,raw_name,raw_desc,'jobf'); jobf_count+=1

    path=work/'runtime-dealias.tsv'
    lines=['#kind\tsource_owner_internal\talias\tsource_desc\traw_name\traw_desc_or_owner']
    for src,raw in sorted(classes.items()): lines.append(f'C\t{src}\t{raw}')
    for (kind,owner,alias,src_desc),(raw_name,raw_desc,origin) in sorted(members.items()):
        lines.append(f'{kind}\t{owner}\t{alias}\t{src_desc}\t{raw_name}\t{raw_desc}\t{origin}')
    path.write_text('\n'.join(lines)+'\n')
    report={'class_links':len(classes),'member_links':len(members),'jobf_member_records':jobf_count,
            'jobf':str(jobf) if jobf.is_file() else None,'map':str(path)}
    (work/'runtime-dealias-map.json').write_text(json.dumps(report,indent=2,sort_keys=True))
    return path,report


def run_dealias(engine: Path, class_input: Path, dealias_map: Path, work: Path) -> tuple[Path,dict]:
    out=work/'replacement-classes-raw'
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True)
    report=work/'runtime-dealias-report.json'
    cmd=['java',*JAVA_RUNTIME_EXPORTS,'-cp',str(engine),'apk2project.hybrid.RuntimeDealiaser',
         '--in',class_input,'--out',out,'--map',dealias_map,'--report',report]
    p=_run(cmd,capture=True,check=False)
    (work/'runtime-dealias.log').write_text(p.stdout or '')
    if p.returncode: raise RuntimeError(f"runtime bytecode dealiasing failed; see {work/'runtime-dealias.log'}\n{p.stdout or ''}")
    data=json.loads(report.read_text())
    actual=sorted(out.rglob('*.class'))
    if len(actual)!=data.get('class_files'): raise RuntimeError('runtime dealias output class count mismatch')
    return out,data


def build_raw_abi(engine: Path, original_apk: Path, output_classes: list[str], work: Path, api: int) -> tuple[Path,dict]:
    exclude=work/'raw-abi-exclude.txt'; exclude.write_text('\n'.join(output_classes)+'\n')
    jar=work/'apk2project-runtime-raw-abi.jar'; report=work/'raw-abi-report.json'
    cmd=['java',*JAVA_RUNTIME_EXPORTS,'-cp',str(engine),'apk2project.hybrid.RawAbiEmitter',
         '--apk',original_apk,'--out',jar,'--exclude-list',exclude,'--report',report,'--api',str(api)]
    p=_run(cmd,capture=True,check=False); (work/'raw-abi.log').write_text(p.stdout or '')
    if p.returncode or not jar.is_file(): raise RuntimeError(f"raw runtime ABI generation failed; see {work/'raw-abi.log'}\n{p.stdout or ''}")
    return jar,json.loads(report.read_text())


def find_javac_classes(project: Path) -> Path:
    preferred=[
        project/'app/build/intermediates/javac/debug/compileDebugJavaWithJavac/classes',
        project/'app/build/intermediates/javac/debug/classes',
    ]
    for p in preferred:
        if p.is_dir() and any(p.rglob('*.class')): return p
    roots=[]
    base=project/'app/build/intermediates'
    if base.exists():
        for p in base.rglob('classes'):
            if p.is_dir() and 'javac' in p.parts and any(p.rglob('*.class')): roots.append(p)
    if not roots: raise FileNotFoundError('could not locate compileDebugJavaWithJavac class output; run a successful --compile first')
    roots.sort(key=lambda p:p.stat().st_mtime, reverse=True)
    return roots[0]


def collect_replacement_classes(class_root: Path, plan: dict, out: Path) -> list[Path]:
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True)
    copied=[]
    for ent in plan['runtime']:
        rel=Path(*ent['fqcn'].split('.'))
        parent=class_root/rel.parent
        stem=rel.name
        matches=[]
        if (parent/(stem+'.class')).is_file(): matches.append(parent/(stem+'.class'))
        matches += sorted(parent.glob(stem+'$*.class')) if parent.is_dir() else []
        if not matches: raise FileNotFoundError(f"compiled class missing for runtime owner {ent['fqcn']} under {class_root}")
        for src in matches:
            dst=out/src.relative_to(class_root); dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,dst); copied.append(dst)
    return copied


def validate_r_constants(project: Path, class_root: Path, work: Path) -> dict:
    """Verify javac-inlined R integer IDs against the original decoded public.xml.

    The final hybrid APK preserves the original resources.arsc, so source-owned
    replacement bytecode must use that same integer resource-ID universe.  javac
    normally inlines static-final R ints; a rebuilt R value that drifted would
    otherwise become a silent runtime semantic bug rather than a linker error.
    """
    work.mkdir(parents=True,exist_ok=True)
    own_path=project/'analysis/hybrid-source-ownership.json'
    own=json.loads(own_path.read_text()) if own_path.is_file() else {}
    r_sources=[]
    for rel in own.get('app_sources') or []:
        rel=rel.replace('\\','/')
        if rel.endswith('/R.java') or rel=='R.java': r_sources.append(rel)
    if not r_sources:
        data={'status':'not-applicable','reason':'no app-owned R.java in ownership checkpoint','checked_constants':0,'mismatches':[]}
        (work/'resource-id-validation.json').write_text(json.dumps(data,indent=2,sort_keys=True)); return data

    public_candidates=[
        project/'analysis/resource-backups/values/public.xml',
        project/'app/src/main/res/values/public.xml',
    ]
    public_xml=next((x for x in public_candidates if x.is_file()),None)
    if public_xml is None:
        raise FileNotFoundError('cannot validate runtime resource IDs: original public.xml backup not found')
    root=ET.parse(public_xml).getroot()
    expected={}
    for e in root.findall('public'):
        typ=e.get('type'); name=e.get('name'); val=e.get('id')
        if not typ or not name or not val: continue
        try: expected[(typ,name)]=int(val,0) & 0xffffffff
        except ValueError: continue

    javap=shutil.which('javap')
    if not javap: raise RuntimeError('javap is required for v28 resource-ID verification')
    checked=0; mismatches=[]; missing_r=[]; observed={}
    const_re=re.compile(r'^\s*public\s+static\s+final\s+int\s+([^\s=;]+)\s*=\s*(-?(?:0x[0-9a-fA-F]+|\d+));\s*$')
    for rel in r_sources:
        base=Path(rel[:-5])  # .../R
        pkg_parent=class_root/base.parent
        if not pkg_parent.is_dir():
            missing_r.append(str(base.parent).replace('\\','/')); continue
        candidates=sorted(pkg_parent.glob('R$*.class'))
        if not candidates:
            missing_r.append(str(base).replace('\\','/')); continue
        for cls in candidates:
            # R$foo$bar is not a normal generated resource holder; only one-level R$type.
            stem=cls.stem
            if not stem.startswith('R$') or '$' in stem[2:]: continue
            typ=stem[2:]
            proc=_run([javap,'-p','-constants',cls],capture=True,check=False)
            if proc.returncode:
                raise RuntimeError(f'javap failed while validating resource IDs: {cls}\n{proc.stdout or ""}')
            for line in (proc.stdout or '').splitlines():
                m=const_re.match(line)
                if not m: continue
                name=m.group(1); raw=int(m.group(2),0) & 0xffffffff
                observed[(typ,name)]=raw
                exp=expected.get((typ,name))
                if exp is None: continue
                checked+=1
                if raw!=exp:
                    mismatches.append({'type':typ,'name':name,'compiled':f'0x{raw:08x}','original':f'0x{exp:08x}','class_file':str(cls)})
    data={'status':'ok' if not mismatches else 'mismatch','public_xml':str(public_xml),
          'expected_public_ids':len(expected),'observed_r_int_constants':len(observed),
          'checked_constants':checked,'missing_r_outputs':missing_r,'mismatches':mismatches}
    (work/'resource-id-validation.json').write_text(json.dumps(data,indent=2,sort_keys=True))
    if missing_r:
        raise RuntimeError('cannot prove runtime resource IDs: compiled R$*.class output missing for '+', '.join(missing_r))
    if mismatches:
        sample=', '.join(f"{x['type']}.{x['name']} {x['compiled']} != {x['original']}" for x in mismatches[:12])
        raise RuntimeError(f'compiled R constants do not match original APK resource IDs ({len(mismatches)} mismatch(es)): {sample}')
    return data


def find_d8(project: Path) -> Path:
    q=shutil.which('d8')
    if q:return Path(q)
    roots=[]
    for e in ('ANDROID_HOME','ANDROID_SDK_ROOT'):
        if os.environ.get(e): roots.append(Path(os.environ[e]))
    roots += [project/'.apk2project-android-sdk', Path.home()/'.cache/apk2project/android-sdk', Path(os.environ.get('PREFIX','/data/data/com.termux/files/usr'))/'opt/android-sdk']
    hits=[]
    for r in roots:
        bt=r/'build-tools'
        if bt.is_dir(): hits += list(bt.glob('*/d8'))+list(bt.glob('*/d8.bat'))
    if not hits: raise FileNotFoundError('d8 not found; install Android build-tools or run apk2project --install-sdk')
    hits.sort(key=lambda p:p.parent.name, reverse=True)
    return hits[0]


def find_android_jar(project: Path, api: int) -> Path|None:
    roots=[]
    for e in ('ANDROID_HOME','ANDROID_SDK_ROOT'):
        if os.environ.get(e): roots.append(Path(os.environ[e]))
    roots += [project/'.apk2project-android-sdk', Path.home()/'.cache/apk2project/android-sdk', Path(os.environ.get('PREFIX','/data/data/com.termux/files/usr'))/'opt/android-sdk']
    for r in roots:
        p=r/'platforms'/f'android-{api}'/'android.jar'
        if p.is_file(): return p
    return None



def sdk_facts(project: Path) -> dict:
    compile_api=35; min_api=21; android_jar=None
    sel=project/'analysis/compile-sdk-selection.json'
    if sel.is_file():
        try:
            d=json.loads(sel.read_text()); chosen=d.get('selected') or {}
            compile_api=int(chosen.get('api') or d.get('selected_compile_sdk') or d.get('compile_sdk') or compile_api)
            p=chosen.get('android_jar')
            if p and Path(p).is_file(): android_jar=Path(p)
            if d.get('min_sdk') is not None: min_api=int(d['min_sdk'])
        except Exception: pass
    bg=project/'app/build.gradle'
    if bg.is_file():
        txt=bg.read_text(errors='replace')
        m=re.search(r'(?m)^\s*compileSdk(?:Version)?\s*(?:=\s*)?(\d+)\b',txt)
        if m: compile_api=int(m.group(1))
        m=re.search(r'(?m)^\s*minSdk(?:Version)?\s*(?:=\s*)?(\d+)\b',txt)
        if m: min_api=int(m.group(1))
    if android_jar is None or not android_jar.is_file(): android_jar=find_android_jar(project,compile_api)
    return {'compile_api':compile_api,'min_api':min_api,'android_jar':str(android_jar) if android_jar else None}


def run_d8(project: Path, classes: list[Path], runtime_classpath: Path, work: Path, min_api: int, compile_api: int, android_jar: Path|None=None) -> Path:
    d8=find_d8(project)
    out=work/'replacement-d8'
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True)
    cmd=[d8,'--release','--min-api',str(min_api),'--output',out]
    android_jar=Path(android_jar) if android_jar else find_android_jar(project,compile_api)
    if android_jar and android_jar.is_file(): cmd += ['--lib',android_jar]
    if runtime_classpath.is_file(): cmd += ['--classpath',runtime_classpath]
    cmd += classes
    p=_run(cmd,capture=True,check=False)
    (work/'d8.log').write_text(p.stdout or '')
    if p.returncode: raise RuntimeError(f"D8 replacement compilation failed; see {work/'d8.log'}\n{p.stdout or ''}")
    if not any(out.glob('classes*.dex')): raise RuntimeError('D8 succeeded but produced no replacement DEX')
    return out


def merge_dex(original_apk: Path, engine: Path, dexlib_cp: list[Path], replacement_dir: Path,
              plan: dict, out_dir: Path, work: Path, api: int, min_api: int) -> dict:
    remove=work/'remove-descriptors.txt'
    remove.write_text('\n'.join(x['descriptor'] for x in plan['runtime'])+'\n')
    report=work/'dex-merge-report.json'
    p=run_dex_helper(engine,dexlib_cp,'merge',
            '--apk',original_apk,'--replacement-dir',replacement_dir,'--remove-list',remove,
            '--out-dir',out_dir,'--report',report,'--api',str(api),'--min-api',str(min_api),capture=True,check=False)
    merge_log=work/'dex-merge.log'
    merge_log.write_text(p.stdout or '')
    # v28.8: surface the Java merge trace in the main apk2project output as well
    # as preserving it verbatim on disk.  On failure do not duplicate the entire
    # trace inside the Python exception; the phase-tagged Java output immediately
    # above plus the persistent log are the useful diagnostics.
    if p.stdout:
        print(p.stdout,end='' if p.stdout.endswith('\n') else '\n')
    if p.returncode:
        raise RuntimeError(f"DEX merge failed with exit code {p.returncode}; full trace: {merge_log}")
    return json.loads(report.read_text())


def _copy_zipinfo(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    n=zipfile.ZipInfo(info.filename,info.date_time)
    n.compress_type=info.compress_type; n.comment=info.comment; n.extra=info.extra
    n.internal_attr=info.internal_attr; n.external_attr=info.external_attr; n.create_system=info.create_system
    n.flag_bits=info.flag_bits & ~0x08
    return n


def repack_apk(original: Path, dex_dir: Path, output: Path) -> dict:
    output.parent.mkdir(parents=True,exist_ok=True)
    dex_files={p.name:p for p in dex_dir.glob('classes*.dex') if DEX_RE.match(p.name)}
    if not dex_files: raise RuntimeError('no merged dex files to package')
    preserved=removed_sig=0
    with zipfile.ZipFile(original,'r') as zin, zipfile.ZipFile(output,'w',allowZip64=True) as zout:
        original_dex_info={i.filename:i for i in zin.infolist() if DEX_RE.match(i.filename)}
        for info in zin.infolist():
            name=info.filename
            if DEX_RE.match(name): continue
            if SIG_RE.match(name) or name.upper()=='META-INF/MANIFEST.MF': removed_sig+=1; continue
            data=zin.read(name); zout.writestr(_copy_zipinfo(info),data,compress_type=info.compress_type); preserved+=1
        for name in sorted(dex_files,key=lambda n:1 if n=='classes.dex' else int(n[7:-4])):
            src=dex_files[name]; oi=original_dex_info.get(name)
            zi=_copy_zipinfo(oi) if oi else zipfile.ZipInfo(name)
            # Match original compression when possible; otherwise DEFLATE.
            c=oi.compress_type if oi else zipfile.ZIP_DEFLATED
            zout.writestr(zi,src.read_bytes(),compress_type=c)
    return {'output':str(output),'sha256':_sha256(output),'preserved_entries':preserved,
            'removed_signature_entries':removed_sig,'dex_entries':sorted(dex_files)}


def _tool(project: Path,name: str) -> Path|None:
    q=shutil.which(name)
    if q:return Path(q)
    roots=[]
    for e in ('ANDROID_HOME','ANDROID_SDK_ROOT'):
        if os.environ.get(e):roots.append(Path(os.environ[e]))
    roots += [project/'.apk2project-android-sdk',Path(os.environ.get('PREFIX','/data/data/com.termux/files/usr'))/'opt/android-sdk']
    hits=[]
    for r in roots:
        if (r/'build-tools').is_dir(): hits += list((r/'build-tools').glob(f'*/{name}'))
    if hits:
        hits.sort(key=lambda p:p.parent.name,reverse=True);return hits[0]
    return None


def sign_debug(project: Path, unsigned: Path, work: Path) -> Path:
    zipalign=_tool(project,'zipalign'); apksigner=_tool(project,'apksigner'); keytool=shutil.which('keytool')
    if not zipalign or not apksigner or not keytool:
        missing=[n for n,v in [('zipalign',zipalign),('apksigner',apksigner),('keytool',keytool)] if not v]
        raise FileNotFoundError('cannot debug-sign hybrid APK; missing '+', '.join(missing))
    aligned=unsigned.with_name(unsigned.stem+'-aligned.apk')
    signed=unsigned.with_name(unsigned.stem.replace('-unsigned','')+'-debug.apk')
    # Android 15+ can require 16 KiB page alignment for uncompressed native
    # libraries.  Newer zipalign exposes -P 16; older build-tools only have
    # legacy -p.  Probe rather than keying this to a guessed build-tools version.
    try:
        zh=_run([zipalign,'-h'],capture=True,check=False)
        zhelp=(zh.stdout or '')+'\n'+(zh.stderr or '')
    except Exception:
        zhelp=''
    align_cmd=[zipalign,'-f']
    if re.search(r'(?m)(?:^|\s)-P(?:\s|,|$)',zhelp):
        align_cmd += ['-P','16']
    elif re.search(r'(?m)(?:^|\s)-p(?:\s|,|$)',zhelp):
        align_cmd += ['-p']
    align_cmd += ['4',unsigned,aligned]
    _run(align_cmd)
    (work/'zipalign-command.txt').write_text(' '.join(map(str,align_cmd))+'\n')
    ks=Path.home()/'.android/debug.keystore'; ks.parent.mkdir(parents=True,exist_ok=True)
    if not ks.exists():
        _run([keytool,'-genkeypair','-keystore',ks,'-storepass','android','-alias','androiddebugkey',
              '-keypass','android','-dname','CN=Android Debug,O=Android,C=US','-keyalg','RSA','-keysize','2048',
              '-validity','10000','-noprompt'])
    _run([apksigner,'sign','--ks',ks,'--ks-key-alias','androiddebugkey','--ks-pass','pass:android',
          '--key-pass','pass:android','--out',signed,aligned])
    p=_run([apksigner,'verify','--verbose',signed],capture=True)
    (work/'apksigner-verify.log').write_text(p.stdout or '')
    return signed


def rebuild(original_apk: Path, project: Path, *, dexlib_jar: Path|None=None,
            tools_dir: Path|None=None, output: Path|None=None, sign: str='debug') -> dict:
    original_apk=Path(original_apk).resolve(); project=Path(project).resolve()
    work=project/'analysis/hybrid-apk'; work.mkdir(parents=True,exist_ok=True)
    script_dir=Path(__file__).resolve().parent
    # Runtime tooling is resolved only now: apk2project.py calls rebuild() after
    # the app's validated source-owned javac has succeeded.
    dexlib_cp=find_dexlib_classpath(dexlib_jar,tools_dir)
    engine=ensure_engine(script_dir,project,dexlib_cp)
    probe=run_dex_helper(engine,dexlib_cp,'probe-dexlib',capture=True)
    (work/'dexlib-probe.log').write_text(probe.stdout or '')
    inv=inventory_apk(original_apk,engine,dexlib_cp,work)
    plan=plan_replacements(project,inv)
    (work/'replacement-plan.json').write_text(json.dumps(plan,indent=2,sort_keys=True))
    own=json.loads((project/'analysis/hybrid-source-ownership.json').read_text())
    sdk=sdk_facts(project); compile_api=int(sdk['compile_api']); min_api=int(sdk['min_api'])
    (work/'sdk-facts.json').write_text(json.dumps(sdk,indent=2,sort_keys=True))
    class_root=find_javac_classes(project)
    resource_ids=validate_r_constants(project,class_root,work)
    class_input=work/'replacement-classes'
    classes=collect_replacement_classes(class_root,plan,class_input)
    shadow=project/'app/libs/apk2project-apk-shadow-abi.jar'
    dealias_map,dealias_map_report=build_runtime_dealias_map(project,shadow,work)
    raw_classes,dealias_report=run_dealias(engine,class_input,dealias_map,work)
    raw_abi,raw_abi_report=build_raw_abi(engine,original_apk,dealias_report.get('output_classes') or [],work,compile_api)
    raw_inputs=sorted(raw_classes.rglob('*.class'))
    replacement=run_d8(project,raw_inputs,raw_abi,work,min_api,compile_api,Path(sdk['android_jar']) if sdk.get('android_jar') else None)
    merged=work/'merged-dex'
    if merged.exists():shutil.rmtree(merged)
    merged.mkdir(parents=True)
    merge_report=merge_dex(original_apk,engine,dexlib_cp,replacement,plan,merged,work,compile_api,min_api)
    if output is None: output=project/'app/build/outputs/apk/hybrid'/f'{original_apk.stem}-hybrid-unsigned.apk'
    unsigned=Path(output).resolve()
    package_report=repack_apk(original_apk,merged,unsigned)
    result={'version':'v28.8','original_apk':str(original_apk),'project':str(project),'plan':plan,
            'compiled_class_root':str(class_root),'resource_ids':resource_ids,'replacement_class_files':[str(x.relative_to(class_input)) for x in classes],
            'sdk':sdk,'runtime_dealias_map':dealias_map_report,'runtime_dealias':dealias_report,'raw_abi':raw_abi_report,
            'raw_replacement_class_files':[str(x.relative_to(raw_classes)) for x in raw_inputs],
            'dexlib_classpath':[str(x) for x in dexlib_cp],'dex_merge':merge_report,'package':package_report}
    if sign=='debug':
        signed=sign_debug(project,unsigned,work);result['signed_apk']=str(signed);result['signed_sha256']=_sha256(signed)
    (work/'hybrid-apk-report.json').write_text(json.dumps(result,indent=2,sort_keys=True))
    return result


def main():
    ap=argparse.ArgumentParser(description='v28.8 preserve-original-DEX hybrid APK rebuilder')
    ap.add_argument('apk',type=Path); ap.add_argument('project',type=Path)
    ap.add_argument('--dexlib-jar',type=Path,default=None,help='official standalone com.android.tools.smali smali-dexlib2 jar or directory containing its runtime dependencies')
    ap.add_argument('--tools-dir',type=Path,default=Path.home()/'.local/share/apk2project/tools')
    ap.add_argument('-o','--output',type=Path,default=None)
    ap.add_argument('--sign',choices=('off','debug'),default='debug')
    z=ap.parse_args();r=rebuild(z.apk,z.project,dexlib_jar=z.dexlib_jar,tools_dir=z.tools_dir,output=z.output,sign=z.sign)
    print(json.dumps(r,indent=2,sort_keys=True))
    print(r.get('signed_apk') or r['package']['output'])

if __name__=='__main__': main()
