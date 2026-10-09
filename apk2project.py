#!/usr/bin/env python3
"""
apk2project_all.py — APK -> reconstructed Android project -> dependency recovery
-> library-source pruning, in one Termux-friendly program.

Pipeline:
  1 decode APK with Apktool
  2 decompile with JADX (+ independent JADX Gradle export)
  3 build normalized Android project tree
  4 scan imports/local declarations
  5 resolve missing classes against Maven Central / Google Maven
  6 download and index JAR/AAR dependencies
  7 synthesize Gradle dependencies
  8 identify decompiled Java belonging to resolved libraries
  9 move (default) or delete high-confidence library sources
 10 optionally run a Gradle compile probe

Pruning is deliberately auditable. Default action is MOVE, not delete.
"""

from __future__ import annotations
import argparse, collections, copy, hashlib, json, os, re, shutil, stat, subprocess, sys, tempfile, time
import urllib.parse, urllib.request, zipfile, threading
import concurrent.futures
from html.parser import HTMLParser
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from pathlib import Path
import xml.etree.ElementTree as ET

try:
    from lxml import etree as LET
except ImportError:
    LET = None

try:
    from source_repair import SourceRepairSession
except Exception as _source_repair_import_error:
    SourceRepairSession = None
else:
    _source_repair_import_error = None

try:
    from binary_islands import BinaryIslandManager
except Exception as _binary_island_import_error:
    BinaryIslandManager = None
else:
    _binary_island_import_error = None

try:
    import hybrid_apk as HybridApkRebuilder
except Exception as _hybrid_apk_import_error:
    HybridApkRebuilder = None
else:
    _hybrid_apk_import_error = None


def readjson(file):
    rawjson = file.read_text()
    strip_comments = re.compile("\n\\s*#[^\n]*", re.DOTALL)
    fixedjson = strip_comments.subn("", rawjson)[0]
    return json.loads(fixedjson)

ANDROID_LICENSES = {
    # SDK platform + build-tools (covers build-tools;35.0.0 and prior).
    "android-sdk-license": [
        "8933bad161af4178b1185d1a37fbf41ea5269c55",
        "d56f5187479451eabf01fb78af6dfcb131a6481e",
        "24333f8a63b6825ea9c5514f83c2829b004d1fee",
    ],
    "android-sdk-preview-license": [
        "84831b9409646a918e30573bab4c9c91346d8abd",
    ],
    "android-sdk-arm-dbt-license": [
        "859f317696f67ef3d7f30a50a5560e7834b43903",
    ],
    "android-googletv-license": [
        "601085b94cd77f0b54ff86406957099ebe79c4d6",
    ],
    "google-gdk-license": [
        "33b6a2b64607f11b759f320ef9dff4ae5c47d97a",
    ],
    "intel-android-extra-license": [
        "d97571e2f888f64b3b20c7ea1a8ac5f1e5a52c61",
    ],
    "mips-android-sysimage-license": [
        "e9acab5b5fbb560a72cfaecce8946896ff6aab9d",
    ],
}


def _write_license_dir(licenses_dir: Path) -> int:
    licenses_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for filename, hashes in ANDROID_LICENSES.items():
        path = licenses_dir / filename
        existing = set()
        if path.exists():
            existing = {ln.strip() for ln in path.read_text().splitlines() if ln.strip()}
        before = len(existing)
        existing.update(hashes)
        path.write_text("\n".join(sorted(existing)) + "\n")
        if len(existing) != before or not path.exists():
            written += 1
    return written


def accept_android_licenses(sdk: Path | None = None, _seen=None):
    """
    Write every known Android SDK license hash to <sdk>/licenses AND to any
    additional SDK roots mentioned in ANDROID_HOME / ANDROID_SDK_ROOT, so the
    build-tools install step never fails the licence check again.
    """
    if _seen is None:
        _seen = set()
    if sdk is None:
        try:
            sdk = find_android_sdk()
        except NameError:
            sdk = None
        if sdk is None:
            sdk = termux_prefix() / "opt/android-sdk"
    sdk = Path(sdk).expanduser()
    try:
        resolved = sdk.resolve()
    except OSError:
        resolved = sdk
    if resolved in _seen:
        return
    _seen.add(resolved)

    n = _write_license_dir(sdk / "licenses")
    log(f"Installed/refreshed Android SDK licences under {sdk/'licenses'} ({n} file(s))")

    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        alt = os.environ.get(env)
        if not alt:
            continue
        alt_path = Path(alt).expanduser()
        try:
            alt_resolved = alt_path.resolve()
        except OSError:
            alt_resolved = alt_path
        if alt_resolved in _seen:
            continue
        _seen.add(alt_resolved)
        try:
            _write_license_dir(alt_path / "licenses")
            detail(f"Also refreshed licences under {alt_path/'licenses'}", 1)
        except Exception as exc:
            detail(f"Could not refresh licences under {alt_path}: {exc}", 2)
  


APKTOOL_VERSION = "3.0.3"
JADX_VERSION = "1.5.6"
APKTOOL_URL = f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VERSION}/apktool_{APKTOOL_VERSION}.jar"
JADX_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"
APKTOOL_SHA256 = "dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423"
CENTRAL_SEARCH = "https://search.maven.org/solrsearch/select"
CENTRAL_REPO = "https://repo1.maven.org/maven2"
GOOGLE_REPO = "https://dl.google.com/dl/android/maven2"
UA = "apk2project-all/1.0"
ANDROID_NS = "http://schemas.android.com/apk/res/android"
A = "{" + ANDROID_NS + "}"
IRE = re.compile(
    r"^\s*import\s+(?:static\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)", re.M
)
PRE = re.compile(r"^\s*package\s+([\w.$]+)\s*;", re.M)
TRE = re.compile(
    r"\b(?:public\s+|protected\s+|private\s+|abstract\s+|final\s+|static\s+)*(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)"
)
PLATFORM = (
    "java.",
    "javax.",
    "android.",
    "dalvik.",
    "sun.",
    "jdk.",
    "org.w3c.",
    "org.xml.",
    "kotlin.",
    "kotlinx.",
)


SCRIPT_VERSION = "bulletproof-v28.4-standalone-dexlib"

VERBOSE = 1


_LOG_LOCK = __import__("threading").Lock()

_USE_COLOR = (
    os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM", "") != "dumb"
    and sys.stderr.isatty()
)
_C_RESET   = "\033[0m"  if _USE_COLOR else ""
_C_DIM     = "\033[2m"  if _USE_COLOR else ""
_C_RED     = "\033[31m" if _USE_COLOR else ""
_C_GREEN   = "\033[32m" if _USE_COLOR else ""
_C_YELLOW  = "\033[33m" if _USE_COLOR else ""
_C_BLUE    = "\033[34m" if _USE_COLOR else ""
_C_CYAN    = "\033[36m" if _USE_COLOR else ""
_C_MAGENTA = "\033[35m" if _USE_COLOR else ""
_C_BOLD    = "\033[1m"  if _USE_COLOR else ""


def log(s):
    with _LOG_LOCK:
        sys.stderr.write(f"{_C_CYAN}[*]{_C_RESET} {s}\n")
        sys.stderr.flush()


def warn(s):
    with _LOG_LOCK:
        sys.stderr.write(f"{_C_YELLOW}[!]{_C_RESET} {s}\n")
        sys.stderr.flush()


def ok(s):
    with _LOG_LOCK:
        sys.stderr.write(f"{_C_GREEN}[+]{_C_RESET} {s}\n")
        sys.stderr.flush()


def step(s):
    with _LOG_LOCK:
        sys.stderr.write(f"\n{_C_BOLD}{_C_MAGENTA}== {s} =={_C_RESET}\n")
        sys.stderr.flush()


def detail(s, level=1):
    if VERBOSE >= level:
        print(f"{_C_DIM}    {s}{_C_RESET}", file=sys.stderr, flush=True)


def die(s):
    print(f"{_C_RED}ERROR:{_C_RESET} {s}", file=sys.stderr)
    raise SystemExit(1)


PROCESS_BLUE = "\033[94m" if _USE_COLOR else ""
PROCESS_RESET = "\033[0m" if _USE_COLOR else ""

def _process_stderr_write(text):
    """Write child-process output live to stderr in light blue."""
    if not text:
        return
    if os.environ.get("NO_COLOR") is not None:
        sys.stderr.write(text)
    else:
        sys.stderr.write(PROCESS_BLUE + text + PROCESS_RESET)
    sys.stderr.flush()

def run(cmd, cwd=None, check=True, capture=False, env=None):
    """
    Run a subprocess while teeing combined stdout/stderr live to stderr.

    The live child output is light blue.  When capture=True, the exact uncolored
    output is also retained in CompletedProcess.stdout for parsers/callers.
    """
    argv = list(map(str, cmd))
    log("$ " + " ".join(argv))
    p = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    chunks = []
    assert p.stdout is not None
    for line in p.stdout:
        if capture:
            chunks.append(line)
        _process_stderr_write(line)
    p.stdout.close()
    rc = p.wait()
    stdout = "".join(chunks) if capture else None
    result = subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr=None)
    if check and rc:
        raise subprocess.CalledProcessError(rc, argv, output=stdout)
    return result


def get(url, timeout=35):
    detail(f"Fetching {url}")
    q = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(q, timeout=timeout) as r:
        return r.read()


def download(url, dst):
    """Download atomically: an interrupted transfer can no longer leave a truncated
    jar that later runs treat as a valid cached artifact."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and dst.stat().st_size:
        return dst
    log("GET " + url)
    tmp = dst.with_name(dst.name + f".{os.getpid()}.{threading.get_ident()}.part")
    tmp.write_bytes(get(url))
    tmp.replace(dst)
    return dst


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1048576), b""):
            h.update(b)
    return h.hexdigest()


def bootstrap(d):
    d.mkdir(parents=True, exist_ok=True)
    aj = d / f"apktool_{APKTOOL_VERSION}.jar"
    if not aj.exists():
        download(APKTOOL_URL, aj)
    if sha256(aj) != APKTOOL_SHA256:
        die("Apktool SHA-256 mismatch")
    jd = d / f"jadx-{JADX_VERSION}"
    jb = jd / "bin/jadx"
    if not jb.exists():
        z = d / f"jadx-{JADX_VERSION}.zip"
        if not z.exists():
            download(JADX_URL, z)
        with zipfile.ZipFile(z) as q:
            q.extractall(jd)
        hits = list(jd.rglob("bin/jadx"))
        if hits:
            jb = hits[0]
    if not jb.exists():
        die("Could not locate JADX launcher after extraction")
    jb.chmod(jb.stat().st_mode | stat.S_IXUSR)
    return aj, jb


def cp(a, b):
    detail(f"copy\n    {a=}\n -> {b=})")
    a, b = Path(a), Path(b)
    if not a.exists():
        return
    if a.is_dir():
        b.mkdir(parents=True, exist_ok=True)
        shutil.copytree(a, b, dirs_exist_ok=True)
    else:
        b.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(a, b)


def snapshot_resume_checkpoint(root: Path, keep: int = 3):
    """Archive the exact user/repaired Java tree + build configuration before a
    resumed invocation can touch it. This is intentionally independent of repair
    transactions: it is the emergency 'what I had when I reran the script' copy.
    """
    root = Path(root)
    java_root = root / "app/src/main/java"
    if not java_root.is_dir():
        return None
    dst_dir = root / "analysis/source-repair/resume-baselines"
    dst_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    dst = dst_dir / f"resume-{stamp}.zip"
    try:
        with zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for src in sorted(java_root.rglob("*.java")):
                zf.write(src, "app/src/main/java/" + src.relative_to(java_root).as_posix())
            for rel in (
                "app/build.gradle", "build.gradle", "settings.gradle", "gradle.properties",
                "local.properties", "app/src/main/AndroidManifest.xml",
            ):
                src = root / rel
                if src.is_file():
                    zf.write(src, rel)
        old = sorted(dst_dir.glob("resume-*.zip"), key=lambda q: q.stat().st_mtime, reverse=True)
        for stale in old[max(1, int(keep)):]:
            stale.unlink(missing_ok=True)
        log(f"Resume safety snapshot: {dst}")
        return dst
    except Exception as exc:
        warn(f"Could not create resume safety snapshot: {exc}")
        dst.unlink(missing_ok=True)
        return None


def _sdk_int(value):
    """Return an integer Android API level when value is numeric, else None."""
    if value is None:
        return None
    m = re.match(r"^\s*(\d+)", str(value))
    return int(m.group(1)) if m else None


def manifest_info(p):
    """Read reconstruction metadata from the pristine Apktool manifest."""
    d = {
        "package": "reconstructed.apk",
        "min_sdk": None,
        "target_sdk": None,
        "compile_sdk": None,
        "version_code": None,
        "version_name": None,
        "extract_native_libs": None,
    }
    try:
        r = ET.parse(p).getroot()
        d["package"] = r.get("package") or d["package"]
        d["version_code"] = r.get(A + "versionCode")
        d["version_name"] = r.get(A + "versionName")
        d["compile_sdk"] = _sdk_int(
            r.get(A + "compileSdkVersion") or r.get("platformBuildVersionCode")
        )
        u = r.find("uses-sdk")
        if u is not None:
            d["min_sdk"] = _sdk_int(u.get(A + "minSdkVersion"))
            d["target_sdk"] = _sdk_int(u.get(A + "targetSdkVersion"))
        app = r.find("application")
        if app is not None:
            raw = app.get(A + "extractNativeLibs")
            if raw is not None:
                d["extract_native_libs"] = str(raw).strip().lower() == "true"
    except Exception as e:
        warn("manifest parse: " + str(e))
    return d


def scan(root):
    imports = collections.Counter()
    classes = set()
    packages = set()
    files = {}
    bad = []
    for p in root.rglob("*.java"):
        try:
            t = p.read_text(errors="ignore")
        except OSError:
            continue
        imports.update(IRE.findall(t))
        m = PRE.search(t)
        pkg = m.group(1) if m else ""
        if pkg:
            packages.add(pkg)
        # First declared type is normally the file's primary class.
        tm = TRE.search(t)
        if tm:
            fq = (pkg + "." + tm.group(1)).strip(".")
            classes.add(fq)
            files[fq] = p
        if any(
            x in t
            for x in (
                "JADX ERROR",
                "Method dump skipped",
                "UnsupportedOperationException",
            )
        ):
            bad.append(str(p))
    return imports, classes, packages, files, bad


def local(x, classes, packages):
    x = x.replace(".*", "")
    if x.startswith(PLATFORM) or x in classes:
        return True
    q = x.split(".")
    return any(".".join(q[:i]) in classes for i in range(len(q), 1, -1)) or any(
        x == p or x.startswith(p + ".") for p in packages
    )




@dataclass(frozen=True, order=True)
class MavenCoordinate:
    group: str
    artifact: str
    version: str
    def tuple(self):
        return (self.group, self.artifact, self.version)
    def notation(self):
        return f"{self.group}:{self.artifact}:{self.version}"

@dataclass
class CandidateEvidence:
    coordinate: MavenCoordinate
    classes: set[str] = field(default_factory=set)
    covers: set[str] = field(default_factory=set)
    import_weight: int = 0
    coverage_count: int = 0
    coverage_ratio: float = 0.0
    package_agreement: float = 0.0
    search_rank_score: float = 0.0
    learned_score: float = 0.0
    recency_score: float = 0.0
    coherence_score: float = 0.0
    sparse_penalty: float = 0.0
    total_score: float = 0.0
    reasons: list[str] = field(default_factory=list)

@dataclass
class PackageArtifactStats:
    gav: list[str]
    successful_apks: int = 0
    classes_matched: int = 0
    queries_matched: int = 0
    failures: int = 0
    hits: int = 0
    first_seen: str | None = None
    last_seen: str | None = None

@dataclass
class LookupEvent:
    time: str
    kind: str
    key: str
    url: str
    cached: bool = False
    error: str | None = None

@dataclass
class PomHealth:
    coordinate: MavenCoordinate
    ok: bool = False
    pom_url: str | None = None
    repository: str | None = None
    parent: MavenCoordinate | None = None
    parent_ok: bool | None = None
    imported_boms: list[MavenCoordinate] = field(default_factory=list)
    missing_metadata: list[str] = field(default_factory=list)
    score_adjustment: float = 0.0
    reason: str = ""

@dataclass
class PruneEvidence:
    artifact: str
    confidence: str
    reason: str
    matched_by: str
    package_ratio: float = 0.0

@dataclass
class ResolverStats:
    queries: int = 0
    cache_hits: int = 0
    package_index_hits: int = 0
    package_probes: int = 0
    class_probes: int = 0

def package_similarity(fqcn, gav):
    """Heuristic structural agreement between Java package and Maven group/artifact."""
    pkg = package_prefix(fqcn)
    group, artifact, _ = gav
    gp = group.split(".")
    pp = pkg.split(".")
    common = 0
    for a, b in zip(gp, pp):
        if a != b:
            break
        common += 1
    group_score = common / max(1, len(gp))
    artifact_score = 1.0 if artifact.lower().replace("-", "") in pkg.lower().replace(".", "") else 0.0
    return min(1.0, 0.8 * group_score + 0.2 * artifact_score)

def score_candidate(gav, cls, missing, imports, search_rank=None, learned=None):
    covers = set(missing) & set(cls)
    import_weight = sum(imports.get(x, 1) for x in covers)
    coverage_count = len(covers)
    coverage_ratio = coverage_count / max(1, len(missing))
    pkg_agreement = (sum(package_similarity(x, gav) for x in covers) / coverage_count
                     if covers else 0.0)

    # Search rank is relevance, not claimed download popularity. It is deliberately
    # subordinate to exact structural evidence.
    search_rank_score = 0.0 if search_rank is None else 40.0 / (1.0 + search_rank)
    learned_score = 0.0
    if learned:
        learned_score = min(120.0,
            30.0 * learned.get("successful_apks", 0)
            + 2.0 * learned.get("classes_matched", 0)
            + 5.0 * learned.get("queries_matched", 0)
            - 20.0 * learned.get("failures", 0))

    # A candidate covering multiple related unresolved classes is much stronger
    # evidence than an artifact that happens to contain one class.
    coherence = 50.0 if coverage_count >= 3 else (20.0 if coverage_count == 2 else 0.0)
    sparse_penalty = 35.0 if coverage_count == 1 and len(missing) >= 4 else 0.0

    total = (
        coverage_count * 1000.0
        + import_weight * 25.0
        + coverage_ratio * 250.0
        + pkg_agreement * 100.0
        + search_rank_score
        + learned_score
        + coherence
        - sparse_penalty
    )
    return CandidateEvidence(
        coordinate=MavenCoordinate(*gav), classes=set(cls), covers=covers,
        import_weight=import_weight, coverage_count=coverage_count,
        coverage_ratio=coverage_ratio, package_agreement=pkg_agreement,
        search_rank_score=search_rank_score, learned_score=learned_score,
        coherence_score=coherence, sparse_penalty=sparse_penalty,
        total_score=total,
        reasons=[
            f"exact={coverage_count}", f"imports={import_weight}",
            f"coverage={coverage_ratio:.1%}", f"package={pkg_agreement:.2f}",
            f"rank={search_rank_score:.1f}", f"learned={learned_score:.1f}",
            f"coherence={coherence:.1f}", f"penalty={sparse_penalty:.1f}"
        ])

# ===========================================================================
# v14 knowledge layer
#
# Three separate stores, each with one job:
#   1. package-map.json (beside the script)   READ-ONLY curated seed. Never written.
#   2. <cache>/lookups.sqlite                 HTTP cache with TTLs + per-artifact
#                                             class lists + a local class index.
#   3. <cache>/package-hints.json             learned package -> group/artifact
#      <cache>/package-artifacts.json         learned package -> exact GAV stats
#
# v13 wrote learned records back into the seed file and learned from every class
# a selected jar happened to contain, so fat/shaded jars (e.g. a plugin SDK that
# bundles androidx) were "learned" as the owners of androidx.* packages.
# ===========================================================================
import sqlite3, threading, zlib, urllib.error

LOOKUP_CACHE = None            # _LookupStore
LOOKUP_CACHE_PATH = None
LOOKUP_MISSES = []
LOOKUP_FAILURES = []
DEPENDENCY_COMPAT_AUDIT = []
SHADED_REJECTIONS = []
PACKAGE_INDEX = {}
PACKAGE_INDEX_PATH = None
PACKAGE_SEED = {}              # prefix -> label (curated, read-only)
PACKAGE_SEED_PATH = None
PACKAGE_MAP_PATH = None        # kept for report compatibility (= seed path)
PACKAGE_HINTS = {}             # learned prefix -> {"groups": {...}}
PACKAGE_HINTS_PATH = None
PINNED_VERSIONS = {}           # (group, artifact) -> version embedded in the APK
_GOOGLE_GROUPS = None
_BLOCKED_HOSTS = collections.Counter()

DAY = 86400.0
# None = never expires. Anything addressed by an exact version is immutable.
CACHE_TTL_OK = {
    "maven-pom": None,
    "google-master-index": 7 * DAY,
    "google-group-index": 7 * DAY,
    "maven-central-class": 30 * DAY,
    "maven-central-package": 30 * DAY,
    "maven-central-ga": 7 * DAY,
    "mvnrepository": 30 * DAY,
}
CACHE_TTL_NOT_FOUND = 14 * DAY     # definitive 404/410
CACHE_TTL_BLOCKED = 1 * DAY        # 403 (e.g. Cloudflare on mvnrepository)
# Timeouts, DNS failures, 429 and 5xx are NEVER cached: v13 cached them forever.

# Package namespaces whose real owner is unambiguous. A class under one of these
# prefixes that lives in an artifact from any other group is a shaded/bundled
# copy: it must not count as coverage, must not be learned, and must not drive
# pruning. (Dynamic Google ownership from master-index.xml is layered on top.)
CANONICAL_OWNERS = (
    ("androidx.", ("androidx.",)),
    ("android.support.", ("com.android.support",)),
    ("com.google.android.material.", ("com.google.android.material",)),
    ("com.google.android.gms.", ("com.google.android.gms", "com.google.firebase")),
    ("com.google.firebase.", ("com.google.firebase", "com.google.android.gms")),
    ("kotlin.", ("org.jetbrains.kotlin",)),
    ("kotlinx.coroutines.", ("org.jetbrains.kotlinx",)),
    ("kotlinx.serialization.", ("org.jetbrains.kotlinx",)),
    ("org.jetbrains.annotations.", ("org.jetbrains",)),
    ("com.google.gson.", ("com.google.code.gson",)),
    ("com.google.common.", ("com.google.guava",)),
    ("com.google.protobuf.", ("com.google.protobuf",)),
    ("okhttp3.", ("com.squareup.okhttp3",)),
    ("okio.", ("com.squareup.okio",)),
    ("retrofit2.", ("com.squareup.retrofit2",)),
    ("com.squareup.", ("com.squareup",)),
    ("io.reactivex.", ("io.reactivex",)),
    ("dagger.", ("com.google.dagger",)),
    ("javax.inject.", ("javax.inject",)),
    ("com.fasterxml.jackson.", ("com.fasterxml.jackson",)),
    ("com.bumptech.glide.", ("com.github.bumptech.glide",)),
    ("org.greenrobot.", ("org.greenrobot",)),
    ("org.bouncycastle.", ("org.bouncycastle",)),
    ("org.slf4j.", ("org.slf4j",)),
)


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def _iso_to_ts(s):
    try:
        return datetime.fromisoformat(str(s)).timestamp()
    except Exception:
        return time.time()


class _LookupStore:
    """SQLite-backed cache. Incremental writes (no full-file rewrite per request),
    crash-safe, and safe to share between concurrent runs."""

    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(self.path), timeout=60,
                                  isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS http(
                url TEXT PRIMARY KEY, kind TEXT, ok INTEGER, status INTEGER,
                body BLOB, error TEXT, fetched REAL);
            CREATE TABLE IF NOT EXISTS artifact_classes(
                path TEXT PRIMARY KEY, size INTEGER, mtime REAL, classes BLOB);
            CREATE TABLE IF NOT EXISTS class_index(
                cls TEXT, g TEXT, a TEXT, v TEXT,
                PRIMARY KEY (cls, g, a, v)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS indexed_artifacts(gav TEXT PRIMARY KEY);
        """)

    # ---------------------------------------------------------------- http
    def __len__(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM http").fetchone()[0]

    def __contains__(self, url):
        with self.lock:
            return self.db.execute("SELECT 1 FROM http WHERE url=?", (url,)).fetchone() is not None

    def lookup(self, url, kind):
        with self.lock:
            row = self.db.execute(
                "SELECT ok, status, body, error, fetched FROM http WHERE url=?", (url,)
            ).fetchone()
        if row is None:
            return None
        ok, status, body, error, fetched = row
        if ok:
            ttl = CACHE_TTL_OK.get(kind, 7 * DAY)
        elif status == 403:
            ttl = CACHE_TTL_BLOCKED
        else:
            ttl = CACHE_TTL_NOT_FOUND
        if ttl is not None and time.time() - (fetched or 0) > ttl:
            return None
        return {"ok": bool(ok), "status": status,
                "body": zlib.decompress(body) if body else b"", "error": error}

    def store(self, url, kind, ok, status=None, body=b"", error=None):
        with self.lock:
            self.db.execute(
                "INSERT OR REPLACE INTO http VALUES (?,?,?,?,?,?,?)",
                (url, kind, int(bool(ok)), status,
                 zlib.compress(body, 6) if body else None, error, time.time()))

    def clear_http(self):
        with self.lock:
            self.db.execute("DELETE FROM http")

    def import_legacy_json(self, legacy):
        """One-time migration of v13 url-lookups.json. Only successes and genuine
        404s are imported; the transient errors v13 cached forever are dropped."""
        try:
            data = json.loads(Path(legacy).read_text())
        except Exception as e:
            warn(f"Could not migrate legacy cache {legacy}: {e}")
            return 0
        n = dropped = 0
        with self.lock:
            self.db.execute("BEGIN")
            for url, ent in data.items():
                if not isinstance(ent, dict):
                    continue
                kind = ("maven-pom" if url.endswith(".pom") else
                        "google-group-index" if url.endswith("group-index.xml") else
                        "mvnrepository" if "mvnrepository.com" in url else
                        "maven-central-search")
                ts = _iso_to_ts(ent.get("time"))
                if ent.get("ok"):
                    body = str(ent.get("body", "")).encode()
                    self.db.execute("INSERT OR IGNORE INTO http VALUES (?,?,?,?,?,?,?)",
                                    (url, kind, 1, 200, zlib.compress(body, 6), None, ts))
                    n += 1
                elif "404" in str(ent.get("error", "")):
                    self.db.execute("INSERT OR IGNORE INTO http VALUES (?,?,?,?,?,?,?)",
                                    (url, kind, 0, 404, None, ent.get("error"), ts))
                    n += 1
                else:
                    dropped += 1
            self.db.execute("COMMIT")
        log(f"Migrated {n} legacy cache entries; dropped {dropped} cached transient failures")
        return n

    # ------------------------------------------------------- artifact classes
    def get_classes(self, path):
        try:
            st = Path(path).stat()
        except OSError:
            return None
        with self.lock:
            row = self.db.execute(
                "SELECT size, mtime, classes FROM artifact_classes WHERE path=?",
                (str(path),)).fetchone()
        if row and row[0] == st.st_size and abs(row[1] - st.st_mtime) < 1e-3:
            return set(zlib.decompress(row[2]).decode().split("\n")) - {""}
        return None

    def put_classes(self, path, classes):
        try:
            st = Path(path).stat()
        except OSError:
            return
        blob = zlib.compress("\n".join(sorted(classes)).encode(), 6)
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO artifact_classes VALUES (?,?,?,?)",
                            (str(path), st.st_size, st.st_mtime, blob))

    # ----------------------------------------------------------- class index
    def index_artifact(self, gav, native_classes):
        key = ":".join(gav)
        with self.lock:
            if self.db.execute("SELECT 1 FROM indexed_artifacts WHERE gav=?", (key,)).fetchone():
                return
            self.db.execute("BEGIN")
            self.db.executemany(
                "INSERT OR IGNORE INTO class_index VALUES (?,?,?,?)",
                ((c, *gav) for c in native_classes if "$" not in c))
            self.db.execute("INSERT OR IGNORE INTO indexed_artifacts VALUES (?)", (key,))
            self.db.execute("COMMIT")

    def owners_of(self, fqcn, limit=6):
        with self.lock:
            rows = self.db.execute(
                "SELECT g, a, v FROM class_index WHERE cls=? LIMIT 50", (fqcn,)).fetchall()
        # Newest-looking version per GA first; versions sort lexically as tuples.
        best = {}
        for g, a, v in rows:
            if (g, a) not in best or _version_key(v) > _version_key(best[(g, a)]):
                best[(g, a)] = v
        return [(g, a, v) for (g, a), v in list(best.items())[:limit]]


def _version_key(v):
    return tuple(int(x) if x.isdigit() else -1 for x in re.split(r"[.\-]", str(v)))


# ---------------------------------------------------------------- loading
def _load_json(path, default):
    try:
        return json.loads(Path(path).read_text()) if Path(path).exists() else default
    except Exception as e:
        warn(f"Could not read {path}: {e}; starting empty")
        return default


def _atomic_write_json(path, data):
    if path is None:
        return
    tmp = Path(str(path) + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    tmp.replace(path)


def load_lookup_cache(cache_dir, seed_path=None):
    global LOOKUP_CACHE, LOOKUP_CACHE_PATH, PACKAGE_INDEX, PACKAGE_INDEX_PATH
    global PACKAGE_SEED, PACKAGE_SEED_PATH, PACKAGE_MAP_PATH, PACKAGE_HINTS, PACKAGE_HINTS_PATH
    cache_dir.mkdir(parents=True, exist_ok=True)

    LOOKUP_CACHE_PATH = cache_dir / "lookups.sqlite"
    LOOKUP_CACHE = _LookupStore(LOOKUP_CACHE_PATH)
    legacy = cache_dir / "url-lookups.json"
    if legacy.exists():
        LOOKUP_CACHE.import_legacy_json(legacy)
        legacy.rename(legacy.with_suffix(".json.migrated"))
    log(f"Persistent lookup cache: {LOOKUP_CACHE_PATH} ({len(LOOKUP_CACHE)} URLs)")

    PACKAGE_INDEX_PATH = cache_dir / "package-artifacts.json"
    PACKAGE_INDEX = _load_json(PACKAGE_INDEX_PATH, {})
    _purge_shaded_from_index()
    log(f"Learned package index: {PACKAGE_INDEX_PATH} ({len(PACKAGE_INDEX)} prefixes)")

    PACKAGE_HINTS_PATH = cache_dir / "package-hints.json"
    PACKAGE_HINTS = _load_json(PACKAGE_HINTS_PATH, {})

    # Seed: read-only. Tolerate a v13-polluted file by importing its dict records
    # into the learned store (minus shaded ones) and ignoring them as seed.
    PACKAGE_SEED_PATH = PACKAGE_MAP_PATH = Path(seed_path or Path(__file__).parent / "package-map.json")
    raw = {}
    try:
        raw = readjson(PACKAGE_SEED_PATH) if PACKAGE_SEED_PATH.exists() else {}
    except Exception as e:
        warn(f"Could not read package seed {PACKAGE_SEED_PATH}: {e}")
    PACKAGE_SEED = {k: v for k, v in raw.items() if isinstance(v, str)}
    legacy_records = {k: v for k, v in raw.items() if isinstance(v, dict)}
    if legacy_records:
        kept, dropped = _import_legacy_hints(legacy_records)
        warn(f"{PACKAGE_SEED_PATH.name} contains {len(legacy_records)} learned records written by v13. "
             f"Imported {kept} group observations into {PACKAGE_HINTS_PATH.name}, discarded {dropped} "
             f"shaded-copy observations. v14 never writes the seed; restore the original file when convenient.")
    log(f"Package seed: {PACKAGE_SEED_PATH} ({len(PACKAGE_SEED)} prefixes, read-only); "
        f"learned hints: {len(PACKAGE_HINTS)} packages")


def _import_legacy_hints(records):
    kept = dropped = 0
    for pkg, rec in records.items():
        for group, stats in (rec.get("groups") or {}).items():
            if canonical_owner_ok(pkg + ".X", group) is False:
                dropped += 1
                continue
            dst = PACKAGE_HINTS.setdefault(pkg, {"groups": {}})["groups"]
            if group not in dst and isinstance(stats, dict):
                dst[group] = stats
                kept += 1
    save_package_hints()
    return kept, dropped


def _purge_shaded_from_index():
    removed = 0
    for pkg in list(PACKAGE_INDEX):
        entries = PACKAGE_INDEX[pkg]
        good = [e for e in entries
                if len(e.get("gav", [])) == 3 and canonical_owner_ok(pkg + ".X", e["gav"][0]) is not False]
        removed += len(entries) - len(good)
        if good:
            PACKAGE_INDEX[pkg] = good
        else:
            del PACKAGE_INDEX[pkg]
    if removed:
        warn(f"Removed {removed} shaded-copy mappings from the learned package index")
        save_package_index()


def package_index_candidates(fqcn):
    pkg = package_prefix(fqcn)
    parts = pkg.split(".")
    ans, seen = [], set()
    for depth in range(len(parts), 1, -1):
        prefix = ".".join(parts[:depth])
        for ent in PACKAGE_INDEX.get(prefix, []):
            gav = tuple(ent.get("gav", []))
            if len(gav) == 3 and gav not in seen and canonical_owner_ok(fqcn, gav[0]) is not False:
                ans.append((prefix, gav, ent))
                seen.add(gav)
    return ans


def save_package_index():
    _atomic_write_json(PACKAGE_INDEX_PATH, PACKAGE_INDEX)


def save_package_hints():
    _atomic_write_json(PACKAGE_HINTS_PATH, PACKAGE_HINTS)


def save_lookup_cache():
    """SQLite writes are incremental; kept for call-site compatibility."""
    return None


# ------------------------------------------------------------- ownership
def google_master_groups():
    """All groups published on Google Maven, from master-index.xml (cached 7 days)."""
    global _GOOGLE_GROUPS
    if _GOOGLE_GROUPS is None:
        body = cached_json_url(GOOGLE_REPO + "/master-index.xml",
                               "google-master-index", "master-index", timeout=60)
        groups = set()
        if body:
            try:
                groups = {ch.tag for ch in ET.fromstring(body)}
            except Exception as e:
                LOOKUP_FAILURES.append({"time": utcnow(), "kind": "google-master-index",
                                        "key": "master-index", "url": GOOGLE_REPO,
                                        "error": f"parse: {e}"})
        _GOOGLE_GROUPS = groups
        detail(f"Google Maven master index: {len(groups)} groups", 1)
    return _GOOGLE_GROUPS


def google_owner_groups(fqcn):
    """Google groups that are a package prefix of fqcn, most specific first.
    androidx.appcompat.widget.Toolbar -> ['androidx.appcompat']."""
    groups = google_master_groups()
    if not groups:
        return []
    parts = package_prefix(fqcn).split(".")
    return [".".join(parts[:d]) for d in range(len(parts), 1, -1)
            if ".".join(parts[:d]) in groups]


def canonical_owner_ok(fqcn, group):
    """True: group is the known owner. False: group is definitely NOT the owner
    (shaded/bundled copy). None: no opinion."""
    name = fqcn if fqcn.endswith(".") else package_prefix(fqcn) + "."
    for prefix, allowed in CANONICAL_OWNERS:
        if name.startswith(prefix):
            return any(group == a.rstrip(".") or group.startswith(a) for a in allowed)
    return None


def artifact_profile(gav, classes):
    """Split an artifact's classes into native vs. foreign (shaded) classes."""
    group = gav[0]
    native, foreign = set(), set()
    for c in classes:
        (foreign if canonical_owner_ok(c, group) is False else native).add(c)
    purity = len(native) / max(1, len(classes))
    return native, foreign, purity


# ------------------------------------------------------- learned package hints
def _package_map_groups(value):
    """Reader for both seed strings and learned records."""
    if isinstance(value, str):
        # Seed values are family labels ('gson', 'androidx'); only dotted values
        # can be real Maven groups.
        return [(value, 1)] if "." in value else []
    if not isinstance(value, dict):
        return []
    groups = value.get("groups", {})
    if isinstance(groups, dict):
        out = []
        for g, stats in groups.items():
            if isinstance(stats, dict):
                score = int(stats.get("hits", 0)) + int(stats.get("classes_matched", 0))
            else:
                score = int(stats or 0)
            out.append((g, score))
        return sorted(out, key=lambda x: x[1], reverse=True)
    if isinstance(value.get("group"), str):
        return [(value["group"], int(value.get("hits", 1)))]
    return []


def package_map_groups(fqcn):
    """Longest-prefix-first lookup across seed + learned hints."""
    matches = []
    for source in (PACKAGE_HINTS, PACKAGE_SEED):
        for prefix, value in source.items():
            p = prefix.rstrip(".")
            if fqcn == p or fqcn.startswith(p + "."):
                matches.append((len(p), p, _package_map_groups(value)))
    matches.sort(key=lambda m: m[0], reverse=True)
    ans, seen = [], set()
    for _, prefix, groups in matches:
        for group, score in groups:
            if group not in seen and canonical_owner_ok(fqcn, group) is not False:
                ans.append((prefix, group, score))
                seen.add(group)
    return ans


def learned_artifacts(prefix, group):
    rec = (PACKAGE_HINTS.get(prefix) or {}).get("groups", {}).get(group) or {}
    return [(a, (s or {}).get("last_version")) for a, s in (rec.get("artifacts") or {}).items()
            if isinstance(s, dict)]


def _learnable_classes(sel):
    group = sel["gav"][0]
    return {c for c in (sel.get("all_hits") or sel.get("covers") or ())
            if canonical_owner_ok(c, group) is not False}


def learn_package_index(selected):
    added = 0
    for sel in selected:
        gav = list(sel["gav"])
        learn = _learnable_classes(sel)
        matched = len(learn)
        for pkg in {package_prefix(fq) for fq in learn if package_prefix(fq)}:
            entries = PACKAGE_INDEX.setdefault(pkg, [])
            ent = next((e for e in entries if e.get("gav") == gav), None)
            if ent:
                ent["hits"] = int(ent.get("hits", 0)) + 1
                ent["successful_apks"] = int(ent.get("successful_apks", 0)) + 1
                ent["classes_matched"] = int(ent.get("classes_matched", 0)) + matched
                ent["queries_matched"] = int(ent.get("queries_matched", 0)) + 1
                ent.setdefault("failures", 0)
                ent["last_seen"] = utcnow()
            else:
                now = utcnow()
                entries.append(asdict(PackageArtifactStats(
                    gav=gav, successful_apks=1, classes_matched=matched,
                    queries_matched=1, failures=0, hits=1,
                    first_seen=now, last_seen=now)))
                added += 1
    save_package_index()
    if added:
        log(f"Learned {added} new package -> artifact mappings")


def learn_package_map(selected):
    """Learn package -> group/artifact hints into the CACHE DIR (never the seed),
    from native (non-shaded) classes only."""
    changed = 0
    now = utcnow()
    for sel in selected:
        group, artifact_id, version = sel["gav"]
        packages = collections.Counter(package_prefix(c) for c in _learnable_classes(sel)
                                       if package_prefix(c))
        for pkg, matched in packages.items():
            rec = PACKAGE_HINTS.setdefault(pkg, {"groups": {}}).setdefault("groups", {}).setdefault(
                group, {"hits": 0, "classes_matched": 0, "artifacts": {},
                        "first_seen": now, "last_seen": now})
            rec["hits"] = int(rec.get("hits", 0)) + 1
            # classes_matched is a running max, not a sum: re-running the same APK
            # should not keep inflating confidence.
            rec["classes_matched"] = max(int(rec.get("classes_matched", 0)), matched)
            rec["last_seen"] = now
            ar = rec.setdefault("artifacts", {}).setdefault(artifact_id, {"hits": 0, "last_version": version})
            ar["hits"] = int(ar.get("hits", 0)) + 1
            ar["last_version"] = version
            changed += 1
    if changed:
        save_package_hints()
        log(f"Learned {changed} package observations -> {PACKAGE_HINTS_PATH}")


# --------------------------------------------------------------- fetching
def _host(url):
    return urllib.parse.urlsplit(url).netloc


def _fetch(url, timeout, attempts=3):
    """GET with retry/backoff for transient failures. Raises the last error."""
    last = None
    for i in range(attempts):
        try:
            return get(url, timeout=timeout)
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (404, 410, 403):
                raise
            if e.code == 429:
                retry = e.headers.get("Retry-After") if e.headers else None
                time.sleep(min(30, float(retry)) if retry and retry.isdigit() else 2 ** (i + 1))
                continue
            if 500 <= e.code < 600:
                time.sleep(1.5 * (i + 1))
                continue
            raise
        except Exception as e:  # URLError, timeout, reset
            last = e
            time.sleep(1.5 * (i + 1))
    raise last


def cached_json_url(url, kind, key, timeout=35):
    """Cached GET. Successes cached per CACHE_TTL_OK; 404/410 for CACHE_TTL_NOT_FOUND;
    403 briefly; transient failures not cached at all."""
    if LOOKUP_CACHE is None:
        raise RuntimeError("lookup cache not initialized")
    ent = LOOKUP_CACHE.lookup(url, kind)
    if ent is not None:
        detail(f"CACHE HIT [{kind}] {key}", 1)
        if ent["ok"]:
            return ent["body"]
        detail(f"CACHED MISS [{kind}] {key}: {ent.get('error')}", 1)
        LOOKUP_MISSES.append({"time": utcnow(), "kind": kind, "key": key, "url": url,
                              "cached": True, "error": ent.get("error")})
        return None
    host = _host(url)
    if _BLOCKED_HOSTS[host] >= 3:
        detail(f"skipping {host}: blocked repeatedly this run", 2)
        return None
    detail(f"CACHE MISS [{kind}] {key}", 2)
    try:
        body = _fetch(url, timeout)
        LOOKUP_CACHE.store(url, kind, True, 200, body)
        return body
    except urllib.error.HTTPError as e:
        err = f"HTTP {e.code}: {e.reason}"
        if e.code in (404, 410, 403):
            LOOKUP_CACHE.store(url, kind, False, e.code, error=err)
            if e.code == 403:
                _BLOCKED_HOSTS[host] += 1
            LOOKUP_MISSES.append({"time": utcnow(), "kind": kind, "key": key, "url": url,
                                  "cached": False, "error": err})
        else:
            LOOKUP_FAILURES.append({"time": utcnow(), "kind": kind, "key": key, "url": url,
                                    "error": err + " (not cached; will retry next run)"})
        return None
    except Exception as e:
        LOOKUP_FAILURES.append({"time": utcnow(), "kind": kind, "key": key, "url": url,
                                "error": f"{type(e).__name__}: {e} (not cached; will retry next run)"})
        return None


# ------------------------------------------------- versions embedded in the APK
_UNSTABLE_VERSION = re.compile(r"(?i)(alpha|beta|rc\d*$|-rc|dev|snapshot|eap|preview|-m\d)")


def pick_version(versions, group, artifact_id):
    pinned = PINNED_VERSIONS.get((group, artifact_id))
    if pinned:
        return pinned
    versions = [v for v in versions if v]
    stable = [v for v in versions if not _UNSTABLE_VERSION.search(v)]
    return (stable or versions)[-1] if versions else None


def pin(gav):
    g, a, v = gav
    return (g, a, PINNED_VERSIONS.get((g, a), v))


def _parse_properties(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")) and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


_VERSION_RE = re.compile(r"^\d[\w.\-+]*$")


def apk_embedded_coordinates(apk):
    """Exact library coordinates the build left inside the APK:
      META-INF/<group>_<artifact>.version         (androidx, material, ...)
      META-INF/maven/<g>/<a>/pom.properties       (unshrunk plain jars)
      <client>.properties with version=/client=   (Play services / Firebase)
    Returns {(group, artifact): (version, source_entry)}."""
    found = {}
    try:
        with zipfile.ZipFile(apk) as z:
            for n in z.namelist():
                base = n.rsplit("/", 1)[-1]
                try:
                    if n.startswith("META-INF/") and n.endswith(".version") and "_" in base:
                        g, _, a = base[:-len(".version")].partition("_")
                        v = z.read(n).decode("utf-8", "replace").strip()
                        if "." in g and a and _VERSION_RE.match(v):
                            found[(g, a)] = (v, n)
                    elif n.startswith("META-INF/maven/") and base == "pom.properties":
                        p = _parse_properties(z.read(n).decode("utf-8", "replace"))
                        if p.get("groupId") and p.get("artifactId") and _VERSION_RE.match(p.get("version", "")):
                            found[(p["groupId"], p["artifactId"])] = (p["version"], n)
                    elif "/" not in n and n.endswith(".properties"):
                        p = _parse_properties(z.read(n).decode("utf-8", "replace"))
                        client, v = p.get("client", ""), p.get("version", "")
                        if client and _VERSION_RE.match(v):
                            g = ("com.google.firebase" if client.startswith("firebase-") else
                                 "com.google.android.gms" if client.startswith("play-services-") else
                                 "com.google.android.datatransport" if client.startswith("transport-") else None)
                            if g:
                                found[(g, client)] = (v, n)
                except Exception as e:
                    detail(f"embedded metadata {n}: {e}", 2)
    except zipfile.BadZipFile as e:
        warn(f"Could not scan APK for embedded versions: {e}")
    return found


def set_pinned_versions(found):
    PINNED_VERSIONS.clear()
    PINNED_VERSIONS.update({ga: v for ga, (v, _) in found.items()})

def central_class(fqcn, rows=12):
    qs = urllib.parse.urlencode({"q": f'fc:"{fqcn}"', "rows": rows, "wt": "json"})
    url = CENTRAL_SEARCH + "?" + qs
    detail("Maven Central: " + fqcn, 1)
    detail(url, 2)
    body = cached_json_url(url, "maven-central-class", fqcn)
    if body is None:
        return []
    try:
        docs = json.loads(body)["response"]["docs"]
        detail(f"found {len(docs)} candidate records", 1)
        if not docs:
            LOOKUP_MISSES.append({"time": utcnow(), "kind": "maven-central-class",
                                  "key": fqcn, "url": url, "cached": url in LOOKUP_CACHE,
                                  "error": "zero search results"})
        return docs
    except Exception as e:
        LOOKUP_FAILURES.append({"time": utcnow(), "kind": "maven-central-class",
                                "key": fqcn, "url": url, "error": f"parse: {e}"})
        warn(f"Central search parse {fqcn}: {e}")
        return []


def gavpath(g, a, v, e):
    return f"{g.replace('.', '/')}/{a}/{v}/{a}-{v}.{e}"


def artifact(g, a, v, cache):
    google_first = g in (google_master_groups() or ()) or g.startswith(("androidx.", "com.google.android", "com.android."))
    repos = ((GOOGLE_REPO, "aar"), (GOOGLE_REPO, "jar"), (CENTRAL_REPO, "jar"), (CENTRAL_REPO, "aar")) \
        if google_first else \
        ((CENTRAL_REPO, "jar"), (CENTRAL_REPO, "aar"), (GOOGLE_REPO, "aar"), (GOOGLE_REPO, "jar"))
    for repo, e in repos:
        p = cache / "artifacts" / g.replace(".", "/") / a / v / f"{a}-{v}.{e}"
        if p.exists() and p.stat().st_size:
            if zipfile.is_zipfile(p):
                detail(f"cache hit {g}:{a}:{v} ({e})", 2)
                return p, e, repo
            warn(f"Discarding corrupt cached artifact {p}")
            p.unlink()
        url = repo + "/" + gavpath(g, a, v, e)
        if LOOKUP_CACHE is not None:
            neg = LOOKUP_CACHE.lookup(url, "artifact")
            if neg is not None and not neg["ok"]:
                continue
        try:
            detail(f"trying {g}:{a}:{v} ({e})", 2)
            return download(url, p), e, repo
        except urllib.error.HTTPError as ex:
            if ex.code in (404, 410) and LOOKUP_CACHE is not None:
                LOOKUP_CACHE.store(url, "artifact", False, ex.code, error=f"HTTP {ex.code}")
            detail(f"not available as {e} from {repo}: {ex}", 2)
        except Exception as ex:
            detail(f"not available as {e} from {repo}: {ex}", 2)
    return None, None, None


def prefetch_artifacts(gavs, cache, workers=6):
    """Download candidate artifacts in parallel; inspection stays sequential."""
    todo = [g for g in gavs if not any(
        (cache / "artifacts" / g[0].replace(".", "/") / g[1] / g[2] / f"{g[1]}-{g[2]}.{e}").exists()
        for e in ("jar", "aar"))]
    if len(todo) < 2:
        return
    log(f"Prefetching {len(todo)} candidate artifacts ({workers} parallel)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda gav: artifact(*gav, cache), todo))


_VERSION_METADATA_CACHE = {}


def artifact_min_sdk(path, artifact_type):
    """Read an AAR's declared minSdkVersion, returning None when unavailable."""
    if artifact_type != "aar" or not path or not Path(path).exists():
        return None
    try:
        with zipfile.ZipFile(path) as z:
            if "AndroidManifest.xml" not in z.namelist():
                return None
            root = ET.fromstring(z.read("AndroidManifest.xml"))
            uses = next((x for x in list(root) if x.tag.rsplit("}", 1)[-1] == "uses-sdk"), None)
            if uses is None:
                return None
            return _sdk_int(uses.get(A + "minSdkVersion"))
    except Exception as ex:
        detail(f"Could not read minSdk from {path}: {ex}", 2)
        return None



def artifact_min_compile_sdk(path, artifact_type):
    """Read AGP AAR metadata minCompileSdk, returning None when not declared."""
    if artifact_type != "aar" or not path or not Path(path).exists():
        return None
    metadata_name = "META-INF/com/android/build/gradle/aar-metadata.properties"
    try:
        with zipfile.ZipFile(path) as z:
            if metadata_name not in z.namelist():
                return None
            text = z.read(metadata_name).decode("utf-8", "replace")
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() == "minCompileSdk":
                return _sdk_int(value.strip())
    except Exception as ex:
        detail(f"Could not read minCompileSdk from {path}: {ex}", 2)
    return None


def find_compile_compatible_artifact_version(
    group, artifact_id, current_version, cache, max_compile_sdk, tmp,
    project_min_sdk=None, required_classes=(),
):
    """Find newest published version compatible with compileSdk and app minSdk."""
    versions = available_artifact_versions(group, artifact_id)
    if not versions:
        return None
    required_classes = set(required_classes or ())
    for version in reversed(versions):
        if version == current_version:
            continue
        p, e, repo = artifact(group, artifact_id, version, cache)
        if not p:
            continue
        lib_min_sdk = artifact_min_sdk(p, e)
        if project_min_sdk and lib_min_sdk is not None and lib_min_sdk > int(project_min_sdk):
            continue
        min_compile = artifact_min_compile_sdk(p, e)
        if min_compile is not None and min_compile > int(max_compile_sdk):
            continue
        cls = classes_in(p, e, tmp)
        if required_classes and not required_classes.issubset(cls):
            continue
        return (group, artifact_id, version), p, e, repo, cls, lib_min_sdk, min_compile
    return None


def reconcile_selected_compile_sdk(selected, coords, compile_sdk, cache, tmp, project_min_sdk=None):
    """Downgrade selected AARs whose AAR metadata requires a newer compileSdk."""
    changed = 0
    for i, sel in enumerate(list(selected)):
        gav = tuple(sel.get("gav") or ())
        if len(gav) != 3:
            continue
        p = Path(sel.get("file") or "")
        e = sel.get("type")
        min_compile = artifact_min_compile_sdk(p, e)
        sel["min_compile_sdk"] = min_compile
        if min_compile is None or min_compile <= int(compile_sdk):
            continue
        g, a, v = gav
        required = set(sel.get("covers") or sel.get("all_hits") or ())
        log(
            f"Selected {g}:{a}:{v} requires compileSdk {min_compile}; rebuild uses "
            f"compileSdk {compile_sdk}. Searching older compatible versions..."
        )
        replacement = find_compile_compatible_artifact_version(
            g, a, v, cache, int(compile_sdk), tmp,
            project_min_sdk=project_min_sdk,
            required_classes=required,
        )
        if replacement is None:
            warn(
                f"No compileSdk-{compile_sdk}-compatible version of {g}:{a} retained "
                f"the required classes; Gradle may report an AAR metadata compatibility error"
            )
            DEPENDENCY_COMPAT_AUDIT.append({
                "action": "no-compilesdk-compatible-version",
                "coordinate": ":".join(gav),
                "library_min_compile_sdk": min_compile,
                "rebuild_compile_sdk": int(compile_sdk),
                "required_classes": sorted(required),
            })
            continue
        new_gav, new_p, new_e, new_repo, new_cls, new_min_sdk, new_min_compile = replacement
        coords.discard(gav)
        coords.add(tuple(new_gav))
        new_sel = dict(sel)
        new_sel.update({
            "gav": tuple(new_gav),
            "file": str(new_p),
            "type": new_e,
            "classes": new_cls,
            "min_sdk": new_min_sdk,
            "min_compile_sdk": new_min_compile,
            "compile_sdk_substitution_from": ":".join(gav),
        })
        selected[i] = new_sel
        changed += 1
        log(
            f"Using compileSdk-compatible {':'.join(new_gav)} "
            f"(minCompileSdk {new_min_compile if new_min_compile is not None else 'unspecified'})"
        )
        DEPENDENCY_COMPAT_AUDIT.append({
            "action": "downgraded-for-compilesdk-compatibility",
            "from": ":".join(gav),
            "to": ":".join(new_gav),
            "library_min_compile_sdk": min_compile,
            "replacement_min_compile_sdk": new_min_compile,
            "rebuild_compile_sdk": int(compile_sdk),
            "required_classes": sorted(required),
        })
    return changed


def available_artifact_versions(group, artifact_id):
    """Return repository metadata versions, preserving repository order and de-duplicating."""
    key = (group, artifact_id)
    if key in _VERSION_METADATA_CACHE:
        return list(_VERSION_METADATA_CACHE[key])
    rel = f"{group.replace('.', '/')}/{artifact_id}/maven-metadata.xml"
    versions = []
    seen = set()
    for repo in (GOOGLE_REPO, CENTRAL_REPO):
        url = f"{repo}/{rel}"
        try:
            root = ET.fromstring(get(url, timeout=20))
            for el in root.findall("./versioning/versions/version"):
                v = (el.text or "").strip()
                if v and v not in seen:
                    versions.append(v)
                    seen.add(v)
        except Exception as ex:
            detail(f"version metadata unavailable {url}: {ex}", 2)
    _VERSION_METADATA_CACHE[key] = tuple(versions)
    return versions


def find_compatible_artifact_version(group, artifact_id, current_version, cache,
                                     project_min_sdk, tmp, required_classes=()):
    """
    When a candidate AAR requires a newer Android version than the APK, search
    older published versions and return the newest one that both fits minSdk and
    still contains the classes that caused us to select the artifact.
    """
    if not project_min_sdk:
        return None
    versions = available_artifact_versions(group, artifact_id)
    if not versions:
        return None
    required_classes = set(required_classes or ())
    # Maven metadata normally lists oldest -> newest.  Walk newest first, but
    # do not retry the exact candidate that already failed the minSdk check.
    for version in reversed(versions):
        if version == current_version:
            continue
        p, e, repo = artifact(group, artifact_id, version, cache)
        if not p:
            continue
        min_sdk = artifact_min_sdk(p, e)
        if min_sdk is not None and min_sdk > project_min_sdk:
            continue
        cls = classes_in(p, e, tmp)
        if required_classes and not required_classes.issubset(cls):
            continue
        return (group, artifact_id, version), p, e, repo, cls, min_sdk
    return None


def classes_in(p, e, tmp):
    """Class list of an artifact, cached in SQLite keyed by path+size+mtime."""
    if LOOKUP_CACHE is not None and p:
        hit = LOOKUP_CACHE.get_classes(p)
        if hit is not None:
            return hit
    out = _classes_in_uncached(p, e, tmp)
    if LOOKUP_CACHE is not None and p and out:
        LOOKUP_CACHE.put_classes(p, out)
    return out


def _classes_in_uncached(p, e, tmp):
    out = set()
    try:
        if e == "jar":
            with zipfile.ZipFile(p) as z:
                for n in z.namelist():
                    if n.endswith(".class") and not n.startswith("META-INF/versions/"):
                        x = n[:-6].replace("/", ".")
                        out.add(x)
                        out.add(x.split("$", 1)[0])
        else:
            with zipfile.ZipFile(p) as z:
                for n in z.namelist():
                    if n == "classes.jar" or (
                        n.startswith("libs/") and n.endswith(".jar")
                    ):
                        q = tmp / (
                            hashlib.sha1((str(p) + n).encode()).hexdigest() + ".jar"
                        )
                        q.write_bytes(z.read(n))
                        out |= _classes_in_uncached(q, "jar", tmp)
                        q.unlink(missing_ok=True)
    except zipfile.BadZipFile:
        pass
    return out


_GROUP_ARTIFACTS_MEMO = {}
_GOOGLE_CANDIDATES_MEMO = {}


def google_group_artifacts(group):
    if group in _GROUP_ARTIFACTS_MEMO:
        return _GROUP_ARTIFACTS_MEMO[group]
    _GROUP_ARTIFACTS_MEMO[group] = res = _google_group_artifacts(group)
    return res


def _google_group_artifacts(group):
    url = f"{GOOGLE_REPO}/{group.replace('.', '/')}/group-index.xml"
    body = cached_json_url(url, "google-group-index", group)
    if body is None:
        return []
    try:
        return [(ch.tag, [v for v in (ch.attrib.get("versions") or "").split(",") if v])
                for ch in ET.fromstring(body)]
    except Exception as e:
        LOOKUP_FAILURES.append({"time": utcnow(), "kind": "google-group-index",
                                "key": group, "url": url, "error": f"parse: {e}"})
        return []


def google_candidates(fqcn, per_group=8):
    """
    Candidates for a class from Google Maven:
      1. authoritative: Google groups that are a package prefix (master-index.xml);
      2. learned hints whose group is published on Google Maven;
      3. learned hints for other groups: recorded artifacts, no network.
    Stable versions preferred; versions embedded in the APK always win.
    Memoised per package: thousands of androidx classes share a handful of groups.
    """
    key = package_prefix(fqcn)
    if key not in _GOOGLE_CANDIDATES_MEMO:
        _GOOGLE_CANDIDATES_MEMO[key] = _google_candidates(key + ".X", per_group)
    return list(_GOOGLE_CANDIDATES_MEMO[key])


def _google_candidates(fqcn, per_group):
    low = package_prefix(fqcn).lower()
    pkg_tokens = set(re.split(r"[._$]", low))
    google = google_master_groups()
    sources = [(g, 1000, g) for g in google_owner_groups(fqcn)]
    sources += [(g, s, p) for p, g, s in package_map_groups(fqcn)[:8]]
    out, seen_groups, seen = [], set(), set()
    for group, weight, prefix in sources:
        if group in seen_groups:
            continue
        seen_groups.add(group)
        scored = []
        if group in google:
            tail = group.rsplit(".", 1)[-1]
            for a, vs in google_group_artifacts(group):
                if not vs or a.endswith(("-lint", "-samples", "-testing", "-test")):
                    continue
                toks = [x for x in re.split(r"[-_.]", a.lower()) if len(x) > 2]
                lexical = sum(1 for x in toks if x in pkg_tokens or x in low)
                score = weight + lexical * 100 + (60 if a == tail else 0) - (40 if a.endswith("-ktx") else 0)
                if weight >= 1000 or lexical or weight > 1:
                    v = pick_version(vs, group, a)
                    if v:
                        scored.append((score, group, a, v))
        else:
            for a, v in learned_artifacts(prefix, group):
                v = PINNED_VERSIONS.get((group, a), v)
                if v:
                    scored.append((weight, group, a, v))
        scored.sort(reverse=True)
        for item in scored[:per_group]:
            if item[1:] not in seen:
                seen.add(item[1:])
                out.append(item)
    return [(g, a, v) for _, g, a, v in sorted(out, reverse=True)[:30]]


def package_prefix(fqcn):
    """Return package portion of an imported class."""
    return fqcn.rpartition(".")[0]

def common_package_groups(names, min_group=3, max_depth=5):
    """
    Cluster unresolved FQCNs by the deepest useful common package prefix.
    We intentionally avoid collapsing all the way to roots such as com/google/androidx.
    """
    names = sorted(set(names))
    groups = collections.defaultdict(set)
    for fq in names:
        parts = package_prefix(fq).split(".")
        # Candidate prefixes, preferring deeper/more specific packages.
        for depth in range(min(len(parts), max_depth), 1, -1):
            groups[".".join(parts[:depth])].add(fq)

    chosen = []
    consumed = set()
    for prefix, members in sorted(groups.items(),
                                  key=lambda kv: (-len(kv[0].split(".")), -len(kv[1]), kv[0])):
        fresh = members - consumed
        if len(fresh) >= min_group:
            chosen.append((prefix, fresh))
            consumed |= fresh
    return chosen, set(names) - consumed

def central_package(prefix, rows=40):
    """
    Maven Central class-index query using a package wildcard. This is a discovery
    optimization only; candidate artifacts are still verified by indexing their
    actual JAR/AAR classes before selection.
    """
    qexpr = f'fc:"{prefix}.*"'
    qs = urllib.parse.urlencode({"q": qexpr, "rows": rows, "wt": "json"})
    url = CENTRAL_SEARCH + "?" + qs
    detail(f"Maven Central package probe: {prefix}.*", 1)
    detail(url, 2)
    body = cached_json_url(url, "maven-central-package", prefix)
    if body is None:
        return []
    try:
        docs = json.loads(body)["response"]["docs"]
        detail(f"package probe found {len(docs)} candidate records", 1)
        if not docs:
            LOOKUP_MISSES.append({"time": utcnow(), "kind": "maven-central-package",
                                  "key": prefix, "url": url, "cached": url in LOOKUP_CACHE,
                                  "error": "zero search results"})
        return docs
    except Exception as e:
        LOOKUP_FAILURES.append({"time": utcnow(), "kind": "maven-central-package",
                                "key": prefix, "url": url, "error": f"parse: {e}"})
        return []

def _pom_url(repo, gav):
    g, a, v = gav
    return repo + "/" + gavpath(g, a, v, "pom")

def _xml_text(node, tag):
    if node is None:
        return None
    # Maven POMs normally use a default namespace; suffix matching avoids
    # hard-coding its version.
    child = next((x for x in list(node) if x.tag.rsplit("}", 1)[-1] == tag), None)
    return child.text.strip() if child is not None and child.text else None

def _xml_children(node, tag):
    return [x for x in list(node) if x.tag.rsplit("}", 1)[-1] == tag]

def pom_exists(gav):
    """Return (exists, repo, url) for a Maven POM, using the persistent cache."""
    for repo in (CENTRAL_REPO, GOOGLE_REPO):
        url = _pom_url(repo, gav)
        body = cached_json_url(url, "maven-pom", ":".join(gav))
        if body is not None:
            return True, repo, url
    return False, None, None

def validate_pom(gav):
    """
    Reject Maven coordinates whose published metadata is structurally broken.
    In particular this catches artifacts whose POM exists but names a missing
    parent POM, like com.github.javadev:okio:1.2.0.
    """
    coord = MavenCoordinate(*gav)
    for repo in (CENTRAL_REPO, GOOGLE_REPO):
        url = _pom_url(repo, gav)
        body = cached_json_url(url, "maven-pom", ":".join(gav))
        if body is None:
            continue
        try:
            root = ET.fromstring(body)
        except Exception as ex:
            return PomHealth(coord, False, url, repo, score_adjustment=-10000,
                             reason=f"POM XML parse failed: {ex}")

        health = PomHealth(coord, True, url, repo, score_adjustment=25,
                           reason="POM metadata resolves")

        parent = next((x for x in list(root)
                       if x.tag.rsplit("}", 1)[-1] == "parent"), None)
        if parent is not None:
            pg, pa, pv = (_xml_text(parent, x) for x in ("groupId", "artifactId", "version"))
            if pg and pa and pv:
                health.parent = MavenCoordinate(pg, pa, pv)
                ok, _, _ = pom_exists((pg, pa, pv))
                health.parent_ok = ok
                if not ok:
                    health.ok = False
                    health.score_adjustment = -10000
                    health.missing_metadata.append(f"parent {pg}:{pa}:{pv}")
                    health.reason = f"broken POM: parent {pg}:{pa}:{pv} cannot be resolved"
                    return health
                health.score_adjustment += 15

        # Validate imported BOMs from dependencyManagement. Ordinary transitive
        # dependencies are left to Gradle; a missing BOM prevents model resolution.
        for dm in _xml_children(root, "dependencyManagement"):
            deps = next((x for x in list(dm)
                         if x.tag.rsplit("}", 1)[-1] == "dependencies"), None)
            if deps is None:
                continue
            for dep in _xml_children(deps, "dependency"):
                typ = _xml_text(dep, "type")
                scope = _xml_text(dep, "scope")
                if typ == "pom" and scope == "import":
                    bg, ba, bv = (_xml_text(dep, x) for x in ("groupId", "artifactId", "version"))
                    # Property-substituted BOM versions require full Maven model
                    # interpolation, so don't falsely reject them here.
                    if bg and ba and bv and "${" not in (bg + ba + bv):
                        bom = MavenCoordinate(bg, ba, bv)
                        health.imported_boms.append(bom)
                        ok, _, _ = pom_exists(bom.tuple())
                        if not ok:
                            health.ok = False
                            health.score_adjustment = -10000
                            health.missing_metadata.append(f"BOM {bom.notation()}")
                            health.reason = f"broken POM: imported BOM {bom.notation()} cannot be resolved"
                            return health
                        health.score_adjustment += 5
        return health

    return PomHealth(coord, False, score_adjustment=-10000,
                     reason="artifact has no resolvable POM in configured repositories")

def penalize_learned_gav(gav, reason):
    """Teach the persistent package index not to keep proposing broken metadata."""
    changed = 0
    wanted = list(gav)
    for entries in PACKAGE_INDEX.values():
        for ent in entries:
            if ent.get("gav") == wanted:
                ent["failures"] = int(ent.get("failures", 0)) + 1
                ent["last_failure"] = utcnow()
                ent["last_failure_reason"] = reason
                changed += 1
    if changed:
        save_package_index()
    return changed

class MvnRepositoryArtifactParser(HTMLParser):
    """Extract /artifact/<group>/<artifact> links without external dependencies."""
    def __init__(self):
        super().__init__()
        self.links = []
        self._seen = set()

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href", "")
        if not href.startswith("/artifact/"):
            return
        path = urllib.parse.urlsplit(href).path.rstrip("/")
        parts = [urllib.parse.unquote(x) for x in path.split("/") if x]
        # artifact/GROUP/ARTIFACT[/VERSION]
        if len(parts) < 3 or parts[0] != "artifact":
            return
        group, artifact = parts[1], parts[2]
        key = (group, artifact)
        if key not in self._seen:
            self._seen.add(key)
            self.links.append(key)

def mvnrepository_page(path):
    """Cached MVNRepository fetch (discovery only; artifacts are verified)."""
    url = "https://mvnrepository.com/artifact/" + path.strip("/")
    return cached_json_url(url, "mvnrepository", path)

def mvnrepository_candidates(fqcn, max_depth=5, max_candidates=30):
    """
    Walk MVNRepository's group hierarchy beginning with the first two package
    components, then three, etc. Example:
      com.fasterxml.jackson.databind.ObjectMapper
        -> /artifact/com.fasterxml
        -> /artifact/com.fasterxml.jackson
        -> /artifact/com.fasterxml.jackson.databind

    Direct artifact links are returned in page order, which MVNRepository
    normally presents by popularity. Deeper matching subgroup pages are followed.
    """
    pkg = package_prefix(fqcn)
    parts = [x for x in pkg.split(".") if x]
    if len(parts) < 2:
        return []

    candidates = []
    seen = set()
    paths = []
    # Explicitly try 2 parts, then 3, then progressively deeper package prefixes.
    for depth in range(2, min(len(parts), max_depth) + 1):
        paths.append(".".join(parts[:depth]))

    for depth, path in enumerate(paths, start=2):
        body = mvnrepository_page(path)
        if body is None:
            continue
        parser = MvnRepositoryArtifactParser()
        try:
            parser.feed(body.decode("utf-8", errors="replace"))
        except Exception as ex:
            LOOKUP_FAILURES.append({
                "time": utcnow(), "kind": "mvnrepository-parse",
                "key": path, "url": "https://mvnrepository.com/artifact/" + path,
                "error": str(ex)
            })
            continue

        wanted_prefix = ".".join(parts[:min(depth + 1, len(parts))])
        for rank, (group, artifact_name) in enumerate(parser.links):
            # Ignore navigation/self links and unrelated groups. A page may list
            # both subgroups and concrete artifacts.
            if group == path and artifact_name == path.rsplit(".", 1)[-1]:
                continue
            relevance = 0
            if pkg == group or pkg.startswith(group + "."):
                relevance += 4
            if group == path:
                relevance += 3
            if wanted_prefix == group or wanted_prefix.startswith(group + "."):
                relevance += 2
            tokens = set(re.split(r"[._-]+", pkg.lower()))
            if artifact_name.lower() in tokens:
                relevance += 2
            if relevance <= 0:
                continue
            key = (group, artifact_name)
            if key not in seen:
                seen.add(key)
                # rank is page order; keep it as a weak popularity/relevance hint.
                candidates.append((rank, relevance, group, artifact_name))

    candidates.sort(key=lambda x: (-x[1], x[0]))
    return candidates[:max_candidates]

def central_latest_version(group, artifact_name):
    """Resolve a group/artifact discovered on MVNRepository to a Central version."""
    qs = urllib.parse.urlencode({
        "q": f'g:"{group}" AND a:"{artifact_name}"',
        "rows": 1, "wt": "json"
    })
    url = CENTRAL_SEARCH + "?" + qs
    body = cached_json_url(url, "maven-central-ga",
                           f"{group}:{artifact_name}")
    if body is None:
        return None
    try:
        docs = json.loads(body)["response"]["docs"]
        if not docs:
            return None
        return docs[0].get("latestVersion") or docs[0].get("v")
    except Exception as ex:
        LOOKUP_FAILURES.append({
            "time": utcnow(), "kind": "maven-central-ga",
            "key": f"{group}:{artifact_name}", "url": url,
            "error": f"parse: {ex}"
        })
        return None

# JADX --deobf synthesizes aliases such as p106y.C1359e or
# p081r0.AbstractC1193b. Those names do not exist in the original Maven
# artifact, so class-index/Maven searches for them can never succeed.
_JADX_ALIAS_PACKAGE_RE = re.compile(r"^p\d{3,}[A-Za-z0-9_$]*$")
_JADX_ALIAS_CLASS_RE = re.compile(
    r"^(?:(?:[A-Z][a-z]+)*C)\d{3,}[A-Za-z0-9_$]*(?:\$.*)?$"
)

def looks_like_jadx_alias(fqcn):
    """Return True for the synthetic names JADX commonly emits with --deobf.

    We use this only for *bundled-class discovery*. Explicit unresolved imports
    are still allowed through, so this optimization cannot hide a real missing
    dependency merely because it has an unusual class name.
    """
    parts = str(fqcn).split(".")
    if not parts:
        return False
    cls = parts[-1]
    pkgs = parts[:-1]
    class_alias = bool(_JADX_ALIAS_CLASS_RE.match(cls))
    package_alias = any(_JADX_ALIAS_PACKAGE_RE.match(seg) for seg in pkgs)
    return class_alias and package_alias


def resolve(imports, classes, packages, cache, tmp, max_rounds, max_queries, app_package=None,
            include_jadx_aliases=False, project_min_sdk=None, allow_min_sdk_bump=False,
            package_only_lookups=False):
    # There are two kinds of dependency evidence:
    #   1) imports that are not present in the decompiled APK source; and
    #   2) classes that ARE present because the APK bundled a third-party library.
    #
    # The old resolver only handled (1). Worse, local() intentionally treats
    # every decompiled class/package as local, so bundled Gson/Protobuf/ASM/etc.
    # could never become Maven candidates and therefore could never be pruned.
    unresolved_imports = {x for x in imports if not local(x, classes, packages)}

    app_package = (app_package or "").strip(".")
    bundled_candidates = set()
    if app_package:
        # Anything outside the application's own namespace is eligible for
        # artifact discovery. Selection still requires the downloaded JAR/AAR
        # to contain the exact class, so this does not blindly prune it.
        outside_app = {
            c for c in classes
            if not (c == app_package or c.startswith(app_package + "."))
            and not c.startswith(PLATFORM)
        }
        if include_jadx_aliases:
            bundled_candidates = outside_app
            skipped_jadx_aliases = set()
        else:
            skipped_jadx_aliases = {c for c in outside_app if looks_like_jadx_alias(c)}
            bundled_candidates = outside_app - skipped_jadx_aliases
            if skipped_jadx_aliases:
                log(
                    f"Skipping {len(skipped_jadx_aliases)} obvious JADX-renamed bundled classes "
                    "from Maven lookup (use --query-jadx-aliases to include them)"
                )
                if VERBOSE >= 2:
                    for c in sorted(skipped_jadx_aliases)[:100]:
                        detail("JADX alias skipped: " + c, 2)
                    if len(skipped_jadx_aliases) > 100:
                        detail(f"... and {len(skipped_jadx_aliases) - 100} more", 2)

    missing = unresolved_imports | bundled_candidates
    # Give bundled classes a small query/scoring weight without pretending
    # they were imports.
    resolve_weights = collections.Counter(imports)
    for c in bundled_candidates:
        resolve_weights[c] = max(1, resolve_weights.get(c, 0))
    original = set(missing)
    provided = set()
    selected = []
    coords = set()
    queries = 0
    cc = {}
    log("Dependency analysis")
    detail(f"unique imports: {len(imports)}")
    detail(f"local/APK classes: {len(classes)}")
    detail(f"unresolved imports: {len(unresolved_imports)}")
    log(f"Bundled-library discovery: {len(bundled_candidates)} decompiled classes outside app namespace {app_package or '(unknown)'}")
    detail(f"total dependency candidates: {len(missing)}")
    for rnd in range(max_rounds):
        started = time.time()
        missing = {x for x in missing if x not in provided}
        if not missing:
            break
        log(
            f"Dependency round {rnd + 1}/{max_rounds} — {len(missing)} unresolved imports"
        )
        pool = set()
        candidate_rank = {}
        candidate_learned = {}
        ordered = sorted(missing, key=lambda x: -resolve_weights[x])

        # Zero-network fast path from mappings learned on earlier APKs.
        indexed_classes, index_gavs = set(), set()
        for fq in ordered:
            for prefix, gav, ent in package_index_candidates(fq):
                indexed_classes.add(fq)
                index_gavs.add(gav)
                candidate_learned[gav] = ent
                detail(f"PACKAGE INDEX {fq} -> {':'.join(gav)} via {prefix}", 1)
        if index_gavs:
            log(f"Package index supplied {len(index_gavs)} artifacts for {len(indexed_classes)} imports without URL searches")
            pool.update(index_gavs)

        # Exact class index built from every artifact inspected on earlier runs.
        class_index_hits = 0
        if LOOKUP_CACHE is not None:
            for fq in ordered:
                if fq in indexed_classes:
                    continue
                owners = LOOKUP_CACHE.owners_of(fq)
                if owners:
                    pool.update(owners)
                    indexed_classes.add(fq)
                    class_index_hits += 1
        if class_index_hits:
            log(f"Local class index resolved candidates for {class_index_hits} classes without network")

        # Versions the APK itself declares (META-INF/*.version etc.).
        if rnd == 0 and PINNED_VERSIONS:
            pool.update((g, a, v) for (g, a), v in PINNED_VERSIONS.items())
            log(f"Seeded {len(PINNED_VERSIONS)} coordinates embedded in the APK")

        # Google-owned namespaces (androidx.*, com.google.android.material.*, gms,
        # firebase...) resolve deterministically from master-index.xml + group
        # indexes; no Maven Central search needed.
        google_owned = set()
        for fq in ordered:
            if fq in indexed_classes or not google_owner_groups(fq):
                continue
            gc = google_candidates(fq)
            if gc:
                pool.update(gc)
                google_owned.add(fq)
        if google_owned:
            log(f"Google Maven ownership supplied candidates for {len(google_owned)} classes")
        indexed_classes |= google_owned

        # First collapse related imports into common package probes. A package
        # lookup can discover one artifact for many classes. We still verify
        # candidates against exact classes contained in the downloaded JAR/AAR.
        network_ordered = [fq for fq in ordered if fq not in indexed_classes]
        grouped, ungrouped = common_package_groups(
            network_ordered,
            min_group=2 if package_only_lookups else 3,
        )
        package_covered = set()
        if grouped:
            log(f"Condensed {sum(len(m) for _, m in grouped)} imports into {len(grouped)} package probes")
        for pi, (prefix, members) in enumerate(grouped, 1):
            if queries >= max_queries:
                break
            detail(f"[pkg {pi:03}/{len(grouped):03}] {prefix}.* ({len(members)} unresolved classes)", 1)
            docs = central_package(prefix)
            queries += 1
            gavs = set()
            for rank, d in enumerate(docs):
                if d.get("g") and d.get("a") and (d.get("v") or d.get("latestVersion")):
                    gav = (d.get("g"), d.get("a"), d.get("v") or d.get("latestVersion"))
                    gavs.add(gav)
                    candidate_rank[gav] = min(rank, candidate_rank.get(gav, rank))
            if gavs:
                pool.update(gavs)
                package_covered |= members
                detail(f"package probe yielded {len(gavs)} coordinates; suppressing {len(members)} class probes this round", 1)
            else:
                detail("package probe empty; falling back to individual classes", 1)

        # Only query individual classes not represented by a successful package
        # discovery. Verification below prevents a broad package hit from being
        # accepted unless the artifact really contains unresolved classes.
        if package_only_lookups:
            if network_ordered:
                log(
                    f"--package-only-lookups: skipping individual class probes for "
                    f"{len(network_ordered) - len(package_covered)} class(es)"
                )
            class_ordered = []
        else:
            class_ordered = [fq for fq in network_ordered if fq not in package_covered]
        for idx, fq in enumerate(class_ordered, 1):
            if queries >= max_queries:
                warn(f"query limit reached ({max_queries})")
                break
            if fq not in cc:
                detail(f"[{idx:03}/{len(class_ordered):03}] {fq} (weight {resolve_weights[fq]}x)", 1)
                docs = central_class(fq)
                queries += 1
                cc[fq] = [
                    (d.get("g"), d.get("a"), d.get("v") or d.get("latestVersion"))
                    for d in docs
                    if d.get("g")
                    and d.get("a")
                    and (d.get("v") or d.get("latestVersion"))
                ]
                if not cc[fq]:
                    detail(
                        "no Central exact-class hits; trying Google Maven heuristic", 1
                    )
                    cc[fq] = google_candidates(fq)

                # Complement class-index discovery with MVNRepository's package/group
                # hierarchy. This is especially useful for bundled libraries such as
                # com.fasterxml.jackson.*, where package-prefix browsing exposes the
                # canonical group/artifact family.
                mvnr = mvnrepository_candidates(fq)
                if mvnr:
                    detail(f"MVNRepository hierarchy yielded {len(mvnr)} GA candidates", 1)
                existing_ga = {(g, a) for g, a, _ in cc[fq]}
                for mvn_rank, relevance, g, a in mvnr:
                    if queries >= max_queries:
                        break
                    if (g, a) in existing_ga:
                        continue
                    v = central_latest_version(g, a)
                    queries += 1
                    if v:
                        gav = (g, a, v)
                        cc[fq].append(gav)
                        existing_ga.add((g, a))
                        # Keep MVNRepository page order as a weak rank signal. The
                        # downloaded artifact must still contain the exact class.
                        candidate_rank[gav] = min(
                            candidate_rank.get(gav, 10_000),
                            100 + mvn_rank
                        )
                        detail(
                            f"MVNRepository candidate {g}:{a}:{v} "
                            f"(page-rank={mvn_rank}, relevance={relevance})", 2
                        )

                detail(f"candidate coordinates: {len(cc[fq])}", 1)
                if VERBOSE >= 2:
                    for gav in cc[fq][:12]:
                        detail("candidate " + ":".join(gav), 2)
                time.sleep(0.03)
            pool.update(cc[fq])
        pool = {pin(g) for g in pool}
        detail(f"round candidate pool: {len(pool)} artifacts", 1)
        inspect = sorted(pool, key=lambda g: (candidate_rank.get(g, 5000), g))[:1200]
        prefetch_artifacts(inspect, cache)
        viable = []
        for ci, gav in enumerate(inspect, 1):
            g, a, v = gav
            detail(f"inspect [{ci}/{min(len(pool),1200)}] {g}:{a}:{v}", 2)
            p, e, repo = artifact(g, a, v, cache)
            if not p:
                continue
            cls = classes_in(p, e, tmp)
            hits = missing & cls
            if not hits:
                continue

            lib_min_sdk = artifact_min_sdk(p, e)
            if (project_min_sdk and lib_min_sdk is not None
                    and lib_min_sdk > project_min_sdk and not allow_min_sdk_bump):
                log(
                    f"Candidate {g}:{a}:{v} requires minSdk {lib_min_sdk}; "
                    f"APK requires {project_min_sdk}. Searching compatible versions..."
                )
                replacement = find_compatible_artifact_version(
                    g, a, v, cache, int(project_min_sdk), tmp, required_classes=hits
                )
                if replacement is None:
                    warn(
                        f"Rejecting {g}:{a}:{v}: minSdk {lib_min_sdk} > "
                        f"APK minSdk {project_min_sdk}, and no compatible version retained "
                        f"the required classes"
                    )
                    DEPENDENCY_COMPAT_AUDIT.append({
                        "action": "rejected-minsdk-incompatible-candidate",
                        "coordinate": f"{g}:{a}:{v}",
                        "library_min_sdk": lib_min_sdk,
                        "project_min_sdk": project_min_sdk,
                        "required_classes": sorted(hits),
                    })
                    continue
                old_gav = gav
                gav, p, e, repo, cls, lib_min_sdk = replacement
                g, a, v = gav
                hits = missing & cls
                log(
                    f"Using minSdk-compatible {g}:{a}:{v} "
                    f"(library minSdk {lib_min_sdk if lib_min_sdk is not None else 'unspecified'})"
                )
                DEPENDENCY_COMPAT_AUDIT.append({
                    "action": "downgraded-for-minsdk-compatibility",
                    "from": ":".join(old_gav),
                    "to": ":".join(gav),
                    "library_min_sdk": lib_min_sdk,
                    "project_min_sdk": project_min_sdk,
                    "required_classes": sorted(hits),
                })

            # Shaded/fat-jar detection: classes outside this group's namespace
            # never count as coverage, are never learned and never drive pruning.
            native_cls, foreign_cls, purity = artifact_profile(gav, cls)
            foreign_hits = hits & foreign_cls
            hits = hits & native_cls
            if LOOKUP_CACHE is not None:
                LOOKUP_CACHE.index_artifact(gav, native_cls)
            if not hits:
                if foreign_hits:
                    SHADED_REJECTIONS.append({"coordinate": ":".join(gav), "purity": round(purity, 3),
                                              "shaded_hits": len(foreign_hits),
                                              "examples": sorted(foreign_hits)[:10]})
                    detail(f"SHADED {':'.join(gav)}: {len(foreign_hits)} hits are bundled copies "
                           f"of other libraries; ignoring", 1)
                continue

            pom = validate_pom(gav)
            if not pom.ok:
                warn(f"Rejecting {':'.join(gav)}: {pom.reason}")
                penalize_learned_gav(gav, pom.reason)
                continue
            ev = score_candidate(gav, native_cls, missing, resolve_weights,
                                 candidate_rank.get(gav), candidate_learned.get(gav))
            ev.total_score += pom.score_adjustment
            if any(gav[0] in google_owner_groups(x) for x in list(hits)[:20]):
                ev.total_score += 200          # canonical Google owner
            if (gav[0], gav[1]) in PINNED_VERSIONS:
                ev.total_score += 150          # the APK says it shipped this
            if purity < 0.5:
                ev.total_score -= 2000         # mostly someone else's classes
            elif purity < 0.95:
                ev.total_score -= 400 * (1 - purity)
            cls = native_cls
            # Imperfect matches are intentional: two real class hits are enough;
            # a single hit is enough when it is actually imported or structurally related.
            similarity = max((package_similarity(x, gav) for x in hits), default=0.0)
            if len(hits) >= 2 or similarity >= .15 or any(x in imports for x in hits):
                viable.append((ev.total_score, gav, p, e, cls, hits, pom, purity, len(foreign_cls)))
                detail(f"VIABLE {':'.join(gav)} hits={len(hits)} score={ev.total_score:.1f}",1)

        if not viable:
            warn(f"No viable artifact covers remaining {len(missing)} candidates; stopping")
            break

        # Greedy set-cover: keep MANY useful artifacts, not just the single winner.
        viable.sort(key=lambda x:(len(x[5]),x[0]), reverse=True)
        newly_covered=set()
        picked=0
        for score,gav,p,e,cls,hits,pom,purity,n_foreign in viable:
            useful=hits-newly_covered
            if not useful:
                continue
            # Permit overlap; reject only nearly-total duplication after the first pick.
            if picked and len(useful)/max(1,len(hits)) < .08:
                continue
            log(f"Selecting {':'.join(gav)} ({e}) — {len(useful)} new / {len(hits)} matching classes")
            coords.add(gav)
            provided |= cls
            newly_covered |= useful
            selected.append({
                "gav":gav, "file":str(p), "type":e, "classes":cls,
                "covers":sorted(useful), "all_hits":sorted(hits),
                "min_sdk": artifact_min_sdk(p, e),
                "purity": round(purity, 4), "foreign_class_count": n_foreign,
                "pom_health":{"ok":pom.ok,"url":pom.pom_url,"repository":pom.repository,
                              "reason":pom.reason}
            })
            if n_foreign:
                warn(f"{':'.join(gav)} also bundles {n_foreign} classes from other libraries' "
                     f"namespaces (purity {purity:.0%}); watch for Gradle 'Duplicate class' errors")
            picked += 1
        if not picked:
            warn("All viable candidates were redundant; stopping")
            break

        left = len(original - provided)
        log(
            f"Round {rnd + 1} complete: selected {picked} artifacts, resolved {len(newly_covered)}, remaining {left}, queries {queries}, elapsed {time.time() - started:.1f}s"
        )
    return original, provided, selected, coords, queries


def write_gradle(root, info, coords):
    ns = (
        info["package"]
        if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", info["package"])
        else "reconstructed.apk"
    )
    min_sdk = int(info.get("min_sdk") or 21)
    target_sdk = int(info.get("target_sdk") or 35)
    compile_sdk = max(35, target_sdk, int(info.get("compile_sdk") or 0))

    (root / "settings.gradle").write_text(
        'pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }\n'
        'dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories { google(); mavenCentral() } }\n'
        'rootProject.name="reconstructed"\ninclude(":app")\n'
    )
    (root / "build.gradle").write_text(
        'plugins { id "com.android.application" version "8.10.1" apply false }\n'
    )
    (root / "gradle.properties").write_text(
        "org.gradle.jvmargs=-Xmx4g -Dfile.encoding=UTF-8\n"
        "android.useAndroidX=true\n"
        "android.nonTransitiveRClass=false\n"
        "android.nonFinalResIds=false\n"
    )
    deps = "\n".join(f'  implementation "{g}:{a}:{v}"' for g, a, v in sorted(coords))
    packaging = ""
    if info.get("extract_native_libs") is not None:
        legacy = "true" if info["extract_native_libs"] else "false"
        packaging = f"  packaging {{ jniLibs {{ useLegacyPackaging = {legacy} }} }}\n"

    (root / "app/build.gradle").write_text(f'''plugins {{ id "com.android.application" }}
android {{
  namespace "{ns}"
  compileSdk {compile_sdk}
  defaultConfig {{ applicationId "{ns}"; minSdk {min_sdk}; targetSdk {target_sdk} }}
{packaging}}}
dependencies {{
{deps}
}}

// apk2project helper: expose the complete resolved runtime AAR set, including
// transitive dependencies that were not directly selected by the Python resolver.
tasks.register("apk2projectResolvedAars") {{
  doLast {{
    configurations.debugRuntimeClasspath.resolvedConfiguration.resolvedArtifacts
      .findAll {{ it.file.name.toLowerCase().endsWith(".aar") }}
      .sort {{ a, b -> a.moduleVersion.id.toString() <=> b.moduleVersion.id.toString() }}
      .each {{ a ->
        println("APK2PROJECT_AAR\t${{a.moduleVersion.id.group}}\t${{a.name}}\t${{a.moduleVersion.id.version}}\t${{a.file.absolutePath}}")
      }}
  }}
}}
''')


def _gradle_command_for_project(root, *args):
    """Return the best Gradle command for a generated project."""
    root = Path(root)
    wrapper = root / "build-termux.sh"
    if wrapper.exists() and os.access(wrapper, os.X_OK):
        return [wrapper, *args]
    gradle = shutil.which("gradle")
    if gradle:
        return [gradle, "--no-daemon", *args]
    return None


def resolve_gradle_runtime_aars(root, analysis_dir):
    """
    Resolve the actual debugRuntimeClasspath AARs, including transitive
    dependencies that the Python dependency resolver did not select directly.
    """
    root = Path(root)
    analysis_dir = Path(analysis_dir)
    cmd = _gradle_command_for_project(root, "-q", ":app:apk2projectResolvedAars")
    if cmd is None:
        detail("Gradle unavailable; skipping transitive AAR inventory", 1)
        return []

    log("Resolving complete Gradle runtime AAR graph for resource reconciliation")
    proc = run(cmd, cwd=root, check=False, capture=True)
    raw = proc.stdout or ""
    records = []
    seen = set()
    for line in raw.splitlines():
        if not line.startswith("APK2PROJECT_AAR\t"):
            continue
        parts = line.split("\t", 4)
        if len(parts) != 5:
            continue
        _, group, artifact, version, file_name = parts
        path = Path(file_name)
        key = (group, artifact, version, str(path))
        if key in seen or not path.is_file():
            continue
        seen.add(key)
        records.append({
            "gav": (group, artifact, version),
            "file": str(path),
            "type": "aar",
            "transitive": True,
        })

    analysis_dir.mkdir(parents=True, exist_ok=True)
    (analysis_dir / "gradle-runtime-aars.log").write_text(raw)
    (analysis_dir / "gradle-runtime-aars.json").write_text(
        json.dumps([
            {"gav": ":".join(r["gav"]), "file": r["file"]}
            for r in records
        ], indent=2, sort_keys=True)
    )
    if proc.returncode:
        warn(
            f"Gradle runtime-AAR inventory exited {proc.returncode}; "
            "continuing with directly selected AARs"
        )
    else:
        log(f"Gradle runtime graph contains {len(records)} AAR artifact(s)")
    return records



def parse_gradle_runtime_artifacts(text):
    """Parse APK2PROJECT_ARTIFACT records emitted by the generated Gradle task."""
    records = []
    seen = set()
    for line in (text or "").splitlines():
        if not line.startswith("APK2PROJECT_ARTIFACT\t"):
            continue
        parts = line.split("\t", 5)
        if len(parts) != 6:
            continue
        _, group, artifact, version, typ, file_name = parts
        typ = typ.lower().strip()
        if typ not in {"jar", "aar"}:
            continue
        path = Path(file_name)
        key = (group, artifact, version, typ, str(path))
        if key in seen or not path.is_file():
            continue
        seen.add(key)
        records.append({
            "gav": (group, artifact, version),
            "file": str(path),
            "type": typ,
            "transitive": True,
        })
    return records


def resolve_gradle_runtime_artifacts(root, analysis_dir):
    """Resolve every JAR/AAR on debugRuntimeClasspath, not just AARs.

    v24's AAR-only inventory was sufficient for resource reconciliation but not
    for reconstructing the original source/dependency boundary. Pure JAR
    dependencies (Guava is a common example) could therefore remain in the JADX
    source tree and fail javac even though Gradle already had their binary artifact.
    """
    root = Path(root)
    analysis_dir = Path(analysis_dir)
    cmd = _gradle_command_for_project(root, "-q", ":app:apk2projectResolvedArtifacts")
    if cmd is None:
        detail("Gradle unavailable; skipping complete runtime artifact inventory", 1)
        return []
    log("Resolving complete Gradle runtime JAR/AAR graph for binary-island ownership")
    proc = run(cmd, cwd=root, check=False, capture=True)
    raw = proc.stdout or ""
    records = parse_gradle_runtime_artifacts(raw)
    analysis_dir.mkdir(parents=True, exist_ok=True)
    (analysis_dir / "gradle-runtime-artifacts.log").write_text(raw)
    (analysis_dir / "gradle-runtime-artifacts.json").write_text(json.dumps([
        {"gav": ":".join(r["gav"]), "type": r["type"], "file": r["file"]}
        for r in records
    ], indent=2, sort_keys=True))
    if proc.returncode:
        warn(f"Gradle runtime-artifact inventory exited {proc.returncode}; using partial results ({len(records)})")
    else:
        jars = sum(1 for r in records if r["type"] == "jar")
        aars = sum(1 for r in records if r["type"] == "aar")
        log(f"Gradle runtime graph contains {jars} JAR(s) + {aars} AAR(s)")
    return records

def reconcile_all_gradle_aar_attrs(root, res_root, analysis_dir, selected):
    """
    Reconcile decoded attrs against direct and transitive Gradle AARs.

    This catches attrs originally supplied by a transitive library. Restoring a
    direct dependency makes Gradle restore that AAR too, so the decoded copy in
    the APK would otherwise collide only at mergeDebugResources time.
    """
    runtime_aars = resolve_gradle_runtime_aars(root, analysis_dir)
    combined = []
    seen = set()
    for entry in list(selected) + runtime_aars:
        key = (tuple(entry.get("gav", ())), entry.get("file"), entry.get("type"))
        if key in seen:
            continue
        seen.add(key)
        combined.append(entry)

    audit = reconcile_selected_aar_attrs(res_root, analysis_dir, combined)
    if runtime_aars:
        normalize_value_resources(res_root, analysis_dir)
    return runtime_aars, audit



def normalize_binary_class(name):
    """Map binary/JAR inner classes to the outer Java source class."""
    return name.split("$", 1)[0]

def package_of(name):
    return name.rpartition(".")[0]

def source_basename(name):
    return name.rpartition(".")[2].split("$", 1)[0]

def dex_classes_from_smali(root):
    """
    Recover original DEX class descriptors from apktool smali output.
    This is intentionally text-based: apktool has already decoded DEX for us,
    so no extra dex parser/tool is required.
    """
    found = set()
    orig = root / "original"
    if not orig.exists():
        return found
    rx = re.compile(r"^\.class\b.*\sL([^;]+);", re.M)
    for smali_dir in [p for p in orig.iterdir() if p.is_dir() and
                      (p.name == "smali" or p.name.startswith("smali_classes"))]:
        for p in smali_dir.rglob("*.smali"):
            try:
                text = p.read_text(errors="ignore")
            except OSError:
                continue
            m = rx.search(text)
            if m:
                found.add(m.group(1).replace("/", "."))
    return found


def _source_has_apk_specific_jadx_members(path):
    """True when decompiled source exposes JADX aliases for R8/minified members.

    A Maven artifact may provide the same public class FQCN but *not* the exact
    private/package member names present in the APK after R8. Pruning such a class
    creates hundreds of `cannot find symbol m814I/f1103t0` errors in callers.
    """
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return False
    # Require several declarations/usages to avoid retaining a class because of one
    # coincidental identifier. Typical JADX aliases are m814I, f1103t0, m867y, etc.
    hits = set(re.findall(r"\b(?:m|f)\d+[A-Za-z_$][\w$]*\b", text))
    return len(hits) >= 2

def prune(root, source_files, selected, mode, aggressive):
    """Every Java source represented in ANY selected JAR/AAR is pruned."""
    java_root=root/"app/src/main/java"
    dex_outer={normalize_binary_class(c) for c in dex_classes_from_smali(root)}
    source_names=set(source_files)
    union=set()
    owners=collections.defaultdict(set)
    for sel in selected:
        gav=":".join(sel["gav"])
        for c in sel.get("classes",()):
            c=normalize_binary_class(c)
            union.add(c); owners[c].add(gav)

    decisions={}
    retained_apk_specific=[]
    for c in sorted(source_names & union):
        fp=source_files.get(c)
        if c in dex_outer and fp and _source_has_apk_specific_jadx_members(fp):
            retained_apk_specific.append(c)
            continue
        decisions[c]=asdict(PruneEvidence(
            artifact=" | ".join(sorted(owners[c])), confidence="certain",
            reason="source class is physically contained in a selected JAR/AAR"
                   + ("; DEX-confirmed" if c in dex_outer else ""),
            matched_by="selected-library-union"))

    if aggressive:
        # Also catch scanner/decompiler filename oddities and residual helper files.
        libpkg=collections.defaultdict(set)
        pkgowner=collections.defaultdict(collections.Counter)
        for c,gavs in owners.items():
            libpkg[package_of(c)].add(source_basename(c))
            for g in gavs: pkgowner[package_of(c)][g]+=1
        srcpkg=collections.defaultdict(list)
        for c in source_names: srcpkg[package_of(c)].append(c)
        for pkg,members in srcpkg.items():
            names=libpkg.get(pkg,set())
            if not names: continue
            hits={source_basename(c) for c in members}&names
            ratio=len(hits)/max(1,len(members))
            gav=pkgowner[pkg].most_common(1)[0][0]
            for c in members:
                if c in retained_apk_specific:
                    continue
                if source_basename(c) in names:
                    decisions.setdefault(c,asdict(PruneEvidence(
                        artifact=gav,confidence="certain",
                        reason="package+basename exists in selected library",
                        matched_by="library-package-basename",package_ratio=ratio)))
            if len(hits)>=3 and ratio>=.60:
                for c in members:
                    if c in retained_apk_specific:
                        continue
                    decisions.setdefault(c,asdict(PruneEvidence(
                        artifact=gav,confidence="aggressive",
                        reason=f"library-owned package: {len(hits)}/{len(members)} source names occur in selected jars",
                        matched_by="library-owned-package",package_ratio=ratio)))

    diagnostics=[f"selected_artifacts={len(selected)} union_classes={len(union)} source_classes={len(source_names)} prune_decisions={len(decisions)} retained_apk_specific={len(retained_apk_specific)}"]
    for c in retained_apk_specific[:200]:
        diagnostics.append(f"RETAIN {c}: DEX-confirmed source has multiple JADX/R8 member aliases; Maven class may not expose APK-private names")
    for sel in selected:
        gav=":".join(sel["gav"]); outer={normalize_binary_class(c) for c in sel.get("classes",())}
        diagnostics.append(f"{gav}: jar_classes={len(sel.get('classes',()))} source_matches={len(source_names&outer)}")
    dest=root/"removed-library-sources"; moved=[]; deleted=[]
    for c,d in sorted(decisions.items()):
        fp=source_files.get(c)
        if not fp or not fp.exists(): continue
        if mode=="delete":
            fp.unlink(); deleted.append(c)
        elif mode=="move":
            q=dest/fp.relative_to(java_root); q.parent.mkdir(parents=True,exist_ok=True)
            if q.exists(): q.unlink()
            __import__("shutil").move(str(fp),str(q)); moved.append(c)
    for d in sorted(java_root.rglob("*"),reverse=True):
        if d.is_dir():
            try:d.rmdir()
            except OSError:pass
    return decisions,moved,deleted,diagnostics



def termux_prefix():
    return Path(os.environ.get("PREFIX", "/data/data/com.termux/files/usr"))

def find_android_sdk():
    candidates = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(env):
            candidates.append(Path(os.environ[env]).expanduser())
    pref = termux_prefix()
    candidates += [
        pref / "opt/android-sdk",
        Path.home() / "android-sdk",
        Path.home() / "Android/Sdk",
    ]
    for p in candidates:
        if p.exists() and (p / "platforms").exists():
            return p.resolve()
    return None


# ---------------------------------------------------------------------------
# apktool framework-res discovery
# ---------------------------------------------------------------------------
APKTOOL_FRAMEWORK_DIRS = tuple(
    p for p in (
        Path(os.environ.get("APKTOOL_FRAMEWORK_DIR", "")) if os.environ.get("APKTOOL_FRAMEWORK_DIR") else None,
        Path.home() / ".apktool-frameworks",
        Path.home() / ".local/share/apktool/framework",
        termux_prefix() / "share/apktool/framework",
    ) if p is not None
)
_EXTRA_FRAMEWORK_DIRS: list[Path] = []


def register_apktool_framework_dir(path):
    """Called when --apktool-framework-dir is supplied."""
    if not path:
        return
    p = Path(path).expanduser()
    if p not in _EXTRA_FRAMEWORK_DIRS:
        _EXTRA_FRAMEWORK_DIRS.insert(0, p)


def _framework_search_dirs():
    return tuple(_EXTRA_FRAMEWORK_DIRS) + APKTOOL_FRAMEWORK_DIRS


def find_apktool_framework(api: int) -> Path | None:
    """
    Locate the apktool-installed framework-res APK for an API level.

    Accepted layouts under each search dir:
        <dir>/<api>/1.apk
        <dir>/<api>/<anything>.apk
        <dir>/<api>-<anything>/<anything>.apk
        <dir>/framework-<api>.apk
        <dir>/<api>.apk
    """
    try:
        api_int = int(api)
    except (TypeError, ValueError):
        return None

    for base in _framework_search_dirs():
        if not base or not base.exists():
            continue

        exact_dir = base / str(api_int)
        if exact_dir.is_dir():
            for cand in sorted(exact_dir.glob("*.apk")):
                if zipfile.is_zipfile(cand):
                    return cand

        direct = base / f"{api_int}.apk"
        if direct.is_file() and zipfile.is_zipfile(direct):
            return direct

        for d in sorted(base.iterdir()):
            name = d.name
            if not name:
                continue
            if d.is_dir() and re.match(rf"^(android-)?{api_int}(?:[-_].+)?$", name):
                for cand in sorted(d.glob("*.apk")):
                    if zipfile.is_zipfile(cand):
                        return cand
            elif d.is_file() and d.suffix == ".apk" and re.match(
                rf"^framework-{api_int}(?:[-_].+)?\.apk$", name
            ):
                if zipfile.is_zipfile(d):
                    return d
    return None


def apktool_framework_as_aapt2_link_include(api: int) -> list[str]:
    """
    Return ["-I", "<framework-res.apk>"] suitable for `aapt2 link`.
    NOT usable with `aapt2 compile` — compile does not accept -I at all.
    """
    fw = find_apktool_framework(api)
    if fw and zipfile.is_zipfile(fw):
        log(f"Using apktool framework-res for API {api}: {fw}")
        return ["-I", str(fw)]
    return []


# Backwards-compat alias for anything still calling the old name.
apktool_framework_as_aapt2_include = apktool_framework_as_aapt2_link_include

def termux_pkg_install(pkgs):
    pkg = shutil.which("pkg")
    if not pkg:
        die("--install-sdk currently bootstraps packages through Termux 'pkg'")
    log("Installing Termux build prerequisites: " + " ".join(pkgs))
    run([pkg, "install", "-y"] + pkgs)

def bootstrap_android_sdk(compile_sdk=35):
    """Best-effort native Termux Android SDK/toolchain bootstrap."""
    sdk = find_android_sdk()
    if sdk and (sdk / "platforms" / f"android-{compile_sdk}" / "android.jar").exists():
        log(f"Android SDK already usable: {sdk}")
        return sdk

    # Package names vary somewhat between Termux repositories; install the
    # core packages individually so an optional package failure is diagnosable.
    required = ["openjdk-21", "gradle", "aapt2"]
    optional = ["aapt", "aidl", "apksigner", "d8", "zipalign"]
    for p in required:
        if not shutil.which(p.replace("openjdk-21", "java").replace("gradle", "gradle")):
            try:
                termux_pkg_install([p])
            except subprocess.CalledProcessError:
                warn(f"Could not install required package {p}")
    for p in optional:
        if not shutil.which(p):
            try:
                termux_pkg_install([p])
            except subprocess.CalledProcessError:
                detail(f"Optional Termux package unavailable: {p}", 1)

    sdk = find_android_sdk()
    if sdk and (sdk / "platforms" / f"android-{compile_sdk}" / "android.jar").exists():
        return sdk

    # Search Termux prefix for a packaged android.jar and construct a minimal
    # SDK layout around it if necessary.
    pref = termux_prefix()
    jars = list(pref.glob("**/android.jar"))
    if not jars:
        die(f"Android API {compile_sdk} platform not found after bootstrap; no android.jar under {pref}")

    # Prefer a path mentioning the requested API, otherwise newest-looking jar.
    jars.sort(key=lambda p: (str(compile_sdk) in str(p), str(p)), reverse=True)
    android_jar = jars[0]
    sdk = pref / "opt/android-sdk"
    platform = sdk / "platforms" / f"android-{compile_sdk}"
    platform.mkdir(parents=True, exist_ok=True)
    target = platform / "android.jar"
    if not target.exists():
        try:
            target.symlink_to(android_jar)
        except OSError:
            shutil.copy2(android_jar, target)
    log(f"Constructed SDK platform {platform} from {android_jar}")
    return sdk

def _valid_android_jar(path):
    """Return True only for a readable ZIP/JAR that AAPT2 can plausibly use."""
    path = Path(path)
    try:
        return path.is_file() and path.stat().st_size > 1024 and zipfile.is_zipfile(path)
    except OSError:
        return False


def _find_best_android_jar(sdk, api):
    """Find a valid android.jar for *api*, tolerating Termux suffixed platform dirs."""
    sdk = Path(sdk)
    pref = termux_prefix()
    candidates = []

    # Prefer the requested SDK first, including odd Termux names such as
    # android-36-2, then fall back to any packaged framework jar under PREFIX.
    for base in (sdk / "platforms", pref):
        if not base.exists():
            continue
        if base == sdk / "platforms":
            paths = list(base.glob(f"android-{api}*/android.jar"))
        else:
            paths = [q for q in base.glob("**/android.jar") if str(api) in str(q.parent)]
        for q in paths:
            if _valid_android_jar(q):
                exact = q.parent.name == f"android-{api}"
                # Exact API/name first, then larger jars, then stable path ordering.
                candidates.append((1 if exact else 0, q.stat().st_size, str(q), q))

    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][3]


def _platform_candidate_score(path, api):
    """Score a Termux SDK platform directory by *usability*, not just its name.

    Termux can leave a canonical-looking android-N directory that contains only
    a jar/symlink while the complete platform lives in android-N-2.  AGP needs
    more than android.jar: in particular build.prop plus package/source
    metadata are used while resolving the target hash.
    """
    path = Path(path)
    score = 0
    if path.name == f"android-{api}":
        score += 2              # tie breaker only; completeness matters more
    if _valid_android_jar(path / "android.jar"):
        score += 50
    for name, weight in (
        ("build.prop", 40),
        ("source.properties", 25),
        ("package.xml", 20),
        ("framework.aidl", 5),
    ):
        if (path / name).is_file():
            score += weight
    return score


def _find_platform_metadata_dir(sdk, api, preferred_jar=None):
    """Find the most complete platform directory for *api*.

    If the selected android.jar came from a platform directory, strongly prefer
    that directory.  This avoids accidentally choosing an incomplete
    android-N stub ahead of Termux's complete android-N-2 package.
    """
    sdk = Path(sdk)
    platforms = sdk / "platforms"
    if not platforms.exists():
        return None

    dirs = [d for d in platforms.glob(f"android-{api}*") if d.is_dir()]
    preferred_parent = None
    if preferred_jar is not None:
        try:
            preferred_parent = Path(preferred_jar).resolve().parent
        except OSError:
            preferred_parent = Path(preferred_jar).parent

    def score(d):
        n = _platform_candidate_score(d, api)
        try:
            if preferred_parent is not None and d.resolve() == preferred_parent:
                # Preference is only a tie-breaker.  A complete suffixed Termux
                # platform must beat an incomplete canonical-looking stub.
                n += 5
        except OSError:
            pass
        return (n, d.name == f"android-{api}", str(d))

    dirs.sort(key=score, reverse=True)
    return dirs[0] if dirs else None


def _link_or_copy(src, dst):
    """Expose one SDK platform entry in the shim without needlessly duplicating it."""
    src, dst = Path(src), Path(dst)
    if dst.exists() or dst.is_symlink():
        if dst.is_dir() and not dst.is_symlink():
            shutil.rmtree(dst)
        else:
            dst.unlink()
    try:
        dst.symlink_to(src.resolve(), target_is_directory=src.is_dir())
        return "symlink"
    except OSError:
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True, symlinks=True)
        else:
            shutil.copy2(src, dst)
        return "copy"


def _verify_shim_platform(platform, api):
    """Validate the minimum platform shape AGP/SDK target discovery expects."""
    platform = Path(platform)
    missing = []
    if not _valid_android_jar(platform / "android.jar"):
        missing.append("android.jar(valid zip/jar)")
    for name in ("build.prop", "source.properties"):
        if not (platform / name).is_file():
            missing.append(name)

    if missing:
        return False, missing

    # Catch the especially confusing case where source.properties exists but
    # declares a different API level.
    try:
        text = (platform / "source.properties").read_text(errors="replace")
        m = re.search(r"(?m)^AndroidVersion\.ApiLevel\s*=\s*(\d+)\s*$", text)
        if m and int(m.group(1)) != int(api):
            return False, [f"source.properties ApiLevel={m.group(1)} (wanted {api})"]
    except OSError:
        pass
    return True, []


def prepare_project_android_sdk(root, sdk, compile_sdk):
    """
    Build a canonical project-local Android SDK view for AGP.

    Termux packages may install a complete platform as ``android-36-2`` while
    its package metadata declares ``platforms;android-36``.  They can also
    leave an incomplete ``android-36`` stub nearby.  AGP/SDK target discovery
    requires the platform's build.prop and metadata in addition to android.jar.

    The shim therefore mirrors the *entire usable donor platform* into the
    canonical ``platforms/android-N`` location, copying package metadata and
    linking/copying all other files.  The Termux-managed SDK is never modified.
    """
    root = Path(root)
    sdk = Path(sdk).resolve()
    api = int(compile_sdk)
    jar = _find_best_android_jar(sdk, api)
    if jar is None:
        die(f"Could not find a valid android.jar for API {api} under {sdk} or {termux_prefix()}")

    donor = _find_platform_metadata_dir(sdk, api, preferred_jar=jar)
    if donor is None:
        die(
            f"Found android.jar for API {api} at {jar}, but could not find a "
            f"platform directory under {sdk/'platforms'} containing SDK metadata"
        )

    # If the jar search happened to prefer an incomplete canonical stub, but
    # the completeness scan found a better donor, use the donor's jar instead.
    donor_jar = donor / "android.jar"
    if _valid_android_jar(donor_jar):
        jar = donor_jar

    shim = root / ".apk2project-android-sdk"
    platform = shim / "platforms" / f"android-{api}"
    if platform.exists() or platform.is_symlink():
        if platform.is_dir() and not platform.is_symlink():
            shutil.rmtree(platform)
        else:
            platform.unlink()
    platform.mkdir(parents=True, exist_ok=True)

    exposed = {}
    metadata_names = {"source.properties", "package.xml", "build.prop", "sdk.properties"}

    # Mirror *everything* from the complete donor.  Metadata is copied so tools
    # see ordinary files at the canonical path; larger payloads are linked when
    # possible to keep this cheap on a phone.
    for src in sorted(donor.iterdir(), key=lambda x: x.name):
        dst = platform / src.name
        if src.name in metadata_names and src.is_file():
            try:
                shutil.copy2(src, dst)
                exposed[src.name] = "copy"
                continue
            except OSError:
                pass
        exposed[src.name] = _link_or_copy(src, dst)

    # Guarantee the selected valid jar is the one visible in the shim.
    exposed["android.jar"] = _link_or_copy(jar, platform / "android.jar")

    # Do not invent build.prop: if it is missing, this donor isn't a usable SDK
    # platform for AGP.  A synthetic source.properties is safe only as a last
    # resort because it describes package metadata, not framework capabilities.
    sp = platform / "source.properties"
    if not sp.exists():
        sp.write_text(
            f"Pkg.Desc=Android SDK Platform {api}\n"
            "Pkg.Revision=1\n"
            f"AndroidVersion.ApiLevel={api}\n"
            "AndroidVersion.IsBaseSdk=true\n"
        )
        exposed["source.properties"] = "synthesized"

    ok, problems = _verify_shim_platform(platform, api)
    if not ok:
        available = []
        for d in sorted((sdk / "platforms").glob(f"android-{api}*")):
            if d.is_dir():
                available.append({
                    "path": str(d),
                    "score": _platform_candidate_score(d, api),
                    "android_jar": _valid_android_jar(d / "android.jar"),
                    "build_prop": (d / "build.prop").is_file(),
                    "source_properties": (d / "source.properties").is_file(),
                    "package_xml": (d / "package.xml").is_file(),
                })
        analysis = root / "analysis"
        analysis.mkdir(parents=True, exist_ok=True)
        (analysis / "android-sdk-shim-failure.json").write_text(json.dumps({
            "api": api,
            "source_sdk": str(sdk),
            "chosen_donor": str(donor),
            "problems": problems,
            "candidates": available,
        }, indent=2, sort_keys=True))
        die(
            f"Could not construct a usable Android SDK Platform {api}: "
            + ", ".join(problems)
            + f". See {analysis/'android-sdk-shim-failure.json'}"
        )

    # Keep SDK-level tools/licenses visible.  aapt2 itself is overridden with
    # Termux's native binary, but AGP may still inspect these packages.
    for name in ("licenses", "build-tools", "platform-tools", "cmdline-tools", "tools"):
        src = sdk / name
        dst = shim / name
        if src.exists() and not dst.exists():
            try:
                dst.symlink_to(src.resolve(), target_is_directory=src.is_dir())
            except OSError:
                if src.is_dir():
                    shutil.copytree(src, dst, dirs_exist_ok=True, symlinks=True)

    analysis = root / "analysis"
    analysis.mkdir(parents=True, exist_ok=True)
    (analysis / "android-sdk-shim.json").write_text(json.dumps({
        "api": api,
        "source_sdk": str(sdk),
        "shim_sdk": str(shim),
        "platform": str(platform),
        "android_jar": str(jar.resolve()),
        "android_jar_size": jar.stat().st_size,
        "metadata_donor": str(donor.resolve()),
        "donor_score": _platform_candidate_score(donor, api),
        "exposed_entries": exposed,
    }, indent=2, sort_keys=True))
    log(f"Using canonical project-local Android SDK shim for API {api}: {shim}")
    detail(f"platform donor: {donor}", 1)
    detail(f"android.jar -> {jar.resolve()}", 1)
    return shim



def ensure_runtime_artifact_inventory_task(root):
    """Add the v25 read-only runtime JAR/AAR inventory task to an existing project.

    Resume mode intentionally preserves app/build.gradle. Appending this helper does
    not change the dependency graph; it only lets Python inspect the classpath that
    already produced the user's current compiler checkpoint.
    """
    bg = Path(root) / "app/build.gradle"
    if not bg.is_file():
        return False
    text = bg.read_text()
    if 'apk2projectResolvedArtifacts' in text:
        return False
    block = r'''

// apk2project v25 read-only helper: complete runtime binary inventory.
tasks.register("apk2projectResolvedArtifacts") {
  doLast {
    def artifacts = configurations.debugRuntimeClasspath.incoming.artifactView { }.artifacts.artifacts
    artifacts
      .findAll {
        def n = it.file.name.toLowerCase()
        n.endsWith(".aar") || n.endsWith(".jar")
      }
      .sort { a, b -> a.id.displayName <=> b.id.displayName }
      .each { a ->
        def cid = a.id.componentIdentifier
        if (cid instanceof org.gradle.api.artifacts.component.ModuleComponentIdentifier) {
          def n = a.file.name.toLowerCase()
          def typ = n.endsWith(".aar") ? "aar" : "jar"
          println("APK2PROJECT_ARTIFACT\t${cid.group}\t${cid.module}\t${cid.version}\t${typ}\t${a.file.absolutePath}")
        }
      }
  }
}
'''
    bg.write_text(text.rstrip() + block + "\n")
    return True

def ensure_full_javac_frontier(root):
    """Patch an existing frozen/resumed build without changing dependencies.

    Repair scoring must compare like with like. Gradle's incremental JavaCompile can
    compile only the changed dependency closure, which makes a visible 3-error build
    explode after one fix merely because javac is now seeing many more source files.
    """
    root = Path(root)
    bg = root / "app/build.gradle"
    if not bg.is_file():
        return False
    text = bg.read_text(errors="ignore")
    original = text
    text = re.sub(
        r'options\.compilerArgs\.addAll\(\["-Xlint:none",\s*"-nowarn",\s*"-Xmaxerrs",\s*"\d+"\]\)',
        'options.compilerArgs.addAll(["-Xlint:none", "-nowarn", "-Xmaxerrs", "10000"])',
        text,
    )
    marker = 'tasks.withType(org.gradle.api.tasks.compile.JavaCompile).configureEach {'
    if 'options.incremental = false' not in text:
        if marker in text:
            text = text.replace(marker, marker + '\n  options.incremental = false', 1)
        else:
            text += (
                '\n\n// apk2project v24: stable full javac frontier for semantic repair.\n'
                'tasks.withType(org.gradle.api.tasks.compile.JavaCompile).configureEach {\n'
                '  options.incremental = false\n'
                '  options.warnings = false\n'
                '  options.compilerArgs.addAll(["-Xlint:none", "-nowarn", "-Xmaxerrs", "10000"])\n'
                '}\n'
            )
    if text != original:
        bg.write_text(text)
        log("Enabled non-incremental full javac frontier (-Xmaxerrs 10000) for reliable repair scoring")
        return True
    return False

def configure_project_sdk(root, sdk, compile_sdk=35):
    root = Path(root)
    sdk = prepare_project_android_sdk(root, sdk, compile_sdk)
    (root / "local.properties").write_text(f"sdk.dir={sdk}\n")

    # Native Termux aapt2 override avoids AGP trying to execute a desktop
    # Linux binary on Android/ARM64.
    aapt2 = shutil.which("aapt2")
    gp = root / "gradle.properties"
    txt = gp.read_text() if gp.exists() else ""
    if aapt2 and "android.aapt2FromMavenOverride=" not in txt:
        txt += f"\nandroid.aapt2FromMavenOverride={aapt2}\n"
        gp.write_text(txt)

    java = shutil.which("java") or "java"
    java_home = Path(java).resolve().parent.parent if java != "java" else Path(os.environ.get("JAVA_HOME", ""))
    build = root / "build-termux.sh"
    build.write_text(f"""#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
export ANDROID_HOME={shlex_quote(str(sdk))}
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export JAVA_HOME={shlex_quote(str(java_home))}
export PATH="$JAVA_HOME/bin:$PATH"
cd "$(dirname "$0")"
exec gradle --no-daemon "${{@:-build}}"
""")
    build.chmod(build.stat().st_mode | stat.S_IXUSR)
    log(f"Wrote {root/'local.properties'}")
    log(f"Wrote runnable {build}")

def shlex_quote(x):
    # Avoid another dependency just for shell quoting.
    return "'" + str(x).replace("'", "'\"'\"'") + "'"




def normalize_reconstructed_manifest(manifest, analysis_dir):
    """
    Normalize durable app/src/main/AndroidManifest.xml for modern AGP.

    Metadata that belongs in Gradle (package/namespace and extractNativeLibs)
    is removed only after it has been read from the pristine Apktool manifest.
    Android 12+ exported requirements are repaired using the old platform
    semantics: a component with an intent-filter was exported by default.
    """
    manifest = Path(manifest)
    analysis_dir = Path(analysis_dir)
    audit = []
    if not manifest.exists():
        return audit

    def record(action, **kw):
        audit.append({"action": action, **kw})

    try:
        if LET is not None:
            tree = LET.parse(str(manifest), _lxml_parser(remove_comments=False))
            root = tree.getroot()
            app = next((x for x in root if _xml_local_name(x.tag) == "application"), None)
        else:
            tree = ET.parse(manifest)
            root = tree.getroot()
            app = root.find("application")

        changed = False
        package_name = root.attrib.pop("package", None)
        if package_name is not None:
            changed = True
            record("removed-manifest-package", value=package_name,
                   reason="AGP namespace/applicationId is emitted in app/build.gradle")

        # Apktool commonly restores build-time metadata that modern AGP should
        # derive from the Gradle model rather than from the source manifest.
        for attr in (
            "platformBuildVersionCode",
            "platformBuildVersionName",
            A + "compileSdkVersion",
            A + "compileSdkVersionCodename",
        ):
            if attr in root.attrib:
                value = root.attrib.pop(attr)
                changed = True
                record("removed-build-metadata-attribute", attribute=attr, value=value)

        if app is not None:
            extracted = app.attrib.pop(A + "extractNativeLibs", None)
            if extracted is not None:
                changed = True
                record(
                    "removed-extractNativeLibs-from-manifest",
                    value=extracted,
                    reason="migrated to android.packaging.jniLibs.useLegacyPackaging",
                )

            children = list(app) if LET is None else list(app.iterchildren())
            for el in children:
                tag = _xml_local_name(el.tag)
                if tag not in {"activity", "activity-alias", "service", "receiver"}:
                    continue
                has_filter = any(_xml_local_name(ch.tag) == "intent-filter" for ch in list(el))
                if has_filter and el.get(A + "exported") is None:
                    el.set(A + "exported", "true")
                    changed = True
                    record(
                        "set-android-exported",
                        component_type=tag,
                        name=el.get(A + "name"),
                        line=getattr(el, "sourceline", None),
                        value="true",
                        reason="component has intent-filter; preserve pre-Android-12 default behavior",
                    )

        if changed:
            backup = analysis_dir / "manifest-backups" / manifest.name
            if not backup.exists():
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(manifest, backup)
            if LET is not None:
                tree.write(str(manifest), encoding="utf-8", xml_declaration=True, pretty_print=True)
            else:
                try:
                    ET.indent(tree, space="    ")
                except AttributeError:
                    pass
                tree.write(manifest, encoding="utf-8", xml_declaration=True)
    except Exception as e:
        warn(f"Could not normalize reconstructed manifest: {e}")
        record("manifest-normalization-failed", error=str(e))

    if audit:
        analysis_dir.mkdir(parents=True, exist_ok=True)
        (analysis_dir / "manifest-normalization.json").write_text(
            json.dumps(audit, indent=2, sort_keys=True)
        )
        fixed = sum(1 for x in audit if x.get("action") == "set-android-exported")
        if fixed:
            log(f"Manifest normalization added android:exported to {fixed} intent-filter component(s)")
    return audit


def _xml_local_name(tag):
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _require_lxml(feature="advanced resource repair"):
    if LET is None:
        warn(
            f"{feature} needs python-lxml; install it in Termux with "
            f"'pkg install python-lxml' (or 'pip install lxml')"
        )
        return False
    return True


def _resource_backup(path, res_root, analysis_dir):
    """Keep one pristine copy of every source resource we modify."""
    path = Path(path)
    res_root = Path(res_root)
    analysis_dir = Path(analysis_dir)
    try:
        rel = path.resolve().relative_to(res_root.resolve())
    except Exception:
        rel = Path(path.name)
    dst = analysis_dir / "resource-backups" / rel
    if not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dst)
    return dst


def _lxml_parser(remove_comments=True):
    return LET.XMLParser(
        remove_comments=remove_comments,
        remove_blank_text=True,
        recover=False,
        huge_tree=True,
    )


def _write_lxml_tree(tree, path, res_root, analysis_dir):
    _resource_backup(path, res_root, analysis_dir)
    tree.write(
        str(path),
        encoding="utf-8",
        xml_declaration=True,
        pretty_print=True,
    )


def _top_resource_key(el):
    """Return Android's logical (type,name) key for a top-level values element."""
    tag = _xml_local_name(el.tag)
    name = el.get("name")
    if not name:
        return None
    if tag == "item":
        typ = el.get("type")
        return (typ, name) if typ else None
    if tag in {"declare-styleable", "public", "overlayable", "staging-public-group"}:
        # These have special semantics and are handled separately where needed.
        return None
    return (tag, name)


def _attr_is_definition(el):
    if _xml_local_name(el.tag) != "attr":
        return False
    # A nested <attr name="x"/> is normally a reference from a styleable, not a
    # second definition.  format/enums/flags make it a real definition.
    if el.get("format"):
        return True
    return any(_xml_local_name(ch.tag) in {"enum", "flag"} for ch in el)


def _split_formats(value):
    return [x.strip() for x in (value or "").split("|") if x.strip()]


def _merge_attr_definition(dst, src, audit, context):
    """Merge format/enum/flag information from src into dst."""
    changed = False
    formats = []
    for x in _split_formats(dst.get("format")) + _split_formats(src.get("format")):
        if x not in formats:
            formats.append(x)
    merged_format = "|".join(formats)
    if merged_format and dst.get("format") != merged_format:
        dst.set("format", merged_format)
        changed = True

    existing = {}
    for ch in dst:
        tag = _xml_local_name(ch.tag)
        if tag in {"enum", "flag"} and ch.get("name"):
            existing[(tag, ch.get("name"))] = ch

    for ch in src:
        tag = _xml_local_name(ch.tag)
        name = ch.get("name")
        if tag not in {"enum", "flag"} or not name:
            continue
        k = (tag, name)
        old = existing.get(k)
        if old is None:
            dst.append(copy.deepcopy(ch))
            existing[k] = dst[-1]
            changed = True
            continue
        if old.get("value") != ch.get("value"):
            audit.append({
                "action": "attr-child-conflict-kept-first",
                "context": context,
                "tag": tag,
                "name": name,
                "kept_value": old.get("value"),
                "discarded_value": ch.get("value"),
            })
    return changed


def _merge_style(dst, src, audit, context):
    changed = False
    seen = {}
    for ch in dst:
        if _xml_local_name(ch.tag) == "item" and ch.get("name"):
            seen[ch.get("name")] = ch
    for ch in src:
        if _xml_local_name(ch.tag) != "item" or not ch.get("name"):
            dst.append(copy.deepcopy(ch))
            changed = True
            continue
        name = ch.get("name")
        if name not in seen:
            dst.append(copy.deepcopy(ch))
            seen[name] = dst[-1]
            changed = True
        elif LET.tostring(seen[name], method="c14n") != LET.tostring(ch, method="c14n"):
            audit.append({
                "action": "style-item-conflict-kept-first",
                "context": context,
                "item": name,
            })
    return changed


def _merge_styleable(dst, src, audit, context):
    """Merge duplicate declare-styleable blocks without losing membership."""
    changed = False
    by_name = {}
    for ch in dst:
        if _xml_local_name(ch.tag) == "attr" and ch.get("name"):
            by_name[ch.get("name")] = ch
    for ch in src:
        if _xml_local_name(ch.tag) != "attr" or not ch.get("name"):
            dst.append(copy.deepcopy(ch))
            changed = True
            continue
        name = ch.get("name")
        old = by_name.get(name)
        if old is None:
            dst.append(copy.deepcopy(ch))
            by_name[name] = dst[-1]
            changed = True
        else:
            if _merge_attr_definition(old, ch, audit, context + f"/attr:{name}"):
                changed = True
    return changed




def _apktool_safe_synthetic_name(name):
    """Return a stable, source-legal replacement for an Apktool/AAPT synthetic name."""
    base = str(name).lstrip("$")
    base = re.sub(r"[^A-Za-z0-9_.]+", "_", base)
    base = base.lower().strip("._") or "resource"
    # File/value entry names beginning with a letter are accepted everywhere we
    # use this. Prefixing also makes collisions with real app resources unlikely.
    return "apktool_synth_" + base


def sanitize_apktool_synthetic_resources(res_root, analysis_dir):
    """
    Repair compiled-only resource names that Apktool may expose as source names.

    AAPT2 creates private synthetic entries for things such as inline animated
    vector drawables. Their compiled names commonly look like:

        drawable/$avd_hide_password__0
        drawable/$m3_avd_show_password__1

    '$' is legal in the compiled resource table's private/generated namespace,
    but it is NOT a legal source resource entry name. A decoded public.xml can
    therefore be impossible to feed back into AAPT2.

    Strategy:
      * if a real decoded source definition/file exists, rename it to a stable
        source-legal name and rewrite XML references;
      * if the '$...' name exists only as a <public> declaration (the common
        Apktool artifact), drop only that declaration -- do NOT invent a fake
        definition;
      * preserve an audit and backups for every modified source file.
    """
    res_root = Path(res_root)
    analysis_dir = Path(analysis_dir)
    audit = []
    if not res_root.exists() or not _require_lxml("Apktool synthetic-resource repair"):
        return audit

    # (resource_type, old_name) -> new_name for actual source definitions.
    renames = {}
    occupied = collections.defaultdict(set)

    # Gather ordinary file-backed resource names first.
    for p in res_root.rglob("*"):
        if not p.is_file() or p.suffix.lower() == ".xml" and p.parent.name.startswith("values"):
            continue
        rtype = p.parent.name.split("-", 1)[0]
        occupied[rtype].add(p.stem)

    # Gather named values resources and rename any actual definition containing '$'.
    value_records = []
    for values_dir in sorted(x for x in res_root.iterdir() if x.is_dir() and x.name.startswith("values")):
        for xml in sorted(values_dir.glob("*.xml")):
            try:
                tree = LET.parse(str(xml), _lxml_parser(remove_comments=True))
                root = tree.getroot()
            except Exception as e:
                audit.append({"action": "synthetic-scan-parse-failed", "file": str(xml), "error": str(e)})
                continue
            if _xml_local_name(root.tag) != "resources":
                continue
            value_records.append((xml, tree, root))
            for el in root:
                tag = _xml_local_name(el.tag)
                name = el.get("name")
                if not name or "$" not in name or tag == "public":
                    continue
                key = _top_resource_key(el)
                if not key:
                    continue
                rtype, old = key
                new = _apktool_safe_synthetic_name(old)
                candidate = new
                n = 2
                while candidate in occupied[rtype]:
                    candidate = f"{new}_{n}"
                    n += 1
                occupied[rtype].add(candidate)
                renames[(rtype, old)] = candidate
                el.set("name", candidate)
                _write_lxml_tree(tree, xml, res_root, analysis_dir)
                audit.append({
                    "action": "renamed-synthetic-values-resource",
                    "type": rtype,
                    "old_name": old,
                    "new_name": candidate,
                    "file": str(xml),
                    "line": getattr(el, "sourceline", None),
                })

    # Rename actual file-backed '$...' resources. Most APKs won't have these;
    # public.xml-only synthetic entries are more common.
    for p in sorted(list(res_root.rglob("*$*"))):
        if not p.is_file() or p.parent.name.startswith("values"):
            continue
        rtype = p.parent.name.split("-", 1)[0]
        old = p.stem
        key = (rtype, old)
        new = renames.get(key) or _apktool_safe_synthetic_name(old)
        candidate = new
        n = 2
        while (p.with_name(candidate + p.suffix)).exists():
            candidate = f"{new}_{n}"
            n += 1
        new = candidate
        renames[key] = new
        _resource_backup(p, res_root, analysis_dir)
        dst = p.with_name(new + p.suffix)
        p.rename(dst)
        audit.append({
            "action": "renamed-synthetic-file-resource",
            "type": rtype,
            "old_name": old,
            "new_name": new,
            "old_file": str(p),
            "new_file": str(dst),
        })

    # Rewrite source XML references to actual definitions we renamed. This is
    # intentionally exact by type/name rather than a global '$' substitution.
    if renames:
        for xml in sorted(res_root.rglob("*.xml")):
            try:
                raw = xml.read_text(encoding="utf-8")
            except Exception:
                continue
            updated = raw
            for (rtype, old), new in renames.items():
                # Handles @drawable/$foo and package-qualified forms such as
                # @com.example:drawable/$foo. The prefix is retained verbatim.
                pat = re.compile(
                    r"([@?](?:\\*?[A-Za-z0-9_.]+:)?" + re.escape(rtype) + r"/)" +
                    re.escape(old) + r"(?=[^A-Za-z0-9_.$]|$)"
                )
                updated = pat.sub(lambda m: m.group(1) + new, updated)
            if updated != raw:
                _resource_backup(xml, res_root, analysis_dir)
                xml.write_text(updated, encoding="utf-8")
                audit.append({"action": "rewrote-synthetic-resource-references", "file": str(xml)})

    # Finally clean <public> declarations. If the synthetic name was backed by a
    # source definition we renamed, rename the declaration too; otherwise remove
    # it. public.xml is metadata for preserving table IDs, not a definition, so a
    # compiled-only '$...' entry must not be recreated as a source resource.
    for xml, _old_tree, _old_root in value_records:
        try:
            tree = LET.parse(str(xml), _lxml_parser(remove_comments=True))
            root = tree.getroot()
        except Exception:
            continue
        dirty = False
        for el in list(root):
            if _xml_local_name(el.tag) != "public":
                continue
            name = el.get("name")
            rtype = el.get("type")
            if not name or "$" not in name or not rtype:
                continue
            replacement = renames.get((rtype, name))
            if replacement:
                el.set("name", replacement)
                action = "renamed-synthetic-public-declaration"
            else:
                root.remove(el)
                action = "removed-compiled-only-synthetic-public-declaration"
            dirty = True
            audit.append({
                "action": action,
                "type": rtype,
                "old_name": name,
                "new_name": replacement,
                "file": str(xml),
                "line": getattr(el, "sourceline", None),
            })
        if dirty:
            _write_lxml_tree(tree, xml, res_root, analysis_dir)

    if audit:
        analysis_dir.mkdir(parents=True, exist_ok=True)
        (analysis_dir / "apktool-synthetic-resources.json").write_text(
            json.dumps(audit, indent=2, sort_keys=True)
        )
        removed = sum(1 for x in audit if x.get("action") == "removed-compiled-only-synthetic-public-declaration")
        renamed = sum(1 for x in audit if x.get("action", "").startswith("renamed-synthetic"))
        log(f"Sanitized Apktool synthetic resources: removed {removed} compiled-only public entries, renamed {renamed} source definitions")
    return audit

def normalize_value_resources(res_root, analysis_dir):
    """
    Normalize decoded values XML and eliminate AAPT2-hostile duplicate definitions.

    Important details:
      * comments are stripped and XML is pretty-printed;
      * duplicate ordinary resources in one configuration are collapsed;
      * duplicate styles and declare-styleables are merged where safe;
      * attr definitions are deduplicated across BOTH top-level <attr> and
        <declare-styleable><attr ...>, while plain nested <attr name="x"/> remains
        a reference and is preserved;
      * enum/flag children are NEVER removed merely for being nested. They are
        valid under attr, including attr under declare-styleable.
    """
    res_root = Path(res_root)
    analysis_dir = Path(analysis_dir)
    audit = []
    if not res_root.exists():
        return audit
    if not _require_lxml("resource normalization"):
        # Preserve the old conservative fallback if lxml is unavailable.
        return remove_duplicate_value_resources_etree(
            res_root, analysis_dir / "deleted-duplicate-resources-fallback.json"
        )

    for values_dir in sorted(p for p in res_root.iterdir()
                             if p.is_dir() and p.name.startswith("values")):
        records = []
        for xml in sorted(values_dir.glob("*.xml")):
            try:
                raw = xml.read_bytes()
                tree = LET.parse(str(xml), _lxml_parser(remove_comments=True))
                root = tree.getroot()
                if _xml_local_name(root.tag) != "resources":
                    warn(f"Skipping non-<resources> values XML: {xml}")
                    continue
                records.append({
                    "path": xml,
                    "tree": tree,
                    "root": root,
                    "dirty": b"<!--" in raw,
                    "normalized": True,
                })
            except Exception as e:
                warn(f"resource parse failed {xml}: {e}")
                audit.append({"action": "parse-failed", "file": str(xml), "error": str(e)})

        # 1. Merge duplicate declare-styleable blocks with the same name.
        styleables = {}
        for rec in records:
            root = rec["root"]
            for el in list(root):
                if _xml_local_name(el.tag) != "declare-styleable" or not el.get("name"):
                    continue
                name = el.get("name")
                if name not in styleables:
                    styleables[name] = (rec, el)
                    continue
                dst_rec, dst = styleables[name]
                _merge_styleable(dst, el, audit, f"{values_dir.name}/declare-styleable:{name}")
                root.remove(el)
                rec["dirty"] = True
                dst_rec["dirty"] = True
                audit.append({
                    "action": "merged-duplicate-declare-styleable",
                    "configuration": values_dir.name,
                    "name": name,
                    "kept": str(dst_rec["path"]),
                    "removed_from": str(rec["path"]),
                })

        # 2. De-duplicate attr DEFINITIONS across top-level and styleables.
        # Prefer a top-level attr as the canonical definition when one exists.
        attr_defs = collections.defaultdict(list)
        for rec in records:
            root = rec["root"]
            for el in list(root):
                tag = _xml_local_name(el.tag)
                if tag == "attr" and el.get("name"):
                    attr_defs[el.get("name")].append((rec, el, "top"))
                elif tag == "item" and el.get("type") == "attr" and el.get("name"):
                    attr_defs[el.get("name")].append((rec, el, "top-item"))
                elif tag == "declare-styleable":
                    for ch in list(el):
                        if _attr_is_definition(ch) and ch.get("name"):
                            attr_defs[ch.get("name")].append((rec, ch, "nested"))

        for name, defs in sorted(attr_defs.items()):
            if len(defs) < 2:
                continue
            canonical = (
                next((d for d in defs if d[2] == "top"), None)
                or next((d for d in defs if d[2] == "nested"), None)
                or defs[0]
            )
            can_rec, can_el, can_kind = canonical
            for rec, el, kind in defs:
                if el is can_el:
                    continue
                _merge_attr_definition(
                    can_el, el, audit,
                    f"{values_dir.name}/attr:{name}"
                )
                can_rec["dirty"] = True
                parent = el.getparent()
                if kind == "nested" and _xml_local_name(parent.tag) == "declare-styleable":
                    # Preserve styleable membership but turn the duplicate definition
                    # into a reference to the canonical attr definition.
                    for ch in list(el):
                        el.remove(ch)
                    keep_name = el.get("name")
                    el.attrib.clear()
                    el.set("name", keep_name)
                    el.text = None
                    rec["dirty"] = True
                    action = "converted-duplicate-attr-definition-to-reference"
                else:
                    parent.remove(el)
                    rec["dirty"] = True
                    action = "removed-duplicate-attr-definition"
                audit.append({
                    "action": action,
                    "configuration": values_dir.name,
                    "name": name,
                    "canonical_file": str(can_rec["path"]),
                    "changed_file": str(rec["path"]),
                    "canonical_line": can_el.sourceline,
                    "duplicate_line": el.sourceline,
                })

        # 3. Collapse duplicate ordinary top-level resources. Styles are merged.
        seen = {}
        for rec in records:
            root = rec["root"]
            for el in list(root):
                tag = _xml_local_name(el.tag)
                if tag in {"attr", "declare-styleable"}:
                    continue
                if tag == "item" and el.get("type") == "attr":
                    continue
                key = _top_resource_key(el)
                if key is None:
                    continue
                if key not in seen:
                    seen[key] = (rec, el)
                    continue
                dst_rec, dst = seen[key]
                typ, name = key
                if typ == "style":
                    _merge_style(dst, el, audit, f"{values_dir.name}/style:{name}")
                    dst_rec["dirty"] = True
                else:
                    same = LET.tostring(dst, method="c14n") == LET.tostring(el, method="c14n")
                    if not same:
                        audit.append({
                            "action": "conflicting-duplicate-resource-kept-first",
                            "configuration": values_dir.name,
                            "type": typ,
                            "name": name,
                            "kept": str(dst_rec["path"]),
                            "discarded": str(rec["path"]),
                        })
                root.remove(el)
                rec["dirty"] = True
                audit.append({
                    "action": "removed-duplicate-resource",
                    "configuration": values_dir.name,
                    "type": typ,
                    "name": name,
                    "kept": str(dst_rec["path"]),
                    "removed_from": str(rec["path"]),
                })

        # 4. Within every styleable/style, remove duplicate member names safely.
        for rec in records:
            root = rec["root"]
            for el in root:
                tag = _xml_local_name(el.tag)
                if tag == "declare-styleable":
                    members = {}
                    for ch in list(el):
                        if _xml_local_name(ch.tag) != "attr" or not ch.get("name"):
                            continue
                        name = ch.get("name")
                        if name not in members:
                            members[name] = ch
                            continue
                        _merge_attr_definition(members[name], ch, audit,
                                               f"{values_dir.name}/declare-styleable:{el.get('name')}/attr:{name}")
                        el.remove(ch)
                        rec["dirty"] = True
                        audit.append({
                            "action": "removed-duplicate-styleable-member",
                            "configuration": values_dir.name,
                            "styleable": el.get("name"),
                            "attr": name,
                            "file": str(rec["path"]),
                        })
                elif tag == "style":
                    members = {}
                    for ch in list(el):
                        if _xml_local_name(ch.tag) != "item" or not ch.get("name"):
                            continue
                        name = ch.get("name")
                        if name in members:
                            el.remove(ch)
                            rec["dirty"] = True
                            audit.append({
                                "action": "removed-duplicate-style-item",
                                "configuration": values_dir.name,
                                "style": el.get("name"),
                                "item": name,
                                "file": str(rec["path"]),
                            })
                        else:
                            members[name] = ch

        # Always normalize formatting/comments once. Backups mean this remains auditable.
        for rec in records:
            _write_lxml_tree(rec["tree"], rec["path"], res_root, analysis_dir)

    report = analysis_dir / "resource-normalization.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(audit, indent=2, sort_keys=True))
    if audit:
        log(f"Resource normalization made/logged {len(audit)} repair decisions")
    else:
        detail("Resource normalization found no duplicate definitions", 1)
    return audit


def remove_duplicate_value_resources_etree(res_root, report_path=None):
    """Conservative fallback used only when lxml is unavailable."""
    removed = []
    res_root = Path(res_root)
    if not res_root.exists():
        return removed
    ET.register_namespace("android", ANDROID_NS)
    for values_dir in sorted(p for p in res_root.iterdir()
                             if p.is_dir() and p.name.startswith("values")):
        seen = {}
        for xml in sorted(values_dir.glob("*.xml")):
            try:
                tree = ET.parse(xml)
                root = tree.getroot()
            except Exception as e:
                warn(f"resource duplicate scan skipped {xml}: {e}")
                continue
            changed = False
            for child in list(root):
                name = child.attrib.get("name")
                if not name:
                    continue
                tag = child.tag.rsplit("}", 1)[-1]
                rtype = child.attrib.get("type") if tag == "item" else tag
                if not rtype or rtype == "declare-styleable":
                    continue
                key = (rtype, name)
                if key not in seen:
                    seen[key] = xml
                    continue
                root.remove(child)
                changed = True
                removed.append({
                    "configuration": values_dir.name,
                    "type": rtype,
                    "name": name,
                    "kept": str(seen[key]),
                    "deleted_from": str(xml),
                })
            if changed:
                tree.write(xml, encoding="utf-8", xml_declaration=True)
    if report_path is not None:
        report_path = Path(report_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(removed, indent=2, sort_keys=True))
    return removed


def remove_duplicate_value_resources(res_root, report_path=None):
    """Compatibility wrapper retained for callers from older versions."""
    analysis_dir = Path(report_path).parent if report_path else Path(res_root).parents[3] / "analysis"
    return normalize_value_resources(res_root, analysis_dir)


AAPT_LOCATION_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+)(?::(?P<column>\d+))?:\s*(?P<message>.*)$"
)
AAPT_DUPLICATE_RE = re.compile(r"duplicate value for resource ['\"]([^'\"]+)['\"]", re.I)
AAPT_UNKNOWN_TAG_RE = re.compile(r"unknown tag <([^>]+)>", re.I)


# Gradle's requested task is compileDebugJavaWithJavac, but prerequisite failures can
# happen in resources, manifests, dependencies, etc.  Never assume every non-zero
# Gradle exit is an AAPT2 failure: doing so makes javac errors burn through the
# resource-repair retry budget and rerun an identical build several times.
_RESOURCE_FAILURE_TASK_RE = re.compile(
    r"(?im)(?:>\s*Task\s+|Execution failed for task ['\"]?)"
    r":[^\s'\"]*(?:merge|process|compile|parse|generate|link)[^\s'\"]*"
    r"(?:Resources|Resource|RFile|Aapt)[^\s'\"]*"
)
_JAVAC_FAILURE_TASK_RE = re.compile(
    r"(?im)(?:>\s*Task\s+|Execution failed for task ['\"]?)"
    r":[^\s'\"]*(?:compile[^\s'\"]*(?:JavaWithJavac|Java)|javac)[^\s'\"]*"
)
_JAVAC_DIAGNOSTIC_RE = re.compile(
    r"(?im)^.*?\.java:\d+(?::\d+)?:\s*(?:error:|warning:)"
)

# These are intentionally separate from the broad marker regexes above.  The
# terminal Gradle failure is much more authoritative than a phrase that happens
# to occur somewhere earlier in the build output.
_EXECUTION_FAILED_TASK_RE = re.compile(
    r"(?im)Execution failed for task\s+['\"](?P<task>:[^'\"]+)['\"]"
)
_TASK_FAILED_LINE_RE = re.compile(
    r"(?im)^\s*>?\s*Task\s+(?P<task>:\S+)\s+FAILED\s*$"
)
_TASK_STARTED_LINE_RE = re.compile(
    r"(?im)^\s*>?\s*Task\s+(?P<task>:\S*compile\S*JavaWithJavac\S*)\s*$"
)


def _gradle_failed_task(text):
    """Return Gradle's most authoritative terminal failed task, if present."""
    text = text or ""
    # The final "Execution failed for task ..." block is Gradle's canonical
    # explanation of the task that caused the build to fail. Prefer it over all
    # incidental diagnostics printed earlier by prerequisite tasks/tools.
    execution = [m.group("task") for m in _EXECUTION_FAILED_TASK_RE.finditer(text)]
    if execution:
        return execution[-1]
    failed = [m.group("task") for m in _TASK_FAILED_LINE_RE.finditer(text)]
    return failed[-1] if failed else None


def _classify_gradle_task_name(task):
    if not task:
        return None
    low = task.lower()
    if "javawithjavac" in low or ("compile" in low and "java" in low):
        return "javac"
    if "manifest" in low:
        return "manifest"
    if any(x in low for x in ("duplicateclasses", "checkdebugaarmetadata", "checkreleaseaarmetadata")):
        return "dependency"
    if (
        any(x in low for x in ("resource", "resources", "aapt", "rfile"))
        and any(x in low for x in ("merge", "process", "compile", "parse", "generate", "link"))
    ):
        return "resource"
    return None


def classify_gradle_compile_failure(text):
    """
    Return resource, javac, manifest, dependency, or other for a failed Gradle run.

    v18 rule: classify the *terminal failed task* first.  Only fall back to
    diagnostic text if Gradle did not identify a failed task.  In particular,
    real .java diagnostics beat generic resource phrases, because javac cannot
    run until its Android resource prerequisites for that invocation have
    completed.
    """
    text = text or ""
    low = text.lower()

    failed_task = _gradle_failed_task(text)
    task_kind = _classify_gradle_task_name(failed_task)
    if task_kind:
        return task_kind

    # A source diagnostic proves javac actually emitted diagnostics.  Do this
    # BEFORE broad AAPT marker matching so an unrelated earlier resource phrase
    # cannot hijack a Java compilation failure.
    if _JAVAC_DIAGNOSTIC_RE.search(text):
        return "javac"
    javac_markers = (
        "cannot find symbol",
        "package does not exist",
        "method does not override or implement a method from a supertype",
        "incompatible types:",
        "class, interface, enum, or record expected",
        "reached end of file while parsing",
        "initializers not allowed in interfaces",
        "<identifier> expected",
        "';' expected",
        "not a statement",
        "illegal start of expression",
    )
    if any(x in low for x in javac_markers):
        return "javac"

    if (
        "manifest merger failed" in low
        or "processdebugmainmanifest failed" in low
        or "processreleasemainmanifest failed" in low
    ):
        return "manifest"

    dependency_markers = (
        "could not resolve all files for configuration",
        "could not resolve all dependencies",
        "could not find ",
        "duplicate class ",
        "failed to transform ",
    )
    if any(x in low for x in dependency_markers):
        return "dependency"

    resource_markers = (
        "android resource compilation failed",
        "android resource linking failed",
        "resource compilation failed",
        "resource linking failed",
        "failed linking references",
        "aapt2 aapt2-",
        "aapt: error:",
        "can not add resource",
        "cannot add resource",
        "to resource table",
    )
    if _RESOURCE_FAILURE_TASK_RE.search(text) or any(x in low for x in resource_markers):
        return "resource"

    # A started javac task plus an otherwise-unclassified failure is still more
    # plausibly a compiler failure than a resource failure at this point.
    if _TASK_STARTED_LINE_RE.search(text):
        return "javac"

    return "other"

def _extract_javac_diagnostics(text):
    """Keep the useful compiler portion in a small sidecar log without parsing it as AAPT2."""
    lines = (text or "").splitlines()
    keep = []
    for i, line in enumerate(lines):
        if _JAVAC_DIAGNOSTIC_RE.search(line) or any(
            marker in line.lower()
            for marker in (
                "cannot find symbol", "package does not exist", "incompatible types:",
                "method does not override", "error:", "symbol:", "location:"
            )
        ):
            lo = max(0, i - 1)
            hi = min(len(lines), i + 4)
            keep.extend(lines[lo:hi])
    # Preserve order while removing repeated context lines.
    seen = set()
    ordered = []
    for line in keep:
        if line not in seen:
            seen.add(line)
            ordered.append(line)
    return "\n".join(ordered) + ("\n" if ordered else "")


def parse_aapt_diagnostics(text):
    out = []
    for raw in (text or "").splitlines():
        m = AAPT_LOCATION_RE.match(raw.strip())
        if not m:
            continue
        msg = m.group("message").strip()
        if msg.lower().startswith("error:"):
            msg = msg[6:].strip()
        diagnostic_file = m.group("file")
        # AAPT2 and javac both use file:line: message formatting.  Never feed
        # Java/Kotlin compiler diagnostics into the resource repair subsystem.
        if Path(diagnostic_file).suffix.lower() in {".java", ".kt", ".kts", ".groovy"}:
            continue
        d = {
            "file": diagnostic_file,
            "line": int(m.group("line")),
            "column": int(m.group("column")) if m.group("column") else None,
            "message": msg,
            "raw": raw,
        }
        dm = AAPT_DUPLICATE_RE.search(msg)
        if dm:
            d["duplicate_resource"] = dm.group(1)
        um = AAPT_UNKNOWN_TAG_RE.search(msg)
        if um:
            d["unknown_tag"] = um.group(1).lstrip(":")
        out.append(d)
    return out


def _path_under(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except Exception:
        return False


def _matching_element_at_line(tree, line, duplicate_resource=None, unknown_tag=None):
    candidates = [e for e in tree.iter() if getattr(e, "sourceline", None) == line]
    if duplicate_resource and "/" in duplicate_resource:
        typ, name = duplicate_resource.split("/", 1)
        for e in candidates:
            tag = _xml_local_name(e.tag)
            etype = e.get("type") if tag == "item" else tag
            if etype == typ and e.get("name") == name:
                return e
            if typ == "attr" and tag == "attr" and e.get("name") == name:
                return e
    if unknown_tag:
        for e in candidates:
            if _xml_local_name(e.tag) == unknown_tag:
                return e
    # Prefer the deepest element when several start on a minified line.
    if candidates:
        return max(candidates, key=lambda e: len(list(e.iterancestors())))
    return None


def repair_source_from_aapt_errors(diagnostics, res_root, analysis_dir):
    """
    Apply only line-addressable, structurally safe repairs to SOURCE resources.
    Never edit build/intermediates here.
    """
    changed = False
    audit = []
    if not _require_lxml("line-aware AAPT2 repair"):
        return False, audit
    res_root = Path(res_root)
    for d in diagnostics:
        f = Path(d["file"])
        if not f.exists() or not _path_under(f, res_root):
            continue
        try:
            tree = LET.parse(str(f), _lxml_parser(remove_comments=True))
        except Exception as e:
            audit.append({"action": "repair-parse-failed", "file": str(f), "error": str(e)})
            continue
        el = _matching_element_at_line(
            tree,
            d["line"],
            d.get("duplicate_resource"),
            d.get("unknown_tag"),
        )
        if el is None:
            continue
        parent = el.getparent()
        ptag = _xml_local_name(parent.tag) if parent is not None else ""
        tag = _xml_local_name(el.tag)

        if d.get("duplicate_resource"):
            # This is the corrected/safer version of cleantree.py: use the exact
            # source file named by AAPT2 and don't blindly remove all nodes sharing
            # a line. Preserve styleable membership for nested attrs.
            if tag == "attr" and ptag == "declare-styleable":
                keep_name = el.get("name")
                for ch in list(el):
                    el.remove(ch)
                el.attrib.clear()
                el.set("name", keep_name)
                el.text = None
                action = "aapt-duplicate-attr-definition-to-reference"
            elif parent is not None:
                parent.remove(el)
                action = "aapt-duplicate-element-removed"
            else:
                continue
            _write_lxml_tree(tree, f, res_root, analysis_dir)
            changed = True
            audit.append({
                "action": action,
                "file": str(f),
                "line": d["line"],
                "resource": d.get("duplicate_resource"),
                "message": d["message"],
            })
            continue

        if d.get("unknown_tag"):
            # enum/flag are perfectly legal under attr (including attr under
            # declare-styleable). Only remove an unknown tag when AAPT2 points to
            # it as a DIRECT child of <resources>; nested nodes are diagnostic-only.
            if parent is not None and ptag == "resources":
                parent.remove(el)
                _write_lxml_tree(tree, f, res_root, analysis_dir)
                changed = True
                audit.append({
                    "action": "aapt-unknown-top-level-tag-removed",
                    "file": str(f),
                    "line": d["line"],
                    "tag": tag,
                    "message": d["message"],
                })
            else:
                audit.append({
                    "action": "aapt-unknown-nested-tag-left-intact",
                    "file": str(f),
                    "line": d["line"],
                    "tag": tag,
                    "parent": ptag,
                    "message": d["message"],
                })
    return changed, audit


def _attempt_recover_xml(path: Path):
    """Recovery-parse an XML file that normal lxml parsing rejected."""
    if LET is None:
        return None, ["lxml unavailable; cannot attempt recovery parse"]
    notes = []
    try:
        parser = LET.XMLParser(recover=True, remove_comments=False, huge_tree=True)
        tree = LET.parse(str(path), parser)
        root = tree.getroot()
        if root is None:
            notes.append("recovery parse produced no root")
            return None, notes
        notes.append("recovery parse succeeded")
        return tree, notes
    except Exception as exc:
        notes.append(f"recovery parse failed: {exc}")
        return None, notes


AAPT_MISSING_ANDROID_RE = re.compile(
    r"resource\s+(android:[\w/]+)\s+not\s+found", re.I
)


def stub_missing_android_references(diagnostics, res_root, analysis_dir):
    """
    Replace references to android: resources the current platform jar does not
    expose with @null.  aapt2 itself falls back this way for missing internal
    references; this makes the same choice explicitly and durably.
    """
    changed = False
    audit: list[dict] = []
    if LET is None:
        return changed, audit
    res_root = Path(res_root)
    missing = {
        m.group(1)
        for m in (AAPT_MISSING_ANDROID_RE.search(d.get("message", "")) for d in diagnostics)
        if m
    }
    if not missing:
        return changed, audit
    for xf in sorted(res_root.rglob("*.xml")):
        try:
            raw = xf.read_text(encoding="utf-8")
        except OSError:
            continue
        updated = raw
        for ref in missing:
            updated = re.sub(
                re.escape("@" + ref) + r"(?![A-Za-z0-9_.])",
                "@null",
                updated,
            )
        if updated != raw:
            _resource_backup(xf, res_root, analysis_dir)
            xf.write_text(updated, encoding="utf-8")
            changed = True
            audit.append({
                "action": "stubbed-missing-android-reference",
                "file": str(xf),
                "references": sorted(missing),
            })
    if audit:
        analysis_dir = Path(analysis_dir)
        analysis_dir.mkdir(parents=True, exist_ok=True)
        rp = analysis_dir / "resource-repair.json"
        existing = []
        if rp.exists():
            try:
                existing = json.loads(rp.read_text())
            except Exception:
                existing = []
        rp.write_text(json.dumps(existing + audit, indent=2, sort_keys=True))
        log(f"Stubbed {len(missing)} missing android: reference(s) with @null")
    return changed, audit

def _write_preflight_manifest(analysis_dir, package_name="apk2project.preflight"):
    """Minimal manifest so `aapt2 link` has something to attach resources to."""
    analysis_dir = Path(analysis_dir)
    analysis_dir.mkdir(parents=True, exist_ok=True)
    mf = analysis_dir / "aapt2-preflight-manifest.xml"
    if not mf.exists():
        mf.write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
            f'    package="{package_name}">\n'
            '  <uses-sdk android:minSdkVersion="21"/>\n'
            '  <application/>\n'
            '</manifest>\n'
        )
    return mf


def resolve_android_jar_from_project(project_root, api):
    """Read local.properties written by configure_project_sdk and return android.jar."""
    lp = Path(project_root) / "local.properties"
    if not lp.is_file():
        return None
    for line in lp.read_text().splitlines():
        line = line.strip()
        if not line.startswith("sdk.dir="):
            continue
        sdk_dir = Path(line.split("=", 1)[1].strip())
        jar = sdk_dir / "platforms" / f"android-{int(api)}" / "android.jar"
        if jar.is_file() and zipfile.is_zipfile(jar):
            return jar
    return None


def run_aapt2_resource_preflight(res_root, analysis_dir, attempts=4, api=None,
                                 android_jar=None, framework_apk=None):
    """
    Compile-only native resource preflight.

    `aapt2 compile` catches malformed XML, illegal resource names, and other
    source-level resource problems cheaply.  Linking is deliberately left to
    Gradle, because only Gradle has the complete resource universe from all AAR
    dependencies.
    """
    aapt2 = shutil.which("aapt2")
    analysis_dir = Path(analysis_dir)
    analysis_dir.mkdir(parents=True, exist_ok=True)
    if not aapt2:
        warn("aapt2 not found; skipping native resource preflight")
        return True, []
    res_root = Path(res_root)
    if not res_root.exists():
        return True, []

    # Resolve framework-res lazily if the caller didn't already.
    if framework_apk is None and api is not None:
        framework_apk = find_apktool_framework(api)
    if framework_apk is not None and not zipfile.is_zipfile(framework_apk):
        warn(f"apktool framework-res is not a valid zip: {framework_apk}; ignoring")
        framework_apk = None

    all_audit: list[dict] = []
    log_chunks: list[str] = []
    out_zip = analysis_dir / "aapt2-source-preflight.zip"

    # ---------------------------------------------------------------- compile
    compile_ok = False
    for attempt in range(1, max(1, attempts) + 1):
        out_zip.unlink(missing_ok=True)
        log(f"AAPT2 compile preflight attempt {attempt}/{attempts}")
        # NOTE: no -I here; `aapt2 compile` does not accept it.
        p = run([aapt2, "compile", "--dir", res_root, "-o", out_zip],
                check=False, capture=True)
        text = p.stdout or ""
        log_chunks.append(f"===== compile attempt {attempt} rc={p.returncode} =====\n{text}\n")
        if p.returncode == 0 and out_zip.exists():
            compile_ok = True
            break

        diagnostics = parse_aapt_diagnostics(text)
        changed, audit = repair_source_from_aapt_errors(diagnostics, res_root, analysis_dir)
        all_audit.extend(audit)
        changed2, audit2 = stub_missing_android_references(diagnostics, res_root, analysis_dir)
        all_audit.extend(audit2)
        changed = changed or changed2

        if not changed:
            recovered_any = False
            for d in diagnostics:
                f = Path(d["file"])
                if not f.exists() or f.suffix.lower() != ".xml":
                    continue
                tree, notes = _attempt_recover_xml(f)
                if tree is None:
                    continue
                _write_lxml_tree(tree, f, res_root, analysis_dir)
                all_audit.append({
                    "action": "xml-recovered",
                    "file": str(f),
                    "notes": notes,
                })
                recovered_any = True
            changed = recovered_any
            if not changed:
                break

        sanitize_apktool_synthetic_resources(res_root, analysis_dir)
        normalize_value_resources(res_root, analysis_dir)

    if not compile_ok:
        (analysis_dir / "aapt2-source-preflight.log").write_text("".join(log_chunks))
        (analysis_dir / "aapt2-source-repairs.json").write_text(
            json.dumps(all_audit, indent=2, sort_keys=True))
        return False, all_audit

    # v18: stop after source compilation.  Standalone `aapt2 link` does not see
    # the resources contributed by Gradle AAR dependencies, so it generates
    # false "no definition for declared symbol" errors (for example AppCompat
    # attrs).  Gradle's own resource pipeline is the authoritative link check.
    (analysis_dir / "aapt2-source-preflight.log").write_text("".join(log_chunks))
    (analysis_dir / "aapt2-source-repairs.json").write_text(
        json.dumps(all_audit, indent=2, sort_keys=True))
    return True, all_audit


def artifact_resources(path, artifact_type):
    """Return resource keys physically supplied by a selected AAR."""
    path = Path(path)
    if artifact_type != "aar" or not path.exists():
        return set()
    out = set()
    try:
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if not n.startswith("res/") or n.endswith("/"):
                    continue
                parts = n.split("/")
                if len(parts) < 3:
                    continue
                typ = parts[1].split("-", 1)[0]
                if typ != "values":
                    out.add((typ, Path(parts[-1]).stem))
                    continue
                if not n.endswith(".xml"):
                    continue
                try:
                    root = ET.fromstring(z.read(n))
                except Exception:
                    continue
                for el in list(root):
                    name = el.attrib.get("name")
                    tag = el.tag.rsplit("}", 1)[-1]
                    if name:
                        rt = el.attrib.get("type") if tag == "item" else tag
                        if rt and rt != "declare-styleable":
                            out.add((rt, name))
                    if tag == "declare-styleable":
                        for ch in list(el):
                            if ch.tag.rsplit("}", 1)[-1] == "attr" and ch.attrib.get("name"):
                                out.add(("attr", ch.attrib["name"]))
    except Exception as e:
        detail(f"AAR resource scan failed for {path}: {e}", 2)
    return out


def selected_library_resource_keys(selected):
    keys = set()
    for sel in selected:
        keys |= artifact_resources(Path(sel["file"]), sel["type"])
    return keys


def reconcile_selected_aar_attrs(res_root, analysis_dir, selected):
    """
    Proactively remove decoded attr *definitions* that are physically supplied
    by selected AARs.  App overrides of ordinary colors/strings/drawables remain
    untouched; attrs are special because defining the same attr twice is exactly
    the AAPT2 failure seen in reconstructed APKs.

    Inside <declare-styleable>, keep membership by converting a defining attr to
    a reference: <attr name="foo"/>.
    """
    if not _require_lxml("proactive selected-AAR attr reconciliation"):
        return []
    res_root = Path(res_root)
    analysis_dir = Path(analysis_dir)
    owners = collections.defaultdict(set)
    for sel in selected:
        gav = ":".join(sel.get("gav", ()))
        for typ, name in artifact_resources(Path(sel["file"]), sel["type"]):
            if typ == "attr" and name and not name.startswith("android:"):
                owners[name].add(gav)
    if not owners:
        return []

    audit = []
    changed_files = 0
    for values_dir in sorted(p for p in res_root.glob("values*") if p.is_dir()):
        for xf in sorted(values_dir.glob("*.xml")):
            try:
                tree = LET.parse(str(xf), _lxml_parser(remove_comments=True))
            except Exception:
                continue
            root = tree.getroot()
            file_changed = False
            for el in list(root):
                tag = _xml_local_name(el.tag)
                if tag == "attr" and el.get("name") in owners:
                    name = el.get("name")
                    root.remove(el)
                    file_changed = True
                    audit.append({
                        "action": "removed-decoded-top-level-attr-owned-by-aar",
                        "configuration": values_dir.name,
                        "name": name,
                        "file": str(xf),
                        "line": el.sourceline,
                        "owners": sorted(owners[name]),
                    })
                    continue
                if tag != "declare-styleable":
                    continue
                for ch in list(el):
                    if _xml_local_name(ch.tag) != "attr":
                        continue
                    name = ch.get("name")
                    if name not in owners or not _attr_is_definition(ch):
                        continue
                    for sub in list(ch):
                        ch.remove(sub)
                    ch.attrib.clear()
                    ch.set("name", name)
                    ch.text = None
                    file_changed = True
                    audit.append({
                        "action": "converted-decoded-styleable-attr-to-aar-reference",
                        "configuration": values_dir.name,
                        "styleable": el.get("name"),
                        "name": name,
                        "file": str(xf),
                        "line": ch.sourceline,
                        "owners": sorted(owners[name]),
                    })
            if file_changed:
                _write_lxml_tree(tree, xf, res_root, analysis_dir)
                changed_files += 1

    if audit:
        analysis_dir.mkdir(parents=True, exist_ok=True)
        (analysis_dir / "selected-aar-attr-reconciliation.json").write_text(
            json.dumps(audit, indent=2, sort_keys=True)
        )
        log(
            f"Proactively reconciled {len(audit)} decoded attr definition(s) "
            f"owned by selected AARs across {changed_files} file(s)"
        )
    return audit


def _remove_app_resource_key(res_root, analysis_dir, config, key):
    """Remove one decoded app copy only when a selected AAR is known to supply it."""
    if not _require_lxml("targeted library-resource collision repair"):
        return False, []
    typ, name = key
    values_dir = Path(res_root) / config
    if not values_dir.exists():
        return False, []
    changed = False
    audit = []
    for xf in sorted(values_dir.glob("*.xml")):
        try:
            tree = LET.parse(str(xf), _lxml_parser(remove_comments=True))
        except Exception:
            continue
        root = tree.getroot()
        file_changed = False
        for el in list(root):
            tag = _xml_local_name(el.tag)
            etype = el.get("type") if tag == "item" else tag
            if etype == typ and el.get("name") == name:
                root.remove(el)
                file_changed = changed = True
                audit.append({
                    "action": "removed-app-copy-supplied-by-selected-aar",
                    "configuration": config,
                    "type": typ,
                    "name": name,
                    "file": str(xf),
                    "line": el.sourceline,
                })
                continue
            if typ == "attr" and tag == "declare-styleable":
                for ch in list(el):
                    if _xml_local_name(ch.tag) == "attr" and ch.get("name") == name and _attr_is_definition(ch):
                        for sub in list(ch):
                            ch.remove(sub)
                        ch.attrib.clear()
                        ch.set("name", name)
                        ch.text = None
                        file_changed = changed = True
                        audit.append({
                            "action": "converted-app-styleable-attr-definition-to-aar-reference",
                            "configuration": config,
                            "type": typ,
                            "name": name,
                            "file": str(xf),
                            "line": ch.sourceline,
                        })
        if file_changed:
            _write_lxml_tree(tree, xf, res_root, analysis_dir)
    return changed, audit



def _resource_config_from_diagnostic_path(path):
    """Extract values/values-vXX/... configuration from a resource file path."""
    parts = Path(path).parts
    for part in reversed(parts[:-1] if parts else parts):
        if part == "values" or part.startswith("values-"):
            return part
    return "values"


def repair_external_library_collisions_from_gradle_output(out, analysis_dir, gradle_output):
    """
    Repair duplicate resources reported directly against dependency resources.

    This is intentionally independent of `selected`: Gradle may pull transitive
    AARs (androidx.core, play-services-base, etc.) that were never selected by the
    dependency resolver itself.  When AAPT2 says an external dependency resource
    duplicates a resource already in the reconstructed app, the APK-decoded app
    tree is the flattened copy.  Remove/convert that durable app copy and let the
    real AAR own the definition.
    """
    out = Path(out)
    analysis_dir = Path(analysis_dir)
    res_root = out / "app/src/main/res"
    changed = False
    audit = []

    for d in parse_aapt_diagnostics(gradle_output):
        dup = d.get("duplicate_resource")
        if not dup or "/" not in dup:
            continue

        raw_file = d.get("file") or ""
        f = Path(raw_file)
        # Diagnostics pointing into app/src/main/res are handled by the normal
        # source repair pass. Here we only trust external dependency resources.
        if _path_under(f, res_root):
            continue

        normalized = raw_file.replace("\\", "/")
        looks_external_resource = (
            "/.gradle/caches/" in normalized
            or "/transforms/" in normalized
            or "/caches/modules-2/" in normalized
        ) and "/res/" in normalized
        if not looks_external_resource:
            continue

        key = tuple(dup.split("/", 1))
        config = _resource_config_from_diagnostic_path(raw_file)
        c, a = _remove_app_resource_key(res_root, analysis_dir, config, key)
        if c:
            for rec in a:
                rec["external_owner_file"] = raw_file
                rec["external_owner_line"] = d.get("line")
                rec["source"] = "gradle-aapt-duplicate-diagnostic"
            changed = True
            audit.extend(a)
        else:
            audit.append({
                "action": "external-library-duplicate-no-app-definition-found",
                "configuration": config,
                "resource": dup,
                "external_owner_file": raw_file,
                "external_owner_line": d.get("line"),
                "message": d.get("message"),
            })

    if audit:
        rp = analysis_dir / "resource-repair.json"
        existing = []
        if rp.exists():
            try:
                existing = json.loads(rp.read_text())
            except Exception:
                existing = []
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(json.dumps(existing + audit, indent=2, sort_keys=True))

    if changed:
        shutil.rmtree(out / "app/build/intermediates", ignore_errors=True)
        normalize_value_resources(res_root, analysis_dir)
        log("Removed reconstructed resource definitions now owned by transitive/direct AARs")

    return changed, audit


def _merged_values_files(out, gradle_output="", deep_scan=False):
    """
    Return merged values XML files worth probing with standalone aapt2.

    v17 always appended every merged values file in the project, so one
    resource failure could launch hundreds of aapt2 processes.  v18 first uses
    only files explicitly named by Gradle/AAPT2.  Exhaustive scanning is kept
    as an opt-in diagnostic escape hatch, not the normal repair path.
    """
    paths = set()
    for d in parse_aapt_diagnostics(gradle_output):
        p = Path(d["file"])
        if p.exists() and p.suffix.lower() == ".xml" and "merged.dir" in str(p):
            paths.add(p.resolve())
    if paths or not deep_scan:
        return sorted(paths)

    base = Path(out) / "app/build/intermediates"
    if base.exists():
        for p in base.glob("**/mergeDebugResources/merged.dir/values*/values*.xml"):
            if p.is_file():
                paths.add(p.resolve())
    return sorted(paths)


def diagnose_and_repair_merged_resources(out, analysis_dir, selected, gradle_output, deep_scan=False):
    """
    Use generated merged XML only as a DIAGNOSTIC. Never patch it in place.
    Repairs are applied to app/src/main/res, which is the durable input Gradle owns.
    """
    aapt2 = shutil.which("aapt2")
    if not aapt2:
        return False, []
    out = Path(out)
    res_root = out / "app/src/main/res"
    analysis_dir = Path(analysis_dir)
    lib_keys = selected_library_resource_keys(selected)
    changed, audit = repair_external_library_collisions_from_gradle_output(
        out, analysis_dir, gradle_output
    )
    logs = []
    merged_files = _merged_values_files(out, gradle_output, deep_scan=deep_scan)
    for i, vf in enumerate(merged_files, 1):
        tmp = analysis_dir / f"aapt2-merged-{i}"
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True, exist_ok=True)
        p = run([aapt2, "compile", "-v", "-o", tmp, vf], check=False, capture=True)
        text = p.stdout or ""
        logs.append(f"===== {vf} rc={p.returncode} =====\n{text}\n")
        diagnostics = parse_aapt_diagnostics(text)
        config = vf.parent.name
        for d in diagnostics:
            dup = d.get("duplicate_resource")
            if not dup or "/" not in dup:
                continue
            key = tuple(dup.split("/", 1))
            if key in lib_keys:
                c, a = _remove_app_resource_key(res_root, analysis_dir, config, key)
                changed |= c
                audit.extend(a)
            else:
                audit.append({
                    "action": "merged-duplicate-not-known-from-selected-aar",
                    "configuration": config,
                    "resource": dup,
                    "merged_file": str(vf),
                    "line": d["line"],
                    "message": d["message"],
                })

        # Record ancestry for unknown tags. In particular, enum/flag under attr
        # are legal and must not be blindly deleted.
        if LET is not None:
            try:
                tree = LET.parse(str(vf), _lxml_parser(remove_comments=False))
                for d in diagnostics:
                    if not d.get("unknown_tag"):
                        continue
                    el = _matching_element_at_line(tree, d["line"], unknown_tag=d["unknown_tag"])
                    if el is None:
                        continue
                    parent = el.getparent()
                    grand = parent.getparent() if parent is not None else None
                    audit.append({
                        "action": "merged-unknown-tag-diagnostic",
                        "merged_file": str(vf),
                        "line": d["line"],
                        "tag": _xml_local_name(el.tag),
                        "parent": _xml_local_name(parent.tag) if parent is not None else None,
                        "grandparent": _xml_local_name(grand.tag) if grand is not None else None,
                        "message": d["message"],
                    })
            except Exception as e:
                audit.append({"action": "merged-diagnostic-parse-failed", "file": str(vf), "error": str(e)})

    if logs:
        with (analysis_dir / "aapt2-merged-diagnostics.log").open("a") as f:
            f.write("".join(logs))
    if audit:
        existing = []
        rp = analysis_dir / "resource-repair.json"
        if rp.exists():
            try:
                existing = json.loads(rp.read_text())
            except Exception:
                existing = []
        rp.write_text(json.dumps(existing + audit, indent=2, sort_keys=True))
    if changed:
        # Never try to preserve/lie about Gradle intermediates with mtimes. Modern
        # Gradle snapshots contents. Delete intermediates so the next attempt is
        # rebuilt cleanly from the repaired durable source tree.
        shutil.rmtree(out / "app/build/intermediates", ignore_errors=True)
        normalize_value_resources(res_root, analysis_dir)
    return changed, audit

# ---------------------------------------------------------------------------
# v11: installed-SDK selection, quieter Termux Gradle, tracing/diagnostics
# ---------------------------------------------------------------------------

SCRIPT_VERSION = "bulletproof-v28.4-standalone-dexlib"

PROCESS_CYAN = "\033[96m"
PROCESS_RESET = "\033[0m"
SHOW_GRADLE_NOISE = False

_GRADLE_NOISE_FRAGMENTS = (
    "To honour the JVM settings for this build a single-use Daemon process will be forked.",
    "To honor the JVM settings for this build a single-use Daemon process will be forked.",
    "Warning: Unable to set daemon's environment variables to match the client because:",
    "There is no native integration with this operating environment.",
    "If the daemon was started with a significantly different environment from the client",
    "relies on environment variables, you may experience unexpected behavior.",
    "Daemon will be stopped at the end of the build",
    "Deprecated Gradle features were used in this build",
    "You can use '--warning-mode all' to show the individual deprecation warnings",
    "command_line_warnings in the Gradle documentation",
    "gradle_daemon.html#sec:disabling_the_daemon in the Gradle documentation",
)


def _is_gradle_command(argv):
    if not argv:
        return False
    names = {Path(str(x)).name for x in argv}
    return bool(names & {"gradle", "gradlew", "gradlew.bat", "build-termux.sh"})


def _suppress_gradle_live_line(line):
    if SHOW_GRADLE_NOISE:
        return False
    text = line.strip()
    if not text:
        return False
    return any(fragment in text for fragment in _GRADLE_NOISE_FRAGMENTS)


def _process_stderr_write_v11(text, *, gradle=False):
    if not text:
        return
    if gradle and _suppress_gradle_live_line(text):
        return
    if os.environ.get("NO_COLOR") is not None:
        sys.stderr.write(text)
    else:
        sys.stderr.write(PROCESS_CYAN + text + PROCESS_RESET)
    sys.stderr.flush()


def run(cmd, cwd=None, check=True, capture=False, env=None):
    """Run a subprocess, teeing complete output while filtering only live Gradle noise."""
    argv = list(map(str, cmd))
    log("$ " + " ".join(argv))
    is_gradle = _is_gradle_command(argv)
    p = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    chunks = []
    assert p.stdout is not None
    for line in p.stdout:
        if capture:
            chunks.append(line)
        _process_stderr_write_v11(line, gradle=is_gradle)
    p.stdout.close()
    rc = p.wait()
    stdout = "".join(chunks) if capture else None
    result = subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr=None)
    if check and rc:
        raise subprocess.CalledProcessError(rc, argv, output=stdout)
    return result


def _aapt2_accepts_android_jar(android_jar):
    """Actually use android.jar as an AAPT2 -I include; ZIP validity alone is insufficient."""
    android_jar = Path(android_jar)
    aapt2 = shutil.which("aapt2")
    if not _valid_android_jar(android_jar):
        return False, "not a readable ZIP/JAR"
    if not aapt2:
        return True, "aapt2 unavailable; ZIP/JAR validation only"
    try:
        with tempfile.TemporaryDirectory(prefix="apk2project-sdk-probe-") as td:
            td = Path(td)
            manifest = td / "AndroidManifest.xml"
            output = td / "probe.apk"
            manifest.write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="apk2project.sdkprobe"><application/></manifest>\n'
            )
            proc = subprocess.run(
                [aapt2, "link", "-o", str(output), "--manifest", str(manifest), "-I", str(android_jar)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                errors="replace",
                timeout=30,
            )
            detail_text = (proc.stdout or "").strip()
            if proc.returncode == 0:
                return True, "aapt2 link include probe succeeded"
            return False, detail_text[-2000:] or f"aapt2 exited {proc.returncode}"
    except Exception as exc:
        return False, f"aapt2 include probe failed: {exc}"


_ANDROID_PLATFORM_DIR_RE = re.compile(r"^android-(\d+)(?:-.+)?$")
_ANDROID_REPOSITORY_BASE = "https://dl.google.com/android/repository/"
_ANDROID_REPOSITORY_INDEXES = (
    "repository2-3.xml",
    "repository2-2.xml",
    "repository2-1.xml",
)


def inspect_installed_android_platforms(sdk, source_kind="installed"):
    """Inventory SDK platforms and prove whether the active native AAPT2 can consume them."""
    if not sdk:
        return []
    sdk = Path(sdk)
    platforms_dir = sdk / "platforms"
    if not platforms_dir.is_dir():
        return []
    records = []
    for directory in sorted(platforms_dir.iterdir(), key=lambda x: x.name):
        if not directory.is_dir():
            continue
        match = _ANDROID_PLATFORM_DIR_RE.match(directory.name)
        if not match:
            continue
        api = int(match.group(1))
        jar = directory / "android.jar"
        aapt_ok, probe = _aapt2_accepts_android_jar(jar)
        record = {
            "api": api,
            "path": str(directory),
            "sdk_root": str(sdk),
            "source_kind": source_kind,
            "canonical_name": directory.name == f"android-{api}",
            "android_jar": str(jar),
            "android_jar_valid_zip": _valid_android_jar(jar),
            "aapt2_include_ok": bool(aapt_ok),
            "aapt2_probe": probe,
            "build_prop": (directory / "build.prop").is_file(),
            "source_properties": (directory / "source.properties").is_file(),
            "package_xml": (directory / "package.xml").is_file(),
        }
        record["usable"] = bool(record["aapt2_include_ok"] and record["build_prop"])
        record["score"] = (
            (1000 if record["usable"] else 0)
            + (100 if record["canonical_name"] else 0)
            + (40 if record["source_properties"] else 0)
            + (20 if record["package_xml"] else 0)
        )
        records.append(record)
    return records


def _xml_local_name(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else tag


def _child_text_by_local_name(parent, name):
    for child in list(parent):
        if _xml_local_name(child.tag) == name:
            return (child.text or "").strip()
    return None


def _descendant_by_local_name(parent, name):
    for child in parent.iter():
        if _xml_local_name(child.tag) == name:
            return child
    return None


def _revision_tuple(remote_package):
    rev = None
    for child in list(remote_package):
        if _xml_local_name(child.tag) == "revision":
            rev = child
            break
    if rev is None:
        return (0, 0, 0)
    values = []
    for name in ("major", "minor", "micro"):
        text = _child_text_by_local_name(rev, name)
        try:
            values.append(int(text or 0))
        except ValueError:
            values.append(0)
    return tuple(values)


def _parse_android_repository_platforms(xml_bytes, index_url):
    """Return stable Android SDK platform archives keyed by API level."""
    root = ET.fromstring(xml_bytes)
    candidates = {}
    for remote in root.iter():
        if _xml_local_name(remote.tag) != "remotePackage":
            continue
        package_path = (remote.attrib.get("path") or "").replace("/", ";")
        match = re.fullmatch(r"platforms;android-(\d+)", package_path)
        if not match:
            continue
        api = int(match.group(1))
        channel = None
        for child in list(remote):
            if _xml_local_name(child.tag) == "channelRef":
                channel = child.attrib.get("ref")
                break
        # channel-0 is stable. No channelRef also occurs in older repository XML.
        if channel not in (None, "channel-0"):
            continue
        revision = _revision_tuple(remote)
        archives = _descendant_by_local_name(remote, "archives")
        if archives is None:
            continue
        choices = []
        for archive in list(archives):
            if _xml_local_name(archive.tag) != "archive":
                continue
            host_os = _child_text_by_local_name(archive, "host-os")
            # SDK platform packages are architecture independent. Prefer a universal
            # archive, but accepting a Linux-tagged one is safe because it contains
            # platform data rather than host executables.
            if host_os and host_os.lower() not in ("linux",):
                continue
            complete = None
            for child in list(archive):
                if _xml_local_name(child.tag) == "complete":
                    complete = child
                    break
            if complete is None:
                continue
            url = _child_text_by_local_name(complete, "url")
            if not url:
                continue
            checksum = None
            checksum_type = None
            size = None
            for child in list(complete):
                lname = _xml_local_name(child.tag)
                if lname == "checksum":
                    checksum = (child.text or "").strip() or None
                    checksum_type = child.attrib.get("type")
                elif lname == "size":
                    try:
                        size = int((child.text or "0").strip())
                    except ValueError:
                        size = None
            choices.append({
                "api": api,
                "revision": revision,
                "url": urllib.parse.urljoin(_ANDROID_REPOSITORY_BASE, url),
                "relative_url": url,
                "checksum": checksum,
                "checksum_type": checksum_type,
                "size": size,
                "host_os": host_os,
                "index_url": index_url,
            })
        if not choices:
            continue
        # Universal archive first, then newest revision.
        choices.sort(key=lambda x: (x["host_os"] is None, x["revision"]), reverse=True)
        chosen = choices[0]
        prior = candidates.get(api)
        if prior is None or chosen["revision"] > prior["revision"]:
            candidates[api] = chosen
    return candidates


def _load_android_repository_catalog(cache_dir):
    """Download/cache Google's SDK repository metadata and list stable platforms."""
    cache_dir = Path(cache_dir)
    meta_dir = cache_dir / ".repository-metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    errors = []
    for name in _ANDROID_REPOSITORY_INDEXES:
        url = urllib.parse.urljoin(_ANDROID_REPOSITORY_BASE, name)
        local = meta_dir / name
        data = None
        # Cached metadata is useful when a later run is offline.
        if local.exists() and local.stat().st_size:
            try:
                data = local.read_bytes()
                parsed = _parse_android_repository_platforms(data, url)
                if parsed:
                    return parsed, {"index_url": url, "cache": str(local), "cached": True}
            except Exception as exc:
                errors.append(f"cached {name}: {exc}")
        try:
            log(f"Fetching Android SDK repository index: {url}")
            data = get(url, timeout=45)
            local.write_bytes(data)
            parsed = _parse_android_repository_platforms(data, url)
            if parsed:
                return parsed, {"index_url": url, "cache": str(local), "cached": False}
            errors.append(f"{name}: no stable platform packages found")
        except Exception as exc:
            errors.append(f"{name}: {exc}")
    raise RuntimeError("Could not load Android SDK repository metadata: " + "; ".join(errors))


def _verify_archive_checksum(path, expected, checksum_type=None):
    if not expected:
        return True, None
    expected = expected.strip().lower()
    alg = (checksum_type or "").lower().replace("-", "")
    if not alg:
        alg = "sha256" if len(expected) == 64 else "sha1" if len(expected) == 40 else ""
    if alg not in ("sha1", "sha256"):
        return True, f"unsupported checksum type {checksum_type!r}; archive retained"
    h = hashlib.new(alg)
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    actual = h.hexdigest().lower()
    return actual == expected, f"{alg}:{actual}"


def _safe_extract_zip(zip_path, destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            target = (destination / info.filename).resolve()
            if target != destination and destination not in target.parents:
                raise RuntimeError(f"unsafe path in SDK platform ZIP: {info.filename}")
        zf.extractall(destination)


def _install_official_android_platform(api, cache_sdk_root, catalog, analysis_dir):
    """Install one architecture-independent official platform package into our cache."""
    api = int(api)
    cache_sdk_root = Path(cache_sdk_root).expanduser().resolve()
    platform = cache_sdk_root / "platforms" / f"android-{api}"
    archive_info = catalog.get(api)
    if archive_info is None:
        return None, {"api": api, "status": "not-in-repository"}

    # Reuse an already valid cached platform first.
    existing = [r for r in inspect_installed_android_platforms(cache_sdk_root, "google-cache") if r["api"] == api]
    if existing:
        existing.sort(key=lambda r: (r["score"], r["path"]), reverse=True)
        if existing[0]["usable"]:
            return existing[0], {"api": api, "status": "cached-usable", "record": existing[0]}

    downloads = cache_sdk_root / ".downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    archive_name = Path(urllib.parse.urlparse(archive_info["url"]).path).name or f"platform-{api}.zip"
    archive = downloads / archive_name
    try:
        if not archive.exists() or not archive.stat().st_size:
            log(f"Downloading official Android SDK Platform {api}: {archive_info['url']}")
            archive.write_bytes(get(archive_info["url"], timeout=120))
        ok, checksum_detail = _verify_archive_checksum(
            archive, archive_info.get("checksum"), archive_info.get("checksum_type")
        )
        if not ok:
            archive.unlink(missing_ok=True)
            raise RuntimeError(f"checksum mismatch for {archive_name} ({checksum_detail})")
        if archive_info.get("size") and archive.stat().st_size != int(archive_info["size"]):
            warn(
                f"SDK platform archive size differs from repository metadata: "
                f"{archive.stat().st_size} != {archive_info['size']}"
            )
        with tempfile.TemporaryDirectory(prefix=f"apk2project-platform-{api}-") as td:
            td = Path(td)
            _safe_extract_zip(archive, td)
            donors = []
            for jar in td.rglob("android.jar"):
                parent = jar.parent
                if parent.name == f"android-{api}" or (parent / "build.prop").exists():
                    donors.append(parent)
            if not donors:
                raise RuntimeError(f"downloaded SDK Platform {api} ZIP contains no usable android.jar")
            donors.sort(key=lambda d: (d.name == f"android-{api}", (d / "build.prop").exists()), reverse=True)
            donor = donors[0]
            if platform.exists():
                shutil.rmtree(platform)
            platform.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(donor, platform)
        records = [r for r in inspect_installed_android_platforms(cache_sdk_root, "google-cache") if r["api"] == api]
        records.sort(key=lambda r: (r["score"], r["path"]), reverse=True)
        record = records[0] if records else None
        detail = {
            "api": api,
            "status": "downloaded",
            "archive": str(archive),
            "archive_info": archive_info,
            "record": record,
        }
        analysis_dir = Path(analysis_dir)
        analysis_dir.mkdir(parents=True, exist_ok=True)
        (analysis_dir / f"android-platform-{api}-download.json").write_text(
            json.dumps(detail, indent=2, sort_keys=True, default=list)
        )
        return record, detail
    except Exception as exc:
        return None, {
            "api": api,
            "status": "download-failed",
            "archive_info": archive_info,
            "error": str(exc),
        }


def _pick_usable_platform(records, target_sdk, allow_below=False):
    usable = [r for r in records if r.get("usable")]
    at_or_above = [r for r in usable if int(r["api"]) >= int(target_sdk)]
    if at_or_above:
        api = min(int(r["api"]) for r in at_or_above)
        choices = [r for r in at_or_above if int(r["api"]) == api]
        choices.sort(key=lambda r: (r["score"], r["path"]), reverse=True)
        return choices[0]
    if allow_below and usable:
        api = max(int(r["api"]) for r in usable)
        choices = [r for r in usable if int(r["api"]) == api]
        choices.sort(key=lambda r: (r["score"], r["path"]), reverse=True)
        return choices[0]
    return None


def _try_refresh_termux_aapt2():
    """Upgrade just aapt2 from the configured Termux repository, then report versions."""
    before = _safe_command_output([shutil.which("aapt2") or "aapt2", "version"])
    pkg = shutil.which("pkg")
    if not pkg:
        return {"attempted": False, "before": before, "reason": "pkg not found"}
    try:
        log("No installed platform works with the current AAPT2; refreshing the Termux aapt2 package")
        run([pkg, "install", "-y", "aapt2"], check=True)
        after = _safe_command_output([shutil.which("aapt2") or "aapt2", "version"])
        return {"attempted": True, "ok": True, "before": before, "after": after}
    except Exception as exc:
        after = _safe_command_output([shutil.which("aapt2") or "aapt2", "version"])
        return {"attempted": True, "ok": False, "before": before, "after": after, "error": str(exc)}


def select_rebuild_compile_sdk(
    info, sdk, analysis_dir, *, require_installed=False, policy="auto",
    platform_cache_dir=None, refresh_aapt2=False, max_download_fallbacks=4,
):
    """
    Select a platform that the *actual Termux AAPT2* can consume.

    auto      : prefer installed >= target, refresh aapt2 when requested, then
                download official platform data; finally allow compileSdk below
                targetSdk when that is the newest AAPT2-compatible platform.
    installed : never download; choose the best installed usable platform, even
                if it is below targetSdk.
    download  : prefer Google's official cached/downloaded platform packages.

    compileSdk is build-time only. targetSdk is preserved independently.
    """
    analysis_dir = Path(analysis_dir)
    analysis_dir.mkdir(parents=True, exist_ok=True)
    target_sdk = int(info.get("target_sdk") or 35)
    original_compile = info.get("compile_sdk")
    platform_cache_dir = Path(
        platform_cache_dir or (Path.home() / ".cache/apk2project/android-sdk")
    ).expanduser().resolve()
    attempts = []

    installed_records = inspect_installed_android_platforms(sdk, "termux-installed") if sdk else []
    selected = None

    if policy in ("auto", "installed"):
        selected = _pick_usable_platform(installed_records, target_sdk, allow_below=False)

    refresh_result = None
    if selected is None and refresh_aapt2 and policy in ("auto", "installed"):
        refresh_result = _try_refresh_termux_aapt2()
        installed_records = inspect_installed_android_platforms(sdk, "termux-installed") if sdk else []
        selected = _pick_usable_platform(installed_records, target_sdk, allow_below=False)

    catalog_meta = None
    catalog = None
    downloaded_records = []
    if selected is None and policy in ("auto", "download"):
        try:
            catalog, catalog_meta = _load_android_repository_catalog(platform_cache_dir)
            available = sorted(catalog)
            # First try the smallest official platform >= targetSdk.
            higher = [api for api in available if api >= target_sdk]
            first = min(higher) if higher else None
            apis_to_try = []
            if first is not None:
                apis_to_try.append(first)
            # If AAPT2 itself is too old for the modern resources.arsc format,
            # walk downward to the newest compatible platform. Limit downloads.
            lower = sorted((api for api in available if api < target_sdk), reverse=True)
            apis_to_try.extend(lower[:max(0, int(max_download_fallbacks))])
            seen = set()
            for api in apis_to_try:
                if api in seen:
                    continue
                seen.add(api)
                record, attempt = _install_official_android_platform(
                    api, platform_cache_dir, catalog, analysis_dir
                )
                attempts.append(attempt)
                if record:
                    downloaded_records.append(record)
                    if record.get("usable"):
                        selected = record
                        break
        except Exception as exc:
            attempts.append({"status": "repository-error", "error": str(exc)})

    # installed-only mode, or download failure: a lower installed platform is
    # still preferable to pretending an unusable newer platform works.
    if selected is None and policy in ("auto", "installed"):
        selected = _pick_usable_platform(installed_records, target_sdk, allow_below=True)

    all_records = installed_records + downloaded_records
    audit = {
        "target_sdk": target_sdk,
        "original_apk_compile_sdk": original_compile,
        "original_compile_sdk_is_informational": True,
        "policy": policy,
        "source_sdk": str(sdk) if sdk else None,
        "platform_cache_sdk": str(platform_cache_dir),
        "aapt2": shutil.which("aapt2"),
        "aapt2_version": _safe_command_output([shutil.which("aapt2") or "aapt2", "version"]),
        "aapt2_refresh": refresh_result,
        "repository": catalog_meta,
        "download_attempts": attempts,
        "candidates": all_records,
        "selected": selected,
    }
    (analysis_dir / "compile-sdk-selection.json").write_text(
        json.dumps(audit, indent=2, sort_keys=True, default=list)
    )

    if selected:
        chosen_api = int(selected["api"])
        chosen_sdk = Path(selected["sdk_root"])
        if chosen_api < target_sdk:
            warn(
                f"AAPT2 cannot consume any available platform >= targetSdk {target_sdk}; "
                f"rebuilding with compileSdk {chosen_api} while preserving targetSdk {target_sdk}. "
                f"If Java/resources require newer APIs, dependency/code compatibility may need another downgrade pass."
            )
        elif original_compile and int(original_compile) != chosen_api:
            log(
                f"APK was originally compiled with API {original_compile}; rebuilding with "
                f"validated API {chosen_api} (targetSdk {target_sdk})"
            )
        else:
            log(f"Selected validated Android SDK Platform {chosen_api} for rebuild")
        return chosen_api, chosen_sdk

    if require_installed:
        usable = sorted({r["api"] for r in all_records if r.get("usable")})
        if usable:
            die(
                f"No selected Android SDK platform could satisfy policy {policy!r}. "
                f"AAPT2-compatible APIs seen: {usable}. See {analysis_dir/'compile-sdk-selection.json'}"
            )
        die(
            "No Android SDK platform passed the active AAPT2 include probe, including any automatic "
            f"download attempts. See {analysis_dir/'compile-sdk-selection.json'}"
        )

    fallback = max(35, target_sdk)
    warn(
        f"No platform was validated while only generating project files; declaring compileSdk {fallback}. "
        f"A compile run will require a usable platform."
    )
    return fallback, sdk


def bootstrap_android_sdk(compile_sdk=None):
    """Install/locate native Termux build tools; platform data may be downloaded separately."""
    required = ["openjdk-21", "gradle", "aapt2"]
    optional = ["aapt", "aidl", "apksigner", "d8", "zipalign"]
    for package in required:
        executable = {"openjdk-21": "java", "gradle": "gradle", "aapt2": "aapt2"}[package]
        if not shutil.which(executable):
            try:
                termux_pkg_install([package])
            except subprocess.CalledProcessError:
                warn(f"Could not install required package {package}")
    for package in optional:
        if not shutil.which(package):
            try:
                termux_pkg_install([package])
            except subprocess.CalledProcessError:
                detail(f"Optional Termux package unavailable: {package}", 1)
    sdk = find_android_sdk()
    if sdk is None:
        warn(
            "No existing Android SDK platforms/ directory found; automatic platform download can create "
            "a private SDK platform cache if --sdk-platform-policy is auto/download"
        )
    return sdk

def _best_platform_for_api(sdk, api):
    records = [r for r in inspect_installed_android_platforms(sdk) if r["api"] == int(api) and r["usable"]]
    if not records:
        return None
    records.sort(key=lambda r: (r["score"], r["path"]), reverse=True)
    return records[0]


def prepare_project_android_sdk(root, sdk, compile_sdk):
    """Canonicalize a validated installed Termux platform without inventing one."""
    root = Path(root)
    sdk = Path(sdk).resolve()
    api = int(compile_sdk)
    chosen = _best_platform_for_api(sdk, api)
    if chosen is None:
        die(f"Android SDK Platform {api} is not usable under {sdk}; inspect analysis/compile-sdk-selection.json")
    donor = Path(chosen["path"])
    shim = root / ".apk2project-android-sdk"
    platform = shim / "platforms" / f"android-{api}"
    if platform.exists() or platform.is_symlink():
        if platform.is_dir() and not platform.is_symlink():
            shutil.rmtree(platform)
        else:
            platform.unlink()
    platform.mkdir(parents=True, exist_ok=True)

    exposed = {}
    metadata_names = {"source.properties", "package.xml", "build.prop", "sdk.properties"}
    for src in sorted(donor.iterdir(), key=lambda x: x.name):
        dst = platform / src.name
        if src.name in metadata_names and src.is_file():
            shutil.copy2(src, dst)
            exposed[src.name] = "copy"
        else:
            exposed[src.name] = _link_or_copy(src, dst)

    sp = platform / "source.properties"
    if not sp.exists():
        sp.write_text(
            f"Pkg.Desc=Android SDK Platform {api}\nPkg.Revision=1\n"
            f"AndroidVersion.ApiLevel={api}\nAndroidVersion.IsBaseSdk=true\n"
        )
        exposed["source.properties"] = "synthesized"

    ok, problems = _verify_shim_platform(platform, api)
    aapt_ok, aapt_probe = _aapt2_accepts_android_jar(platform / "android.jar")
    if not aapt_ok:
        problems.append("shim android.jar failed AAPT2 include probe")
    if not ok or problems:
        die(f"Could not construct a usable project-local Android SDK Platform {api}: " + ", ".join(problems))

    # AGP treats the path in local.properties/ANDROID_SDK_ROOT as the complete
    # Android SDK.  Since this project-local shim becomes that SDK root, expose
    # SDK-level packages from the real Termux SDK as well as the selected
    # platform.  In particular, Gradle must be able to see licenses/ and
    # build-tools/ here or it may try to reinstall Build Tools and then report
    # that their licenses have not been accepted.
    for name in (
        "licenses",
        "build-tools",
        "platform-tools",
        "cmdline-tools",
        "tools",
    ):
        src_entry = sdk / name
        dst_entry = shim / name

        if not src_entry.exists():
            continue

        # Recreate these links/copies on every run so a stale project-local shim
        # cannot keep pointing at an old SDK tree.
        if dst_entry.is_symlink() or dst_entry.exists():
            try:
                if dst_entry.is_dir() and not dst_entry.is_symlink():
                    shutil.rmtree(dst_entry)
                else:
                    dst_entry.unlink()
            except OSError as exc:
                warn(f"Could not refresh SDK shim entry {dst_entry}: {exc}")
                continue

        try:
            dst_entry.symlink_to(
                src_entry.resolve(),
                target_is_directory=src_entry.is_dir(),
            )
            exposed[name] = f"symlink -> {src_entry.resolve()}"
        except OSError:
            try:
                if src_entry.is_dir():
                    shutil.copytree(src_entry, dst_entry, dirs_exist_ok=True, symlinks=True)
                else:
                    shutil.copy2(src_entry, dst_entry)
                exposed[name] = f"copy <- {src_entry}"
            except OSError as exc:
                warn(f"Could not expose SDK shim entry {name}: {exc}")

    analysis = root / "analysis"
    analysis.mkdir(parents=True, exist_ok=True)
    (analysis / "android-sdk-shim.json").write_text(json.dumps({
        "api": api,
        "source_sdk": str(sdk),
        "chosen_installed_platform": chosen,
        "shim_sdk": str(shim),
        "shim_platform": str(platform),
        "aapt2_probe": aapt_probe,
        "exposed_entries": exposed,
    }, indent=2, sort_keys=True))
    log(f"Using validated project-local Android SDK shim for API {api}: {shim}")
    return shim


def _safe_command_output(argv):
    try:
        proc = subprocess.run(list(map(str, argv)), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, errors="replace", timeout=15)
        return (proc.stdout or "").strip()
    except Exception as exc:
        return f"<failed: {exc}>"


def write_gradle_environment_audit(root, sdk, compile_sdk):
    root = Path(root)
    analysis = root / "analysis"
    analysis.mkdir(parents=True, exist_ok=True)
    keys = ("JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "GRADLE_HOME", "GRADLE_USER_HOME",
            "GRADLE_OPTS", "JAVA_OPTS", "JAVA_TOOL_OPTIONS", "PATH", "PREFIX")
    payload = {
        "selected_compile_sdk": int(compile_sdk),
        "configured_sdk": str(sdk) if sdk else None,
        "environment": {k: os.environ.get(k) for k in keys},
        "effective_wrapper_environment": {
            "ANDROID_HOME": str(sdk) if sdk else None,
            "ANDROID_SDK_ROOT": str(sdk) if sdk else None,
            "JAVA_HOME": str(Path(shutil.which("java")).resolve().parent.parent) if shutil.which("java") else os.environ.get("JAVA_HOME"),
            "GRADLE_OPTS_append": "-Xmx4g -Dfile.encoding=UTF-8",
        },
        "executables": {name: shutil.which(name) for name in ("java", "javac", "gradle", "aapt2", "jfr", "jcmd", "strace")},
        "java_version": _safe_command_output([shutil.which("java") or "java", "-version"]),
        "gradle_version": _safe_command_output([shutil.which("gradle") or "gradle", "--version"]),
        "aapt2_version": _safe_command_output([shutil.which("aapt2") or "aapt2", "version"]),
        "note": (
            "The Termux 'no native integration' daemon warning is an environment-sync limitation, not proof that a "
            "specific variable was lost. v11 avoids org.gradle.jvmargs in gradle.properties so --no-daemon can remain "
            "in the launcher JVM when possible."
        ),
    }
    (analysis / "gradle-environment.json").write_text(json.dumps(payload, indent=2, sort_keys=True))


def write_gradle(root, info, coords):
    ns = info["package"] if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", info["package"]) else "reconstructed.apk"
    min_sdk = int(info.get("min_sdk") or 21)
    target_sdk = int(info.get("target_sdk") or 35)
    compile_sdk = int(info.get("rebuild_compile_sdk") or max(35, target_sdk))
    (root / "settings.gradle").write_text(
        'pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }\n'
        'dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories { google(); mavenCentral() } }\n'
        'rootProject.name="reconstructed"\ninclude(":app")\n'
    )
    (root / "build.gradle").write_text('plugins { id "com.android.application" version "8.10.1" apply false }\n')
    (root / "gradle.properties").write_text(
        "org.gradle.daemon=false\nandroid.useAndroidX=true\nandroid.nonTransitiveRClass=false\nandroid.nonFinalResIds=false\n"
    )
    deps = "\n".join(f'  implementation "{g}:{a}:{v}"' for g, a, v in sorted(coords))
    packaging = ""
    if info.get("extract_native_libs") is not None:
        legacy = "true" if info["extract_native_libs"] else "false"
        packaging = f"  packaging {{ jniLibs {{ useLegacyPackaging = {legacy} }} }}\n"
    gradle_text = f'''plugins {{ id "com.android.application" }}
android {{
  namespace "{ns}"
  compileSdk {compile_sdk}
  defaultConfig {{ applicationId "{ns}"; minSdk {min_sdk}; targetSdk {target_sdk} }}
{packaging}}}
dependencies {{
{deps}
}}

// Decompiled source is expected to contain noisy unchecked/varargs/deprecation
// constructs. Keep javac diagnostics error-only so the repair engine and terminal
// are not buried in warnings.
tasks.withType(org.gradle.api.tasks.compile.JavaCompile).configureEach {{
  options.warnings = false
  options.compilerArgs.addAll(["-Xlint:none", "-nowarn", "-Xmaxerrs", "10000"])
}}

// apk2project helper: expose the *entire* resolved runtime artifact graph.
// v24 only inventoried transitive AARs, so ordinary JAR dependencies such as
// Guava could remain as broken decompiled Java even though Gradle already had
// the authoritative binary on its classpath.
tasks.register("apk2projectResolvedArtifacts") {{
  doLast {{
    def artifacts = configurations.debugRuntimeClasspath.incoming.artifactView {{ }}.artifacts.artifacts
    artifacts
      .findAll {{
        def n = it.file.name.toLowerCase()
        n.endsWith(".aar") || n.endsWith(".jar")
      }}
      .sort {{ a, b -> a.id.displayName <=> b.id.displayName }}
      .each {{ a ->
        def cid = a.id.componentIdentifier
        if (cid instanceof org.gradle.api.artifacts.component.ModuleComponentIdentifier) {{
          def n = a.file.name.toLowerCase()
          def typ = n.endsWith(".aar") ? "aar" : "jar"
          println("APK2PROJECT_ARTIFACT\t${{cid.group}}\t${{cid.module}}\t${{cid.version}}\t${{typ}}\t${{a.file.absolutePath}}")
        }}
      }}
  }}
}}

// Resource reconciliation still needs the AAR-only view.
tasks.register("apk2projectResolvedAars") {{
  doLast {{
    def artifacts = configurations.debugRuntimeClasspath.incoming.artifactView {{ }}.artifacts.artifacts
    artifacts
      .findAll {{ it.file.name.toLowerCase().endsWith(".aar") }}
      .sort {{ a, b -> a.id.displayName <=> b.id.displayName }}
      .each {{ a ->
        def cid = a.id.componentIdentifier
        if (cid instanceof org.gradle.api.artifacts.component.ModuleComponentIdentifier) {{
          println("APK2PROJECT_AAR\t${{cid.group}}\t${{cid.module}}\t${{cid.version}}\t${{a.file.absolutePath}}")
        }}
      }}
  }}
}}

'''
    (root / "app/build.gradle").write_text(gradle_text)


def configure_project_sdk(root, sdk, compile_sdk=35):
    root = Path(root)
    sdk = prepare_project_android_sdk(root, sdk, compile_sdk)
    (root / "local.properties").write_text(f"sdk.dir={sdk}\n")
    aapt2 = shutil.which("aapt2")
    gp = root / "gradle.properties"
    txt = gp.read_text() if gp.exists() else ""
    if aapt2 and "android.aapt2FromMavenOverride=" not in txt:
        txt += f"\nandroid.aapt2FromMavenOverride={aapt2}\n"
        gp.write_text(txt)
    java = shutil.which("java") or "java"
    java_home = Path(java).resolve().parent.parent if java != "java" else Path(os.environ.get("JAVA_HOME", ""))
    build = root / "build-termux.sh"
    build.write_text(f'''#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
export ANDROID_HOME={shlex_quote(str(sdk))}
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export JAVA_HOME={shlex_quote(str(java_home))}
export PATH="$JAVA_HOME/bin:$PATH"
export GRADLE_OPTS="${{GRADLE_OPTS:-}} -Xmx4g -Dfile.encoding=UTF-8"
cd "$(dirname "$0")"
if (( $# == 0 )); then
  set -- build
fi

# Add Termux-friendly Gradle defaults only when the caller did not already
# specify them.  The Python driver also supplies --console=plain, so blindly
# adding it here produced Gradle's "Multiple arguments were provided for
# command-line option '--console'" error.
gradle_prefix=()
has_console=0
has_daemon_mode=0
for arg in "$@"; do
  case "$arg" in
    --console|--console=*) has_console=1 ;;
    --daemon|--no-daemon) has_daemon_mode=1 ;;
  esac
done
(( has_daemon_mode )) || gradle_prefix+=(--no-daemon)
(( has_console )) || gradle_prefix+=(--console=plain)

exec gradle "${{gradle_prefix[@]}}" "$@"
''')
    build.chmod(build.stat().st_mode | stat.S_IXUSR)
    write_gradle_environment_audit(root, sdk, compile_sdk)
    log(f"Wrote {root/'local.properties'}")
    log(f"Wrote runnable {build}")


def _gradle_cli_options(z):
    options = ["--console=plain", f"--warning-mode={z.gradle_warning_mode}"]
    if z.gradle_log_level == "info":
        options.append("--info")
    elif z.gradle_log_level == "debug":
        options.append("--debug")
    elif z.gradle_log_level == "quiet":
        options.append("--quiet")
    return options


def _gradle_execution_env(z, analysis_dir):
    env = os.environ.copy()
    if z.trace_gradle:
        jfr = Path(analysis_dir) / "gradle.jfr"
        jfr.parent.mkdir(parents=True, exist_ok=True)
        opts = env.get("GRADLE_OPTS", "")
        jfr_opt = f"-XX:StartFlightRecording=name=apk2project,settings=profile,filename={jfr},dumponexit=true"
        env["GRADLE_OPTS"] = (opts + " " + jfr_opt).strip()
    return env


def _maybe_wrap_strace(cmd, z, analysis_dir):
    if not z.trace_processes:
        return cmd
    strace = shutil.which("strace")
    if not strace:
        warn("--trace-processes requested but strace is not installed; pkg install strace")
        return cmd
    output = Path(analysis_dir) / "process-exec.log"
    return [strace, "-f", "-e", "trace=execve", "-s", "8192", "-o", str(output), *cmd]


def _extract_deprecation_context(text, context=2):
    lines = (text or "").splitlines()
    selected = set()
    for i, line in enumerate(lines):
        low = line.lower()
        if ("deprecated" in low or "deprecation" in low) and "deprecated gradle features were used in this build" not in low:
            for j in range(max(0, i-context), min(len(lines), i+context+1)):
                selected.add(j)
    if not selected:
        return ""
    out, previous = [], None
    for i in sorted(selected):
        if previous is not None and i > previous + 1:
            out.append("--")
        out.append(lines[i])
        previous = i
    return "\n".join(out) + "\n"


def _summarize_jfr(analysis_dir):
    analysis_dir = Path(analysis_dir)
    jfr_path = analysis_dir / "gradle.jfr"
    jfr = shutil.which("jfr")
    if not jfr_path.is_file() or not jfr:
        return
    try:
        proc = subprocess.run([jfr, "print", "--events", "ExecutionSample", str(jfr_path)],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, errors="replace", timeout=120)
        raw = proc.stdout or ""
        lines, hits = raw.splitlines(), []
        needles = ("com.android.", "org.gradle.", "aaptcompiler", "ResourceCompiler", "LinkApplicationAndroidResourcesTask")
        for i, line in enumerate(lines):
            if any(n in line for n in needles):
                lo, hi = max(0, i-6), min(len(lines), i+7)
                hits.extend(lines[lo:hi])
                hits.append("--")
        (analysis_dir / "gradle-jfr-stacks.txt").write_text("\n".join(hits[:20000]) + ("\n" if hits else ""))
    except Exception as exc:
        (analysis_dir / "gradle-jfr-stacks.txt").write_text(f"Could not summarize JFR recording: {exc}\n")


# ---------------------------------------------------------------------------
# v19: task-aware javac + quiet/library-aware targeted decompilation
# ---------------------------------------------------------------------------

_JAVAC_ERROR_FILE_RE = re.compile(
    r"(?m)^(?P<file>[^\n]*?\.java):(?P<line>\d+)(?::\d+)?:\s*error:\s*(?P<message>.*)$"
)
_JADX_INVALID_REGISTER_RE = re.compile(r"(?m)^\s*\?\?\s+(?:r\d+|[A-Za-z_$][\w$]*)\b")


def _jadx_help_text(jadx_command):
    """Return JADX help without polluting normal build output."""
    try:
        proc = subprocess.run(
            [*map(str, jadx_command), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=30,
        )
        return proc.stdout or ""
    except Exception:
        return ""


def _jadx_compile_oriented_args(jadx_command, mode="auto"):
    """Use only conservative switches supported by the installed JADX."""
    help_text = _jadx_help_text(jadx_command)
    # JADX 1.5.6 (the bootstrapped version) supports all of these.  Filtering by
    # --help keeps a system-installed older/newer JADX from failing just because
    # one optional conservative switch changed name.
    candidates = [
        ("--decompilation-mode", ["--decompilation-mode", mode]),
        ("--no-inline-methods", ["--no-inline-methods"]),
        ("--no-inline-anonymous", ["--no-inline-anonymous"]),
        ("--no-inline-kotlin-lambda", ["--no-inline-kotlin-lambda"]),
        ("--no-finally", ["--no-finally"]),
    ]
    if not help_text:
        # The bundled JADX is pinned, so these are safe there.  For an unknown
        # launcher whose help cannot be read, keep only the universally useful
        # mode switch rather than risking failure on optional flags.
        return ["--decompilation-mode", mode]
    out = []
    for flag, argv in candidates:
        if flag in help_text:
            out.extend(argv)
        else:
            detail(f"JADX does not advertise {flag}; skipping that optional conservative flag", 2)
    return out


def _jadx_deobf_map_args(jadx_command, map_path, mode="read-or-save"):
    """Ask JADX to persist/reuse its exact auto-generated JOBF rename map when supported.

    JOBF contains owner+descriptor scoped class/field/method aliases and is therefore
    much stronger evidence for the APK shadow linker than reversing C####/m####/f####
    names heuristically.  Older/system JADX launchers that do not advertise these
    options simply fall back to the semantic/DEX linker.
    """
    if map_path is None:
        return []
    help_text = _jadx_help_text(jadx_command)
    if not help_text or "--deobf-cfg-file" not in help_text:
        return []
    map_path = Path(map_path)
    map_path.parent.mkdir(parents=True, exist_ok=True)
    out = ["--deobf-cfg-file", str(map_path)]
    if "--deobf-cfg-file-mode" in help_text:
        out += ["--deobf-cfg-file-mode", mode]
    return out


def _ensure_jadx_deobf_map(jadx_command, apk, map_path, scratch_root):
    """Best-effort one-time JOBF bootstrap for resumed projects created before v27.

    JADX can build its auto-rename table without emitting source/resources.  This lets a
    --keep-work project gain exact owner+descriptor aliases without replacing a single
    manually repaired Java file.  Failure is non-fatal: the DEX+javac linker remains.
    """
    map_path = Path(map_path)
    if map_path.is_file() and map_path.stat().st_size:
        return True
    help_text = _jadx_help_text(jadx_command)
    if "--deobf-cfg-file" not in help_text:
        return False
    scratch_root = Path(scratch_root)
    shutil.rmtree(scratch_root, ignore_errors=True)
    scratch_root.mkdir(parents=True, exist_ok=True)
    cmd = [*jadx_command, "--deobf", *_jadx_deobf_map_args(jadx_command, map_path, mode="overwrite")]
    if "--no-src" in help_text:
        cmd.append("--no-src")
    if "--no-res" in help_text:
        cmd.append("--no-res")
    cmd += ["--log-level", "warn", "-d", str(scratch_root), str(apk)]
    proc = _quiet_subprocess(cmd)
    try:
        (scratch_root.parent / "jadx-map-probe.log").write_text(proc.stdout or "")
    except OSError:
        pass
    shutil.rmtree(scratch_root, ignore_errors=True)
    if map_path.is_file() and map_path.stat().st_size:
        log(f"JADX exact rename map bootstrapped without replacing source: {map_path}")
        return True
    detail("JADX JOBF bootstrap produced no map; continuing with DEX+javac alias inference", 1)
    return False


def _primary_fqcn_from_text(text, fallback_stem=None):
    pm = PRE.search(text or "")
    pkg = pm.group(1) if pm else ""
    tm = TRE.search(text or "")
    name = tm.group(1) if tm else fallback_stem
    if not name:
        return None
    return (pkg + "." + name).strip(".")


def _primary_fqcn_from_source(path):
    path = Path(path)
    try:
        return _primary_fqcn_from_text(path.read_text(errors="ignore"), path.stem)
    except OSError:
        return None


def prune_android_platform_sources(root, android_jar, mode="move"):
    """
    Remove decompiled android.* source files when the selected platform android.jar
    already supplies the same class.  Decompiled framework stubs are both needless
    and frequently invalid Java (for example interface static initializer blocks).
    """
    root = Path(root)
    java_root = root / "app/src/main/java"
    android_jar = Path(android_jar) if android_jar else None
    audit = []
    moved = []
    deleted = []
    if not java_root.exists() or not android_jar or not _valid_android_jar(android_jar):
        return audit, moved, deleted

    try:
        with zipfile.ZipFile(android_jar) as zf:
            jar_entries = set(zf.namelist())
    except (OSError, zipfile.BadZipFile):
        return audit, moved, deleted

    dest_root = root / "removed-platform-sources"
    for src in sorted((java_root / "android").rglob("*.java")) if (java_root / "android").exists() else []:
        try:
            rel = src.relative_to(java_root)
        except ValueError:
            continue
        class_entry = rel.with_suffix(".class").as_posix()
        if class_entry not in jar_entries:
            continue
        record = {
            "source": str(src),
            "class_entry": class_entry,
            "android_jar": str(android_jar),
            "action": mode,
            "reason": "selected android.jar already provides this android.* class",
        }
        if mode == "delete":
            src.unlink(missing_ok=True)
            deleted.append(rel.as_posix())
        elif mode == "move":
            dst = dest_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                dst.unlink()
            shutil.move(str(src), str(dst))
            record["destination"] = str(dst)
            moved.append(rel.as_posix())
        else:
            record["action"] = "report-only"
        audit.append(record)

    for d in sorted((java_root / "android").rglob("*"), reverse=True) if (java_root / "android").exists() else []:
        if d.is_dir():
            try:
                d.rmdir()
            except OSError:
                pass
    return audit, moved, deleted


def _artifact_display_name(entry):
    gav = entry.get("gav") if isinstance(entry, dict) else None
    if gav:
        return ":".join(map(str, gav))
    if isinstance(entry, dict) and entry.get("file"):
        return str(entry["file"])
    return "unknown-library"


def enrich_runtime_aars_with_classes(runtime_aars, tmp):
    """Attach class inventories to Gradle-resolved transitive AAR records.

    Direct selections already carry a class set from dependency discovery.  The
    Gradle runtime inventory historically did not, which meant transitive
    libraries (Material, AppCompat helpers, coroutines adapters, etc.) could
    survive source pruning and later confuse javac/JADX repair.
    """
    out = []
    for entry in runtime_aars or ():
        rec = dict(entry)
        if rec.get("classes"):
            out.append(rec)
            continue
        f = Path(rec.get("file") or "")
        try:
            rec["classes"] = classes_in(f, rec.get("type") or "aar", tmp) if f.is_file() else set()
        except Exception as exc:
            rec["classes"] = set()
            detail(f"Could not inventory classes for runtime AAR {f}: {exc}", 2)
        out.append(rec)
    return out


def build_library_class_owners(artifacts):
    """Map exact outer-class FQCNs to the resolved artifacts that provide them."""
    owners = collections.defaultdict(set)
    for entry in artifacts or ():
        owner = _artifact_display_name(entry)
        for cls in entry.get("classes", ()) if isinstance(entry, dict) else ():
            owners[normalize_binary_class(cls)].add(owner)
    return {k: sorted(v) for k, v in owners.items()}



_JAVAC_SOURCE_ERROR_RE = re.compile(
    r"(?m)^(?P<file>[^\n]*?\.java):(?P<line>\d+)(?::\d+)?:\s*error:\s*(?P<message>.*)$"
)


def javac_error_source_classes(text, java_root):
    """Return Counter(FQCN -> visible javac errors) for source files in the project."""
    java_root = Path(java_root).resolve()
    out = collections.Counter()
    for m in _JAVAC_SOURCE_ERROR_RE.finditer(text or ""):
        p = Path(m.group("file"))
        try:
            p = p.resolve() if p.is_absolute() else (java_root / p).resolve()
            p.relative_to(java_root)
        except Exception:
            continue
        if not p.is_file():
            continue
        try:
            t = p.read_text(errors="ignore")
        except OSError:
            continue
        pm = PRE.search(t); tm = TRE.search(t)
        if not tm:
            continue
        pkg = pm.group(1) if pm else ""
        fq = (pkg + "." + tm.group(1)).strip(".")
        out[fq] += 1
    return out


def ensure_gradle_dependency(root, gav):
    """Insert one implementation dependency without rewriting the whole project."""
    root = Path(root)
    bg = root / "app/build.gradle"
    if not bg.is_file():
        return False
    notation = ":".join(gav)
    text = bg.read_text()
    if notation in text:
        return False
    marker = "dependencies {"
    at = text.find(marker)
    if at < 0:
        return False
    pos = at + len(marker)
    text = text[:pos] + f'\n  implementation "{notation}"  // apk2project v25 emergency binary-island promotion' + text[pos:]
    bg.write_text(text)
    return True


def discover_binary_artifact_for_error_sources(error_counts, existing_artifacts, cache, tmp,
                                                *, app_package=None, max_classes=12):
    """Find an authoritative Maven/Google binary for broken bundled source.

    This is a late, javac-driven dependency discovery pass. The ordinary resolver
    already considers bundled classes, but a huge source tree/query budget can still
    miss a library family. Here we search only classes *currently producing compiler
    errors*, download candidate artifacts, and require exact physical class coverage.
    A candidate covering multiple failing classes wins by a large margin.
    """
    if not error_counts:
        return None, []
    existing_classes = set()
    existing_gavs = set()
    for e in existing_artifacts or ():
        existing_gavs.add(tuple(e.get("gav", ())))
        existing_classes |= {normalize_binary_class(c) for c in e.get("classes", ())}

    targets = [fq for fq, _ in error_counts.most_common(max_classes)
               if fq not in existing_classes and not fq.startswith(PLATFORM)]
    if app_package:
        # Application-owned classes are not candidates merely because they fail.
        targets = [fq for fq in targets if not (fq == app_package or fq.startswith(app_package + "."))]
    if not targets:
        return None, []

    pool = set()
    evidence = []
    for fq in targets:
        # Persistent exact indexes first: no network if we've seen this library before.
        for _, gav, _ in package_index_candidates(fq):
            pool.add(tuple(gav)); evidence.append((fq, tuple(gav), "package-index"))
        if LOOKUP_CACHE is not None:
            for gav in LOOKUP_CACHE.owners_of(fq, limit=8):
                pool.add(tuple(gav)); evidence.append((fq, tuple(gav), "class-index"))
        gc = google_candidates(fq)
        for gav in gc[:12]:
            pool.add(tuple(gav)); evidence.append((fq, tuple(gav), "google-maven"))
        # Exact Maven Central search is expensive but this path only runs after javac
        # proves the source is broken, so a handful of focused lookups is worthwhile.
        for d in central_class(fq, rows=12):
            if d.get("g") and d.get("a") and (d.get("v") or d.get("latestVersion")):
                gav = (d["g"], d["a"], d.get("v") or d.get("latestVersion"))
                pool.add(gav); evidence.append((fq, gav, "central-exact-class"))

    candidates = []
    target_set = set(targets)
    for gav in list(pool)[:160]:
        gav = pin(tuple(gav))
        if gav in existing_gavs:
            continue
        health = validate_pom(gav)
        if not health.ok:
            continue
        p, typ, repo = artifact(*gav, cache)
        if not p:
            continue
        cls = classes_in(p, typ, tmp)
        covers = target_set & {normalize_binary_class(c) for c in cls}
        if not covers:
            continue
        weighted = sum(error_counts[c] for c in covers)
        pkg_score = sum(package_similarity(c, gav) for c in covers) / max(1, len(covers))
        # Multiple exact failing classes is near-conclusive ownership evidence.
        score = len(covers) * 10000 + weighted * 100 + pkg_score * 100
        candidates.append((score, gav, p, typ, repo, cls, covers, health.reason))

    if not candidates:
        return None, evidence
    candidates.sort(key=lambda x: x[0], reverse=True)
    score, gav, p, typ, repo, cls, covers, why = candidates[0]
    # Safe acceptance: either multiple currently failing classes are physically in
    # one artifact, or one class has very strong package/group agreement.
    pkg_agreement = sum(package_similarity(c, gav) for c in covers) / max(1, len(covers))
    if len(covers) < 2 and pkg_agreement < 0.80:
        return None, evidence
    rec = {
        "gav": tuple(gav), "file": str(p), "type": typ,
        "repo": repo, "classes": set(cls), "transitive": False,
        "emergency_binary_island": True,
        "covers_error_classes": sorted(covers),
        "discovery_score": score,
        "pom_reason": why,
    }
    return rec, evidence

def _quiet_subprocess(argv, cwd=None):
    """Capture a noisy diagnostic subprocess without streaming it to the terminal."""
    detail("$ " + " ".join(map(str, argv)), 2)
    return subprocess.run(
        list(map(str, argv)), cwd=cwd, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, errors="replace"
    )


def _jadx_warning_summary(output, fqcn):
    """Separate warnings that mention the requested class from unrelated DEX noise."""
    lines = (output or "").splitlines()
    target = []
    unrelated = []
    # JADX often emits a headline followed by an `in method: fqcn.method(...)`
    # line.  Preserve a small rolling block so that the headline is attributed to
    # the target if the subsequent context names the requested class.
    block = []
    for line in lines:
        if "WARN" in line or "ERROR" in line:
            if block:
                unrelated.extend(block)
            block = [line]
            continue
        if block:
            block.append(line)
            if fqcn and fqcn in line:
                target.extend(block)
                block = []
            elif len(block) >= 8:
                unrelated.extend(block)
                block = []
    if block:
        if any(fqcn in x for x in block) if fqcn else False:
            target.extend(block)
        else:
            unrelated.extend(block)
    return target, unrelated


def _targeted_candidate_invalid_reason(text):
    """Reject obvious non-Java emitted by a failed JADX restructuring pass."""
    if not (text or "").strip():
        return "empty targeted output"
    if _JADX_INVALID_REGISTER_RE.search(text):
        return "targeted output still contains JADX ?? register/type artifacts"
    if re.search(r"(?m)^\s*goto\s+L(?:_|\d|0x)", text):
        return "targeted output contains raw goto syntax"
    return None


def _javac_jadx_artifact_candidates(gradle_output, java_root):
    """Return malformed JADX source files actually named by javac diagnostics."""
    java_root = Path(java_root).resolve()
    candidates = []
    seen = set()
    for m in _JAVAC_ERROR_FILE_RE.finditer(gradle_output or ""):
        raw = m.group("file").strip()
        path = Path(raw)
        if not path.is_absolute():
            path = (java_root / path).resolve()
        else:
            path = path.resolve()
        try:
            path.relative_to(java_root)
        except ValueError:
            continue
        if path in seen or not path.is_file():
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        # The characteristic JADX invalid-type/register token from --show-bad-code.
        # Also catch the interface initializer artifact visible in framework stubs.
        artifact = bool(_JADX_INVALID_REGISTER_RE.search(text))
        if not artifact and "initializers not allowed in interfaces" in m.group("message").lower():
            artifact = "static {" in text or "static{" in text
        if artifact:
            seen.add(path)
            candidates.append(path)
    return candidates


def _candidate_java_file(single_output, scratch, original):
    single_output = Path(single_output)
    if single_output.is_file():
        return single_output
    scratch = Path(scratch)
    hits = list(scratch.rglob(Path(original).name))
    return hits[0] if hits else None


def targeted_jadx_javac_repair(
    gradle_output, java_root, jadx_command, apk, analysis_dir,
    no_deobf=False, library_class_owners=None, jadx_map=None,
    hybrid_binary_sources=None,
):
    """Repair only app-owned javac failures containing obvious JADX artifacts.

    Targeted JADX is intentionally silent on the terminal.  Its full output is
    retained per attempt, unrelated warnings are ignored, and exact classes
    supplied by resolved direct/transitive libraries are never re-decompiled.
    """
    java_root = Path(java_root)
    analysis_dir = Path(analysis_dir)
    library_class_owners = library_class_owners or {}
    hybrid_binary_rel = set()
    if hybrid_binary_sources:
        try:
            hbs = Path(hybrid_binary_sources)
            if hbs.is_file():
                hybrid_binary_rel = {
                    ln.strip().replace("\\", "/")
                    for ln in hbs.read_text(errors="ignore").splitlines()
                    if ln.strip()
                }
        except Exception:
            hybrid_binary_rel = set()
    candidates = _javac_jadx_artifact_candidates(gradle_output, java_root)
    audit = []
    changed = []
    audit_path = analysis_dir / "jadx-targeted-repair.json"
    if not candidates:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_text("[]\n")
        return changed, audit

    help_text = _jadx_help_text(jadx_command)
    if help_text and ("--single-class" not in help_text or "--single-class-output" not in help_text):
        warn("Installed JADX does not support targeted --single-class output; javac source repair skipped")
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_text(json.dumps([{"status": "skipped", "reason": "JADX lacks --single-class output"}], indent=2) + "\n")
        return changed, audit

    advertised_modes = ["auto"]
    if not help_text or "--decompilation-mode" in help_text:
        advertised_modes += ["restructure", "simple"]

    scratch_root = analysis_dir / "jadx-targeted-repair"
    backup_root = analysis_dir / "jadx-targeted-originals"
    scratch_root.mkdir(parents=True, exist_ok=True)
    backup_root.mkdir(parents=True, exist_ok=True)

    for index, src in enumerate(candidates, 1):
        original_text = src.read_text(errors="ignore")
        fqcn = _primary_fqcn_from_text(original_text, src.stem)
        rec = {"source": str(src), "class": fqcn, "status": "not-replaced", "attempts": []}
        if not fqcn:
            rec["reason"] = "could not determine primary class name"
            audit.append(rec)
            continue

        # Hybrid shadow ownership is stronger than targeted re-decompilation.  A
        # binary-owned source file is evidence for alias recovery only; replacing it
        # with another JADX rendering can reintroduce exactly the AndroidX/Material
        # source that the shadow boundary was created to keep away from javac.
        try:
            rel = src.resolve().relative_to(java_root.resolve()).as_posix()
        except Exception:
            rel = None
        if rel and rel in hybrid_binary_rel:
            rec["status"] = "skipped-hybrid-binary-owned"
            rec["reason"] = "APK hybrid shadow owns this class; source is alias evidence only"
            audit.append(rec)
            log(f"Skipping targeted JADX repair for hybrid binary-owned source {fqcn}")
            continue

        owners = library_class_owners.get(normalize_binary_class(fqcn), [])
        if owners:
            rec["status"] = "skipped-library-owned"
            rec["library_owners"] = owners
            rec["reason"] = "resolved library already provides this exact class; do not repair decompiled library source"
            audit.append(rec)
            log(f"Skipping targeted JADX repair for library-owned class {fqcn} ({' | '.join(owners)})")
            continue

        base = scratch_root / f"{index:03d}-{re.sub(r'[^A-Za-z0-9_.-]+', '_', fqcn)}"
        shutil.rmtree(base, ignore_errors=True)
        base.mkdir(parents=True, exist_ok=True)

        # Ordinary original names do not need global deobfuscation. JADX-generated
        # aliases such as p001a0.RunnableC0003a generally *do* require --deobf in
        # order for --single-class to resolve that alias, so enable it only there.
        need_deobf = (not no_deobf) and looks_like_jadx_alias(fqcn)
        rec["deobf_for_alias"] = bool(need_deobf)
        log(f"Targeted JADX repair: {fqcn}" + (" (alias resolution requires --deobf)" if need_deobf else ""))

        accepted_text = None
        accepted_candidate = None
        accepted_mode = None
        for mode in advertised_modes:
            scratch = base / mode
            scratch.mkdir(parents=True, exist_ok=True)
            single_output = scratch / src.name
            cmd = [
                *jadx_command,
                "--single-class", fqcn,
                "--single-class-output", single_output,
                *_jadx_compile_oriented_args(jadx_command, mode=mode),
                *(["--deobf"] if need_deobf else []),
                *(_jadx_deobf_map_args(jadx_command, jadx_map, mode="read") if need_deobf else []),
                # APK/DEX input is handled by JADX's dex-input plugin.  Do not
                # force java-convert.mode here: that plugin only converts
                # .class/.jar/.aar inputs to DEX and is irrelevant to APK DEX
                # decompilation.  Leaving it unset also keeps targeted and full
                # decompilation aligned with JADX's native APK path.
                # Keep WARN internally so we can tell whether the requested class
                # itself failed restructuring; _quiet_subprocess prevents unrelated
                # library warnings from flooding the user's terminal.
                "--log-level", "warn",
                apk,
            ]
            proc = _quiet_subprocess(cmd)
            jadx_output = proc.stdout or ""
            (scratch / "jadx.log").write_text(jadx_output)
            target_warn, unrelated_warn = _jadx_warning_summary(jadx_output, fqcn)
            attempt_rec = {
                "mode": mode,
                "returncode": proc.returncode,
                "log": str(scratch / "jadx.log"),
                "target_warning": bool(target_warn),
                "target_warning_excerpt": "\n".join(target_warn[-30:])[-6000:],
                "unrelated_warning_lines": len(unrelated_warn),
            }

            candidate = _candidate_java_file(single_output, scratch, src)
            if proc.returncode != 0 or candidate is None or not candidate.is_file():
                attempt_rec["result"] = "no-java-output"
                rec["attempts"].append(attempt_rec)
                continue

            candidate_text = candidate.read_text(errors="ignore")
            candidate_fqcn = _primary_fqcn_from_text(candidate_text, candidate.stem)
            invalid_reason = _targeted_candidate_invalid_reason(candidate_text)
            attempt_rec["candidate"] = str(candidate)
            attempt_rec["candidate_class"] = candidate_fqcn
            if candidate_fqcn != fqcn:
                attempt_rec["result"] = "rejected"
                attempt_rec["reason"] = f"primary class changed ({fqcn} -> {candidate_fqcn})"
            elif invalid_reason:
                attempt_rec["result"] = "rejected"
                attempt_rec["reason"] = invalid_reason
            else:
                attempt_rec["result"] = "accepted"
                accepted_text = candidate_text
                accepted_candidate = candidate
                accepted_mode = mode
                rec["attempts"].append(attempt_rec)
                break
            rec["attempts"].append(attempt_rec)

        if accepted_text is None:
            rec["reason"] = "no targeted JADX strategy produced cleaner Java"
            audit.append(rec)
            continue

        rel = src.resolve().relative_to(java_root.resolve())
        backup = backup_root / rel
        backup.parent.mkdir(parents=True, exist_ok=True)
        if not backup.exists():
            backup.write_text(original_text)
        src.write_text(accepted_text)
        rec["status"] = "replaced"
        rec["candidate"] = str(accepted_candidate)
        rec["accepted_mode"] = accepted_mode
        rec["backup"] = str(backup)
        changed.append(str(src))
        log(f"Targeted JADX repair replaced malformed source: {rel} (mode={accepted_mode})")
        audit.append(rec)

    previous = []
    if audit_path.exists():
        try:
            previous = json.loads(audit_path.read_text())
        except Exception:
            previous = []
    audit_path.write_text(json.dumps(previous + audit, indent=2, sort_keys=True))
    return changed, audit


# ---------------------------------------------------------------------------
# v26: Java hybrid compiler + APK ABI shadow JAR
# ---------------------------------------------------------------------------

_HYBRID_JAVA_EXPORTS = [
    "--add-exports", "jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED",
    "--add-exports", "jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED",
    "--add-exports", "jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED",
    "--add-exports", "jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED",
    "--add-exports", "jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED",
    "--add-exports", "java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED",
]

# v26.1 hard-binary preset for JADX's characteristic deobfuscation aliases.
# These are matched against the full source FQCN by the Java ownership engine.
_HYBRID_OBFUSCATED_BINARY_REGEXES = [
    r"(?:^|\.)p\d+[A-Za-z0-9_$]*(?:\.|$)",
    r"(?:^|[.$])(?:Abstract|Interface|Enum|Runnable|Callable|Comparator|Iterator|View|Dialog|Activity|Fragment|Service|Receiver|Adapter|Builder|Factory|Listener|Callback|Manager|Provider|Controller|Layout|Behavior|Exception|Error|Task|Thread)?C\d+[A-Za-z0-9_$]*(?:$|\$)",
]


def _hybrid_engine_sources():
    root = Path(__file__).resolve().parent / "java_engine"
    # The source/JADX ownership engine must stay independent of runtime DEX
    # tooling. DexHybridRebuilder is compiled lazily by hybrid_apk.py only after
    # the validated app javac boundary has succeeded and standalone dexlib2 has
    # been resolved. A missing/broken dexlib can therefore never collapse the
    # source/binary boundary or send quarantined library sources back to javac.
    return sorted(p for p in root.glob("*.java") if p.name != "DexHybridRebuilder.java")


def ensure_hybrid_java_engine(project_root):
    """Compile the JDK-internal Java helper against the user's own JDK.

    We intentionally do not ship precompiled class files: com.sun.tools.javac.* and
    the JDK-bundled ASM are implementation APIs, so compiling locally avoids a JDK
    build/version mismatch and makes the required --add-exports explicit/auditable.
    """
    sources = _hybrid_engine_sources()
    if not sources:
        raise FileNotFoundError("Java hybrid engine sources are missing")
    classes = Path(project_root) / "analysis/java-engine/classes"
    marker = classes / "apk2project/hybrid/HybridCompiler.class"
    newest_source = max(p.stat().st_mtime for p in sources)
    if marker.is_file() and marker.stat().st_mtime >= newest_source:
        return classes
    classes.mkdir(parents=True, exist_ok=True)
    javac = shutil.which("javac")
    if not javac:
        raise RuntimeError("javac is required for --hybrid-shadow")
    cmd = [javac, *_HYBRID_JAVA_EXPORTS, "-d", classes, *sources]
    proc = run(cmd, check=False, capture=True)
    if proc.returncode != 0 or not marker.is_file():
        raise RuntimeError("could not compile Java hybrid engine")
    log(f"Compiled Java hybrid engine with JDK internals -> {classes}")
    return classes


def _manifest_root_classes(manifest_path, package_name):
    """Return explicitly named app components as strong source roots."""
    out = set()
    try:
        root = ET.parse(manifest_path).getroot()
        app = root.find("application")
        if app is None:
            return out
        name_attr = A + "name"
        for el in [app, *list(app)]:
            if el.tag.rsplit("}", 1)[-1] not in {"application", "activity", "activity-alias", "service", "receiver", "provider"}:
                continue
            name = el.get(name_attr)
            if not name:
                continue
            if name.startswith("."):
                name = package_name + name
            elif "." not in name and package_name:
                name = package_name + "." + name
            out.add(name)
    except Exception as exc:
        detail(f"manifest source-root scan: {exc}", 2)
    return out


def _filter_manifest_roots_to_app_prefixes(root_classes, app_prefixes):
    """Keep only manifest components that can plausibly be application source.

    Android library manifests contribute providers/receivers/services during manifest
    merging (AndroidX Startup/ProfileInstaller are common examples).  Treating every
    manifest component as a strong source root defeats the hybrid boundary by forcing
    library providers back through javac.  Explicit app prefixes are the authority.
    """
    prefixes = [str(p).rstrip(".") for p in (app_prefixes or ()) if str(p).strip()]
    return {
        fq for fq in (root_classes or ())
        if any(fq == prefix or fq.startswith(prefix + ".") for prefix in prefixes)
    }


def configure_hybrid_shadow_gradle(root, shadow_jar, binary_source_list):
    """Compile only app-owned Java and put the APK ABI shadow on javac's classpath.

    compileOnly is critical: the shadow class files are deliberately non-executable
    ABI stubs. They must satisfy javac but must never be dexed into a rebuilt APK.
    """
    root = Path(root)
    bg = root / "app/build.gradle"
    if not bg.is_file():
        return False
    shadow_jar = Path(shadow_jar)
    binary_source_list = Path(binary_source_list)
    try:
        shadow_rel = shadow_jar.relative_to(root / "app").as_posix()
    except ValueError:
        shadow_rel = shadow_jar.as_posix()
    try:
        list_rel = binary_source_list.relative_to(root / "app").as_posix()
    except ValueError:
        list_rel = binary_source_list.as_posix()
    text = bg.read_text()
    begin = "// APK2PROJECT_V26_HYBRID_BEGIN"
    end = "// APK2PROJECT_V26_HYBRID_END"
    block = f'''\n{begin}
// Compile-time only ABI extracted from the APK's own DEX/smali surface.
// It intentionally contains poison method bodies and MUST NOT be packaged.
dependencies {{
  compileOnly files("{shadow_rel}")
}}

def apk2projectBinarySourceFile = file("{list_rel}")
def apk2projectBinaryOwnedSources = apk2projectBinarySourceFile.exists()
    ? (apk2projectBinarySourceFile.readLines("UTF-8").findAll {{ !it.trim().isEmpty() }} as Set)
    : ([] as Set)

// Keep decompiled non-app/library/obfuscated source visible on disk, but never
// ask javac to compile it. FileTreeElement.path is relative to the Java source root.
android.sourceSets.main.java.exclude {{ element ->
  apk2projectBinaryOwnedSources.contains(element.path)
}}

// The APK ABI must win if an upstream Maven dependency exposes the same FQCN.
// This is common after R8 transformed AndroidX/Material classes: the Maven class
// has the public API, while callers in this decompile reference APK-private aliases.
tasks.withType(org.gradle.api.tasks.compile.JavaCompile).configureEach {{ task ->
  // AGP may leave JavaCompile.classpath null while the task is first being
  // configured.  Prepending with Groovy `+` at that point creates an ordinary
  // ArrayList [shadowJar, null], which cannot be assigned back to FileCollection.
  // Delay the precedence adjustment until execution, when AGP has finalized the
  // real classpath, and always construct a genuine Gradle FileCollection.
  doFirst {{
    def agpClasspath = task.classpath ?: project.files()
    task.classpath = project.files(file("{shadow_rel}"), agpClasspath)

    // Belt-and-suspenders ownership enforcement.  AGP versions/plugins can rebuild
    // JavaCompile.source after sourceSets have been configured.  Re-filter the final
    // task source immediately before javac so a binary-owned AndroidX/Material/JADX
    // provider can never leak back into compilation merely because it still exists
    // on disk for alias evidence.
    def apk2projectJavaRoot = file("src/main/java").canonicalFile.toPath()
    task.setSource(task.source.filter {{ f ->
      try {{
        def fp = f.canonicalFile.toPath()
        if (!fp.startsWith(apk2projectJavaRoot)) return true
        def rel = apk2projectJavaRoot.relativize(fp).toString().replace(java.io.File.separator, "/")
        return !apk2projectBinaryOwnedSources.contains(rel)
      }} catch (Exception ignored) {{
        return true
      }}
    }})
  }}
}}
{end}\n'''
    if begin in text and end in text:
        text = re.sub(re.escape(begin) + r".*?" + re.escape(end), block.strip(), text, flags=re.S)
    else:
        text = text.rstrip() + "\n" + block
    bg.write_text(text)
    return True


def remove_hybrid_shadow_gradle(root):
    bg = Path(root) / "app/build.gradle"
    if not bg.is_file():
        return False
    text = bg.read_text()
    begin = "// APK2PROJECT_V26_HYBRID_BEGIN"
    end = "// APK2PROJECT_V26_HYBRID_END"
    if begin not in text or end not in text:
        return False
    text = re.sub(r"\n?" + re.escape(begin) + r".*?" + re.escape(end) + r"\n?", "\n", text, flags=re.S)
    bg.write_text(text)
    return True


def build_hybrid_shadow(
    project_root, java_root, original_root, app_prefixes, root_classes=(), *,
    apk_path=None, permissive=True, force_binary_regexes=(), extra_source_roots=(),
    classpath_file=None, jadx_map=None,
):
    """Build and validate the APK ABI shadow transactionally.

    The live shadow/classification files are never overwritten until the candidate
    JAR has passed DEX-surface + alias-provenance validation.  This matters on resume:
    a more ambitious semantic-link pass must not destroy the last known-good compiler
    checkpoint merely because its candidate JAR was malformed.
    """
    project_root = Path(project_root)
    java_root = Path(java_root)
    analysis = project_root / "analysis"
    engine_classes = ensure_hybrid_java_engine(project_root)
    shadow = project_root / "app/libs/apk2project-apk-shadow-abi.jar"
    ownership = analysis / "hybrid-source-ownership.json"
    binary_list = project_root / "app/apk2project-binary-sources.txt"
    candidate_dir = analysis / "java-engine/candidate"
    candidate_dir.mkdir(parents=True, exist_ok=True)
    candidate_shadow = candidate_dir / "apk2project-apk-shadow-abi.jar"
    candidate_ownership = candidate_dir / "hybrid-source-ownership.json"
    candidate_binary_list = candidate_dir / "apk2project-binary-sources.txt"
    shadow.parent.mkdir(parents=True, exist_ok=True)
    for stale in (candidate_shadow, candidate_ownership, candidate_binary_list):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass

    cmd = [
        shutil.which("java") or "java", *_HYBRID_JAVA_EXPORTS,
        "-cp", str(engine_classes), "apk2project.hybrid.HybridCompiler", "shadow",
        "--java-root", str(java_root), "--original", str(original_root),
        "--out", str(candidate_shadow), "--ownership", str(candidate_ownership),
        "--source-list", str(candidate_binary_list),
    ]
    if apk_path:
        cmd += ["--apk", str(Path(apk_path).resolve())]
    for prefix in app_prefixes:
        if prefix:
            cmd += ["--app-prefix", str(prefix)]
    for fq in sorted(set(root_classes)):
        if fq:
            cmd += ["--root-class", str(fq)]
    for rx in force_binary_regexes or ():
        if rx:
            cmd += ["--force-binary-regex", str(rx)]
    for eroot in extra_source_roots or ():
        eroot = Path(eroot)
        if eroot.is_dir():
            cmd += ["--extra-source-root", str(eroot)]
    if classpath_file:
        classpath_file = Path(classpath_file)
        if classpath_file.is_file():
            cmd += ["--classpath-file", str(classpath_file)]
    if jadx_map:
        jadx_map = Path(jadx_map)
        if jadx_map.is_file():
            cmd += ["--jadx-map", str(jadx_map)]
    if not permissive:
        cmd.append("--strict-abi")

    proc = run(cmd, check=False, capture=True)
    (analysis / "java-hybrid-shadow.log").write_text(proc.stdout or "")
    if proc.returncode != 0 or not candidate_shadow.is_file():
        raise RuntimeError("Java hybrid ABI shadow candidate generation failed")

    # v27: never let a malformed shadow poison javac. Compare the emitted class
    # surfaces and every synthetic alias directly against APK DEX before promotion.
    if apk_path:
        validation = analysis / "java-engine/shadow-validation.json"
        candidate_validation = candidate_dir / "shadow-validation.json"
        vcmd = [
            shutil.which("java") or "java", *_HYBRID_JAVA_EXPORTS,
            "-cp", str(engine_classes), "apk2project.hybrid.HybridCompiler", "validate",
            "--apk", str(Path(apk_path).resolve()), "--shadow-jar", str(candidate_shadow),
            "--report", str(candidate_validation),
        ]
        vp = subprocess.run(list(map(str, vcmd)), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors="replace")
        (analysis / "java-engine/shadow-validation.log").write_text(vp.stdout or "")
        if candidate_validation.is_file():
            shutil.copy2(candidate_validation, validation)
        if vp.returncode != 0:
            raise RuntimeError(
                f"APK ABI shadow candidate failed DEX/alias validation (rc={vp.returncode}); see {validation}"
            )

    # Candidate is now known-good. Promote all three files as one logical checkpoint.
    # os.replace is atomic on the same filesystem; candidate_dir lives under project_root.
    candidate_shadow.replace(shadow)
    candidate_ownership.replace(ownership)
    candidate_binary_list.replace(binary_list)
    configure_hybrid_shadow_gradle(project_root, shadow, binary_list)
    log(f"Hybrid source/binary boundary: validated APK ABI shadow promoted -> {shadow.name}")
    return shadow, ownership, binary_list


def quarantine_hybrid_binary_sources(project_root, java_root, binary_source_list, action):
    """Physically remove binary-owned Java from the active source root *after* ABI generation.

    `move` is intentionally preferred over delete: files are relocated to an evidence archive
    that the Java engine can scan on later runs for JADX alias recovery, while javac never sees
    them as Android source.  `delete` really deletes them after the shadow JAR has been built.
    """
    action = (action or "keep").lower()
    if action == "keep" or not binary_source_list:
        return {"action": action, "moved": 0, "deleted": 0, "missing": 0, "archive_root": None}
    java_root = Path(java_root).resolve()
    list_path = Path(binary_source_list)
    if not list_path.is_file():
        return {"action": action, "moved": 0, "deleted": 0, "missing": 0, "archive_root": None}
    archive_root = Path(project_root) / "analysis/hybrid-binary-source-archive/java"
    moved = deleted = missing = 0
    audit = []
    for raw in list_path.read_text(errors="ignore").splitlines():
        rel = raw.strip().replace("\\", "/")
        if not rel:
            continue
        src = (java_root / rel).resolve()
        try:
            src.relative_to(java_root)
        except ValueError:
            continue
        if not src.is_file():
            missing += 1
            continue
        if action == "move":
            dst = archive_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                # Preserve the newest active-source copy as the alias-evidence version.
                dst.unlink()
            shutil.move(str(src), str(dst))
            moved += 1
            audit.append({"source": str(src), "archive": str(dst), "action": "move"})
        elif action == "delete":
            src.unlink()
            deleted += 1
            audit.append({"source": str(src), "action": "delete"})
    # Trim empty package directories without touching the java root itself.
    for d in sorted((p for p in java_root.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        try:
            if d != java_root and not any(d.iterdir()):
                d.rmdir()
        except OSError:
            pass
    report = Path(project_root) / "analysis/hybrid-binary-source-quarantine.json"
    report.write_text(json.dumps({
        "action": action, "moved": moved, "deleted": deleted, "missing": missing,
        "archive_root": str(archive_root) if action == "move" else None,
        "files": audit,
    }, indent=2, sort_keys=True))
    if action == "move":
        log(f"Hybrid binary-source quarantine: moved {moved} file(s) out of app/src/main/java -> {archive_root}")
    else:
        warn(f"Hybrid binary-source quarantine: permanently deleted {deleted} binary-owned Java file(s)")
    return {
        "action": action, "moved": moved, "deleted": deleted, "missing": missing,
        "archive_root": archive_root if action == "move" else None,
    }


def write_hybrid_classpath_file(project_root, shadow_jar, android_jar=None, artifacts=()):
    """Build a javac-analysis classpath file consumed by HybridCompiler analyze.

    AARs are represented by their embedded classes.jar; ordinary JARs are direct.
    """
    project_root = Path(project_root)
    entries = []
    for p in (shadow_jar, android_jar):
        if p and Path(p).is_file():
            entries.append(str(Path(p).resolve()))
    scratch = project_root / "analysis/java-engine/classpath-aars"
    scratch.mkdir(parents=True, exist_ok=True)
    for ent in artifacts or ():
        f = ent.get("file")
        typ = ent.get("type")
        if not f or not Path(f).is_file():
            continue
        if typ == "jar":
            entries.append(str(Path(f).resolve()))
        elif typ == "aar":
            try:
                with zipfile.ZipFile(f) as zf:
                    if "classes.jar" not in zf.namelist():
                        continue
                    gav = "_".join(map(str, ent.get("gav", ("aar",))))
                    dst = scratch / (re.sub(r"[^A-Za-z0-9_.-]+", "_", gav) + ".jar")
                    if not dst.exists():
                        dst.write_bytes(zf.read("classes.jar"))
                    entries.append(str(dst.resolve()))
            except Exception:
                continue
    entries = list(dict.fromkeys(entries))
    cpfile = project_root / "analysis/java-engine/classpath.txt"
    cpfile.parent.mkdir(parents=True, exist_ok=True)
    cpfile.write_text("\n".join(entries) + "\n")
    return cpfile


def run_hybrid_javac_analysis(project_root, java_root, app_prefixes, binary_list, classpath_file):
    """Run rich attributed javac analysis of app-owned source only."""
    project_root = Path(project_root)
    classes = ensure_hybrid_java_engine(project_root)
    cmd = [
        shutil.which("java") or "java", *_HYBRID_JAVA_EXPORTS,
        "-cp", str(classes), "apk2project.hybrid.HybridCompiler", "analyze",
        "--java-root", str(java_root), "--source-list", str(binary_list),
        "--classpath-file", str(classpath_file),
    ]
    for p in app_prefixes:
        if p:
            cmd += ["--app-prefix", str(p)]
    proc = subprocess.run(list(map(str, cmd)), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, errors="replace")
    analysis = project_root / "analysis/java-engine"
    analysis.mkdir(parents=True, exist_ok=True)
    (analysis / "attributed.jsonl").write_text(proc.stdout or "")
    (analysis / "analyze.stderr.log").write_text(proc.stderr or "")
    return proc.returncode



def run_hybrid_source_normalize(project_root, java_root, binary_list, classpath_file):
    """Use the Java engine to normalize two high-confidence JADX source artifacts.

    1) SSA register type warnings (r0v1/r0v2/...) are grouped by register+method and
       resolved with javac Types.lub; unknown SSA versions are non-vetoing unless
       source member-use constraints contradict the candidate.
    2) simple interface <clinit> blocks are converted to legal Java field initializers
       instead of being deleted.
    """
    project_root = Path(project_root)
    classes = ensure_hybrid_java_engine(project_root)
    analysis = project_root / "analysis/java-engine"
    analysis.mkdir(parents=True, exist_ok=True)
    report = analysis / "source-normalize.jsonl"
    cmd = [
        shutil.which("java") or "java", *_HYBRID_JAVA_EXPORTS,
        "-cp", str(classes), "apk2project.hybrid.HybridCompiler", "normalize",
        "--java-root", str(java_root), "--report", str(report),
    ]
    if binary_list:
        cmd += ["--source-list", str(binary_list)]
    if classpath_file:
        cmd += ["--classpath-file", str(classpath_file)]
    proc = subprocess.run(list(map(str, cmd)), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, errors="replace")
    (analysis / "source-normalize.log").write_text(proc.stdout or "")
    if proc.returncode != 0:
        raise RuntimeError(f"Java decompiler source normalization failed rc={proc.returncode}; see {analysis/'source-normalize.log'}")
    changed = 0
    if report.is_file():
        for line in report.read_text(errors="ignore").splitlines():
            try:
                rec = json.loads(line)
                if rec.get("kind") == "edit":
                    changed += 1
            except Exception:
                pass
    if changed:
        log(f"Java decompiler normalizer applied {changed} SSA/<clinit> source edit(s)")
    else:
        detail("Java decompiler normalizer: no safe SSA/<clinit> edits applied", 1)
    return changed

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase progress detail; use -vv for URLs/candidate inspection",
    )
    ap.add_argument("apk", type=Path)
    ap.add_argument("-o", "--output", type=Path)
    ap.add_argument(
        "--tools-dir", type=Path, default=Path.home() / ".local/share/apk2project/tools"
    )
    ap.add_argument("--install-tools", action="store_true")
    ap.add_argument("--install-sdk", action="store_true", help="bootstrap/configure a native Termux Android SDK and build script")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--keep-work", action="store_true")
    ap.add_argument(
        "--no-resume-snapshot", action="store_true",
        help="do not create the automatic pre-run Java/build checkpoint when resuming an existing project",
    )
    ap.add_argument("--no-deobf", action="store_true")
    ap.add_argument(
        "--query-jadx-aliases", action="store_true",
        help=(
            "also query Maven for obvious JADX --deobf synthetic names such as "
            "p106y.C1359e; disabled by default because such lookups cannot match "
            "the original artifact class names"
        ),
    )
    ap.add_argument("--max-rounds", type=int, default=12)
    ap.add_argument("--max-queries", type=int, default=750)
    ap.add_argument("--lookup-cache-dir", type=Path, default=Path.home() / ".cache/apk2project",
                    help="persistent Maven/Google URL lookup cache shared across runs")
    ap.add_argument("--clear-lookup-cache", action="store_true",
                    help="forget cached HTTP lookups (keeps downloaded artifacts and learned mappings)")
    ap.add_argument("--clear-learned", action="store_true",
                    help="forget learned package hints/index (keeps HTTP cache and artifacts)")
    ap.add_argument("--package-seed", type=Path, default=None,
                    help="read-only curated package seed (default: package-map.json beside the script)")
    ap.add_argument("--no-embedded-versions", action="store_true",
                    help="ignore library versions recorded inside the APK (META-INF/*.version etc.)")
    ap.add_argument("--add-embedded-deps", action="store_true",
                    help="also declare every library coordinate recorded inside the APK, even when "
                         "R8 renamed its classes so they cannot be matched")
    ap.add_argument("--learn-from-failed-builds", action="store_true",
                    help="learn mappings even when --compile hit dependency-resolution or duplicate-class errors")
    ap.add_argument("--prune", choices=("none", "move", "delete"), default="move")
    ap.add_argument("--aggressive-prune", action="store_true")
    ap.add_argument(
        "--binary-islands", choices=("off", "safe", "aggressive"), default="safe",
        help=(
            "javac-driven library quarantine: when failing decompiled classes are physically "
            "contained in resolved JAR/AAR dependencies, move that source cohort out of the "
            "Java tree and let the binary artifact provide it. safe (default) preserves APK/R8 "
            "alias-heavy provider classes; aggressive may quarantine those too"
        ),
    )
    ap.add_argument(
        "--hybrid-shadow", choices=("off", "safe", "permissive"), default="off",
        help=(
            "v27.2 app-source/binary-shadow mode: generate a validated compileOnly ABI JAR directly "
            "from the APK DEX surface (with optional smali/JOBF enrichment) and exclude non-app "
            "decompiled Java from javac. safe preserves DEX access/finality "
            "where practical; permissive (recommended for damaged JADX trees) widens binary-owned ABI "
            "members to public and removes source-level access barriers. default: off"
        ),
    )
    ap.add_argument(
        "--app-source-prefix", action="append", default=[],
        help=(
            "Java package prefix to keep compiling as editable app source in --hybrid-shadow mode; "
            "repeatable. Default is the APK manifest package/application namespace."
        ),
    )
    ap.add_argument(
        "--hybrid-obfuscated-binary", action="store_true",
        help=(
            "force JADX-style obfuscated packages/classes (p####... and C####..., including "
            "AbstractC/InterfaceC/EnumC variants) to binary ownership even when they live under "
            "an app source prefix or are manifest roots"
        ),
    )
    ap.add_argument(
        "--hybrid-force-binary-regex", action="append", default=[],
        help=(
            "regex matched against full Java FQCN; matching types are always binary-owned. "
            "Repeatable and evaluated before app-source-prefix/root ownership."
        ),
    )
    ap.add_argument(
        "--hybrid-binary-source-action", choices=("keep", "move", "delete"), default="keep",
        help=(
            "after the shadow ABI is generated: keep binary-owned Java in place but excluded "
            "from javac (default), move it to analysis/hybrid-binary-source-archive/java, or "
            "permanently delete it. move is recommended."
        ),
    )
    ap.add_argument(
        "--hybrid-java-analysis", action=argparse.BooleanOptionalAction, default=True,
        help=(
            "after creating the APK ABI shadow, run the add-exports javac Symbol/Type analyzer over "
            "app-owned source and save analysis/java-engine/attributed.jsonl (default: enabled)"
        ),
    )
    ap.add_argument(
        "--hybrid-source-normalize", action=argparse.BooleanOptionalAction, default=True,
        help=(
            "before javac, run the Java/javac-internal decompiler normalizer over app-owned source: "
            "infer common SSA register types from JADX warnings using Types.lub and legalize simple "
            "interface <clinit> blocks into field initializers (default: enabled in hybrid-shadow mode)"
        ),
    )
    ap.add_argument("--compile", action="store_true")
    ap.add_argument(
        "--rebuild-apk", action="store_true",
        help=(
            "v28: after a successful hybrid-shadow javac build, rebuild the runtime APK by "
            "preserving original resources/binary DEX classes and replacing only source-owned classes"
        ),
    )
    ap.add_argument(
        "--hybrid-apk-sign", choices=("off", "debug"), default="debug",
        help="v28 APK output signing: off or reusable ~/.android/debug.keystore (default: debug)",
    )
    ap.add_argument(
        "--hybrid-apk-output", type=Path, default=None,
        help="output path for the v28 unsigned hybrid APK; default: app/build/outputs/apk/hybrid/...",
    )
    ap.add_argument(
        "--dexlib-jar", type=Path, default=None,
        help=("official standalone com.android.tools.smali smali-dexlib2 jar or directory; "
              "normally resolved from apk2project/Gradle/Maven caches or bootstrapped automatically"),
    )
    ap.add_argument(
        "--java-repair", choices=("off", "safe", "balanced", "aggressive"), default="balanced",
        help=(
            "semantic javac-guided source repair mode. safe avoids destructive edits; "
            "balanced (default) permits small invalid-node removal/method stubbing when strongly "
            "supported; aggressive permits lower-confidence last-resort repairs"
        ),
    )
    ap.add_argument(
        "--java-repair-rounds", type=int, default=48,
        help="maximum semantic Java repair transactions after javac failures (default: 48; provider rescues/frontier advances may require many validated rounds)",
    )
    ap.add_argument(
        "--java-repair-min-confidence", type=float, default=0.72,
        help="minimum confidence score for semantic source edits (default: 0.72)",
    )
    ap.add_argument(
        "--java-repair-max-files", type=int, default=120,
        help="maximum diagnostic Java files AST-analyzed in one repair round (default: 120)",
    )
    ap.add_argument(
        "--java-tree-trace", choices=("off", "summary", "detail", "verbose"), default="detail",
        help=(
            "live colored tracing from the JDK compiler-tree analyzer: off, summary, "
            "detail (default: types + methods), or verbose (also variables + calls)"
        ),
    )
    ap.add_argument(
        "--no-java-repair-rollback", action="store_true",
        help="keep semantic source edits even when the next javac result is clearly worse",
    )
    ap.add_argument("--skip-decompile", action="store_true")
    ap.add_argument(
        "--refresh-sources", action="store_true",
        help=(
            "rerun JADX with compile-oriented conservative settings and replace "
            "app/src/main/java; useful once when upgrading a project previously "
            "decompiled with --show-bad-code"
        ),
    )
    ap.add_argument(
        "--refresh-dependencies", action="store_true",
        help=(
            "re-resolve and rewrite dependency coordinates even when resuming an existing project; "
            "by default a resume freezes the last known dependency set"
        ),
    )
    ap.add_argument(
        "--refresh-resources", action="store_true",
        help="replace app/src/main/res from the pristine Apktool decode; by default an existing working resource tree is preserved",
    )
    ap.add_argument(
        "--refresh-manifest", action="store_true",
        help="replace app/src/main/AndroidManifest.xml from the pristine Apktool decode; by default the working manifest is preserved",
    )
    ap.add_argument(
        "--resource-repair-attempts", type=int, default=4,
        help="maximum native-AAPT2 / Gradle resource auto-repair attempts (default: 4)",
    )
    ap.add_argument(
        "--no-resource-preflight", action="store_true",
        help="skip the native aapt2 compile preflight of app/src/main/res",
    )
    ap.add_argument(
        "--resource-deep-scan", action="store_true",
        help=(
            "when a genuine Gradle resource failure names no merged XML file, "
            "probe every merged values XML with aapt2; disabled by default because "
            "it can launch hundreds of diagnostic aapt2 processes"
        ),
    )
    ap.add_argument(
        "--allow-minsdk-bump", action="store_true",
        help=(
            "allow dependency selection to raise the reconstructed app minSdk when "
            "no compatible library version exists; default preserves the APK minSdk"
        ),
    )
    ap.add_argument(
        "--sdk-platform-policy", choices=("auto", "installed", "download"), default="auto",
        help=(
            "Android platform selection: auto prefers working installed platforms and can download "
            "official platform packages; installed forbids downloads; download prefers Google's "
            "official platform cache (default: auto)"
        ),
    )
    ap.add_argument(
        "--sdk-platform-cache-dir", type=Path,
        default=Path.home() / ".cache/apk2project/android-sdk",
        help="persistent cache for official Android SDK platform packages",
    )
    ap.add_argument(
        "--sdk-platform-fallbacks", type=int, default=4,
        help="maximum older official API levels to try when the active AAPT2 cannot read target/newer platforms (default: 4)",
    )
    ap.add_argument(
        "--package-only-lookups", action="store_true",
        help=(
            "issue at most one Maven Central lookup per unique unresolved package "
            "prefix and skip per-class probes entirely; far fewer network calls, "
            "may miss rare artifacts"
        ),
    )
    ap.add_argument(
        "--apktool-framework-dir", type=Path, default=None,
        help=(
            "directory containing apktool-installed framework APKs, e.g. "
            "~/.apktool-frameworks (default: auto-detect several paths)"
        ),
    )
    ap.add_argument(
        "--no-license-check", action="store_true",
        help="do not seed Android SDK licences before compiling",
    )
    ap.add_argument(
        "--show-gradle-noise", action="store_true",
        help="show Termux/Gradle daemon and generic deprecation boilerplate that is hidden by default",
    )
    ap.add_argument(
        "--gradle-warning-mode", choices=("none", "summary", "all", "fail"), default="none",
        help="Gradle warning mode for generated build probes (default: all; actual deprecations are saved to analysis/gradle-deprecations.log)",
    )
    ap.add_argument(
        "--gradle-log-level", choices=("quiet", "lifecycle", "info", "debug"), default="lifecycle",
        help="Gradle logging verbosity for compile probes (default: lifecycle)",
    )
    ap.add_argument(
        "--trace-processes", action="store_true",
        help="trace spawned OS commands during the Gradle compile with strace into analysis/process-exec.log",
    )
    ap.add_argument(
        "--trace-gradle", action="store_true",
        help="record Java Flight Recorder samples from the Gradle launcher/in-process AGP into analysis/gradle.jfr",
    )
    z = ap.parse_args()
    global VERBOSE, SHOW_GRADLE_NOISE
    VERBOSE = z.verbose
    SHOW_GRADLE_NOISE = z.show_gradle_noise
    if getattr(z, "apktool_framework_dir", None):
        register_apktool_framework_dir(z.apktool_framework_dir)
    log(f"apk2project {SCRIPT_VERSION}")
    if not callable(globals().get("resolve")):
        die("internal error: dependency resolver function is missing")
    apk = z.apk.expanduser().resolve()
    if not apk.is_file():
        die("APK not found")
    out = (z.output or Path.cwd() / (apk.stem + "-project")).resolve()
    if out.exists() and z.force:
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    _preexisting_java_root = out / "app/src/main/java"
    had_existing_java_tree = (
        _preexisting_java_root.exists()
        and any(_preexisting_java_root.rglob("*.java"))
        and not z.force
    )
    if had_existing_java_tree and not z.no_resume_snapshot:
        snapshot_resume_checkpoint(out)
    resume_project = had_existing_java_tree and not z.refresh_sources
    if resume_project:
        log(f"Resume checkpoint detected: preserving existing Java/classpath state under {out}")
    apktool_jar = jadx_binary = None
    if z.install_tools:
        if not shutil.which("java"):
            die("Install Java: pkg install openjdk-21")
        apktool_jar, jadx_binary = bootstrap(z.tools_dir.expanduser())

    apktool_command = (
        [shutil.which("apktool")]
        if shutil.which("apktool")
        else ([shutil.which("java"), "-jar", apktool_jar] if apktool_jar else None)
    )
    jadx_command = (
        [shutil.which("jadx")]
        if shutil.which("jadx")
        else ([jadx_binary] if jadx_binary else None)
    )
    if not apktool_command or not jadx_command:
        die("apktool/jadx unavailable; use --install-tools")

    work_dir = out / "_work"
    work_dir.mkdir(exist_ok=True)
    apktool_out = work_dir / "apktool"
    jadx_sources = work_dir / "jadx"
    jadx_export = work_dir / "jadx-export"
    # Exact aliases produced by the same JADX run.  Keep this under _work so resume
    # runs can retain a stable deobfuscated namespace; it is also copied into analysis.
    jadx_map = work_dir / "jadx-renames.jobf"
    jadx_proc = jadx_export_proc = None

    apktool_ready = (apktool_out / "AndroidManifest.xml").exists() and (apktool_out / "apktool.yml").exists()
    jadx_ready = (jadx_sources / "sources").exists() and any((jadx_sources / "sources").rglob("*.java"))
    jadx_export_ready = jadx_export.exists() and any(jadx_export.iterdir())

    if z.refresh_sources and z.skip_decompile:
        die("--refresh-sources cannot be combined with --skip-decompile")
    if z.refresh_sources:
        log("Refreshing JADX sources with compile-oriented settings")
        shutil.rmtree(jadx_sources, ignore_errors=True)
        jadx_ready = False

    if z.skip_decompile:
        if not apktool_ready or not jadx_ready:
            die("--skip-decompile requested but reusable _work/apktool and _work/jadx outputs are incomplete")
        log("Skipping Apktool/JADX by request; reusing existing output")
    else:
        if apktool_ready:
            log(f"Reusing existing Apktool decode: {apktool_out}")
        else:
            log("Decoding APK with Apktool")
            run(apktool_command + ["d", "-f", apk, "-o", apktool_out])

        if jadx_ready:
            log(f"Reusing existing JADX sources: {jadx_sources}")
        else:
            log("Decompiling DEX with JADX")
            # Compile-oriented decompilation: never use --show-bad-code.  That
            # switch intentionally emits malformed constructs such as `?? r11;`,
            # which are useful for inspection but impossible for javac to parse.
            jadx_proc = run(
                jadx_command
                + _jadx_compile_oriented_args(jadx_command)
                + ([] if z.no_deobf else ["--deobf"])
                + ([] if z.no_deobf else _jadx_deobf_map_args(
                    jadx_command, jadx_map, mode=("overwrite" if z.refresh_sources else "read-or-save")
                ))
                # APK/DEX input uses JADX's dex-input plugin directly.  Do not
                # force java-convert.mode=d8; that option applies only when JADX
                # must convert Java bytecode (.class/.jar/.aar) into DEX first.
                + ["--log-level", "progress"]
                + ["-d", jadx_sources, apk],
                check=False, capture=True,
            )

        if jadx_export_ready:
            log(f"Reusing existing JADX Gradle export: {jadx_export}")
        else:
            log("Running JADX Gradle export")
            jadx_export_proc = run(
                jadx_command + ["--export-gradle", "-d", jadx_export, apk],
                check=False, capture=True,
            )

        if VERBOSE >= 1:
            if jadx_proc and jadx_proc.stdout:
                print(jadx_proc.stdout, file=sys.stderr, flush=True)
            if jadx_export_proc and jadx_export_proc.stdout:
                print(jadx_export_proc.stdout, file=sys.stderr, flush=True)

    # A resume from v26 or earlier may have perfectly valuable manually repaired Java
    # but no persisted JADX rename map. Build only the mapping metadata; never replace
    # source as a side effect of gaining exact aliases for the shadow linker.
    if z.hybrid_shadow != "off" and not z.no_deobf and not jadx_map.is_file():
        _ensure_jadx_deobf_map(
            jadx_command, apk, jadx_map, work_dir / "jadx-map-probe"
        )

    main = out / "app/src/main"
    if not (main / "java").exists():
       (main / "java").mkdir(parents=True)
    # app/src/main/res is the DURABLE working resource tree.  Never overwrite it
    # on a resume/re-run unless the user explicitly asks for --refresh-resources.
    # This matters because all AAPT2 repairs below are intentionally applied to
    # source resources, never to build/intermediates (which AGP owns/regenerates).
    res_dst = main / "res"
    if z.refresh_resources:
        log("Refreshing app/src/main/res from pristine Apktool decode")
        shutil.rmtree(res_dst, ignore_errors=True)
        cp(apktool_out / "res", res_dst)
    elif res_dst.exists() and any(res_dst.iterdir()):
        log(f"Reusing existing working resource tree: {res_dst}")
    else:
        cp(apktool_out / "res", res_dst)

    manifest_dst = main / "AndroidManifest.xml"
    if z.refresh_manifest:
        log("Refreshing app/src/main/AndroidManifest.xml from pristine Apktool decode")
        cp(apktool_out / "AndroidManifest.xml", manifest_dst)
    elif manifest_dst.exists():
        log(f"Reusing existing working manifest: {manifest_dst}")
    else:
        cp(apktool_out / "AndroidManifest.xml", manifest_dst)

    copy_pairs = [
        (apktool_out / "assets", main / "assets"),
        (apktool_out / "lib", main / "jniLibs"),
        (jadx_sources / "resources", out / "jadx-resources"),
        (jadx_export, out / "jadx-gradle-export"),
    ]
    for a, b in copy_pairs:
        cp(a, b)

    # Remove/rename Apktool-exposed AAPT2 private synthetic resources (for
    # example drawable/$avd_hide_password__0) before the ordinary XML
    # normalization/preflight. These compiled-only names cannot legally appear
    # in source resource tables.
    sanitize_apktool_synthetic_resources(main / "res", out / "analysis")

    # Normalize before Gradle ever sees the decoded values tree. This pass is
    # ancestry-aware: enum/flag under attr are valid and retained; duplicate attr
    # definitions (including definitions nested in declare-styleable) are merged.
    normalize_value_resources(main / "res", out / "analysis")

    # Do not resurrect sources that a previous pruning pass moved/deleted.
    java_has_sources = (main / "java").exists() and any((main / "java").rglob("*.java"))
    if z.refresh_sources:
        # Explicit only: preserve resume semantics by default, but provide a way
        # to replace trees originally produced with --show-bad-code.
        shutil.rmtree(main / "java", ignore_errors=True)
        cp(jadx_sources / "sources", main / "java")
        java_has_sources = True
    elif java_has_sources:
        log(f"Reusing normalized Java source tree: {main/'java'}")
    else:
        cp(jadx_sources / "sources", main / "java")
    orig = out / "original"
    orig.mkdir(exist_ok=True)
    cp(apktool_out / "apktool.yml", orig / "apktool.yml")
    cp(apktool_out / "unknown", orig / "unknown")
    for p in apktool_out.iterdir():
        if p.name == "smali" or p.name.startswith("smali_classes"):
            cp(p, orig / p.name)
    # Always read package/sdk metadata from the pristine Apktool manifest.
    # The working manifest is intentionally stripped of source package/build-only
    # attributes for modern AGP and is preserved across reruns.
    info = manifest_info(apktool_out / "AndroidManifest.xml")
    normalize_reconstructed_manifest(main / "AndroidManifest.xml", out / "analysis")
    imports, classes, packages, source_files, bad = scan(main / "java")
    lookup_dir = z.lookup_cache_dir.expanduser()
    if z.clear_learned:
        for name in ("package-hints.json", "package-artifacts.json"):
            (lookup_dir / name).unlink(missing_ok=True)
        log("Cleared learned package mappings")
    load_lookup_cache(lookup_dir, seed_path=z.package_seed)
    if z.clear_lookup_cache:
        LOOKUP_CACHE.clear_http()
        log("Cleared cached HTTP lookups (artifacts and learned mappings kept)")
    embedded = {} if z.no_embedded_versions else apk_embedded_coordinates(apk)
    set_pinned_versions(embedded)
    if embedded:
        log(f"APK declares {len(embedded)} exact library versions; these pin resolution")
    (out / "analysis").mkdir(parents=True, exist_ok=True)
    (out / "analysis" / "embedded-coordinates.json").write_text(json.dumps(
        {f"{g}:{a}": {"version": v, "source": s} for (g, a), (v, s) in sorted(embedded.items())},
        indent=2))
    cache = lookup_dir
    tmp = out / ".dep-cache/tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    previous_report = {}
    previous_coords = set()
    previous_report_path = out / "analysis/report.json"
    if resume_project and previous_report_path.is_file():
        try:
            previous_report = json.loads(previous_report_path.read_text())
            for item in previous_report.get("coordinates", []):
                parts = str(item).split(":", 2)
                if len(parts) == 3:
                    previous_coords.add(tuple(parts))
        except Exception as exc:
            warn(f"Could not read previous dependency checkpoint: {exc}")
    initial, provided, selected, coords, queries = resolve(
        imports, classes, packages, cache, tmp, z.max_rounds, z.max_queries,
        app_package=info.get("package"),
        include_jadx_aliases=z.query_jadx_aliases,
        project_min_sdk=info.get("min_sdk") or 21,
        allow_min_sdk_bump=z.allow_minsdk_bump,
        package_only_lookups=z.package_only_lookups,
    )

    if z.allow_minsdk_bump:
        required_min = max(
            [int(info.get("min_sdk") or 21)]
            + [int(sel["min_sdk"]) for sel in selected if sel.get("min_sdk") is not None]
        )
        if required_min > int(info.get("min_sdk") or 21):
            warn(
                f"Raising reconstructed minSdk from {info.get('min_sdk') or 21} "
                f"to {required_min} because --allow-minsdk-bump was supplied"
            )
            info["min_sdk"] = required_min

    # Select a platform before finalizing dependencies. On Termux the native AAPT2
    # may only understand an older platform resources table even when newer SDK
    # directories are installed. compileSdk is build-time metadata, so targetSdk
    # remains untouched if we need to use an older compatible platform.
    sdk = bootstrap_android_sdk() if z.install_sdk else find_android_sdk()
    if sdk is not None and not z.no_license_check:
        accept_android_licenses(sdk)
    compile_sdk, sdk = select_rebuild_compile_sdk(
        info,
        sdk,
        out / "analysis",
        require_installed=bool(z.install_sdk or z.compile),
        policy=z.sdk_platform_policy,
        platform_cache_dir=z.sdk_platform_cache_dir,
        refresh_aapt2=bool(z.install_sdk),
        max_download_fallbacks=z.sdk_platform_fallbacks,
    )
    info["rebuild_compile_sdk"] = compile_sdk

    # AARs can declare minCompileSdk independently of minSdk. If AAPT2 forces us
    # down to (for example) API 34, also walk dependencies backward to the newest
    # versions whose AAR metadata can compile against that API.
    if resume_project and previous_coords and not z.refresh_dependencies:
        compile_compat_changes = 0
        log("Resume checkpoint: skipping dependency version substitutions")
    else:
        compile_compat_changes = reconcile_selected_compile_sdk(
            selected, coords, compile_sdk, cache, tmp, project_min_sdk=info.get("min_sdk") or 21
        )
        if compile_compat_changes:
            log(f"Dependency compileSdk compatibility substitutions: {compile_compat_changes}")

    if resume_project and previous_coords and not z.refresh_dependencies:
        freshly_resolved_coords = set(coords)
        coords = set(previous_coords)
        log(
            f"Resume checkpoint: froze {len(coords)} dependency coordinate(s) from previous state "
            f"(fresh resolver proposed {len(freshly_resolved_coords)}; use --refresh-dependencies to replace them)"
        )

    if z.add_embedded_deps and embedded:
        before = len(coords)
        have = {(g, a) for g, a, _ in coords}
        for (g, a), (v, _) in embedded.items():
            if (g, a) not in have:
                coords.add((g, a, v))
        log(f"--add-embedded-deps declared {len(coords) - before} extra coordinates")
    # Learning is deferred until after the optional compile probe so a build that
    # proves the dependency set wrong does not get memorised.
    pending_learn = list(selected)

    # Do this BEFORE Gradle. Decoded APK resources often contain copies of
    # dependency attr definitions; once the real AAR is restored, those copies
    # become illegal duplicate attrs. Reconcile against the final dependency set.
    if resume_project and not z.refresh_dependencies:
        log("Resume checkpoint: preserving previously reconciled resource/dependency boundary")
    else:
        reconcile_selected_aar_attrs(main / "res", out / "analysis", selected)
        normalize_value_resources(main / "res", out / "analysis")

    if resume_project and not z.refresh_dependencies and (out / "app/build.gradle").is_file():
        log("Resume checkpoint: preserving existing Gradle build files/classpath")
    else:
        write_gradle(out, info, coords)
    if z.hybrid_shadow == "off" and remove_hybrid_shadow_gradle(out):
        log("Removed prior v26 hybrid-shadow Gradle filter because --hybrid-shadow=off")
    if z.binary_islands != "off":
        if ensure_runtime_artifact_inventory_task(out):
            log("Installed read-only complete runtime JAR/AAR inventory task into preserved Gradle project")
    if z.compile and z.java_repair != "off":
        ensure_full_javac_frontier(out)
    if sdk is not None and (z.install_sdk or z.compile):
        if not z.no_license_check:
            accept_android_licenses(sdk)
        configure_project_sdk(out, sdk, compile_sdk)

    # Decompiled android.* framework classes must not shadow the selected platform.
    # If android.jar contains the exact class, prefer the real platform definition.
    platform_prune_audit = []
    platform_moved = []
    platform_deleted = []
    android_jar_for_sources = resolve_android_jar_from_project(out, compile_sdk)
    if android_jar_for_sources and not resume_project and z.hybrid_shadow == "off":
        platform_prune_audit, platform_moved, platform_deleted = prune_android_platform_sources(
            out, android_jar_for_sources, z.prune
        )
    elif android_jar_for_sources and (resume_project or z.hybrid_shadow != "off"):
        log("Resume/hybrid checkpoint: skipping physical android.* platform-source pruning")
        if platform_prune_audit:
            log(
                f"Platform-source pruning: matched={len(platform_prune_audit)}, "
                f"moved={len(platform_moved)}, deleted={len(platform_deleted)}"
            )
    (out / "analysis").mkdir(parents=True, exist_ok=True)
    (out / "analysis" / "platform-source-pruning.json").write_text(
        json.dumps(platform_prune_audit, indent=2, sort_keys=True)
    )
    hybrid_shadow_jar = None
    hybrid_binary_list = None
    hybrid_app_prefixes = []
    hybrid_force_binary_regexes = []
    hybrid_manifest_roots = []
    hybrid_archive_root = out / "analysis/hybrid-binary-source-archive/java"
    if z.hybrid_shadow != "off":
        hybrid_app_prefixes = list(dict.fromkeys(
            [p for p in (z.app_source_prefix or []) if p]
            or ([info.get("package")] if info.get("package") else [])
        ))
        if not hybrid_app_prefixes:
            warn("--hybrid-shadow requested but no app source prefix could be determined; leaving full source compilation enabled")
        else:
            hybrid_manifest_roots = _manifest_root_classes(apktool_out / "AndroidManifest.xml", info.get("package") or "")
            # Library manifests contribute providers/receivers/services too.  A manifest
            # component is only a strong *source* root when it belongs to one of the
            # explicitly app-owned namespaces; otherwise it should remain eligible for
            # the APK binary shadow just like any other AndroidX/Material provider.
            hybrid_manifest_roots = _filter_manifest_roots_to_app_prefixes(
                hybrid_manifest_roots, hybrid_app_prefixes
            )
            try:
                hybrid_force_binary_regexes = list(z.hybrid_force_binary_regex or [])
                if z.hybrid_obfuscated_binary:
                    hybrid_force_binary_regexes = [*_HYBRID_OBFUSCATED_BINARY_REGEXES, *hybrid_force_binary_regexes]
                    log("Hybrid ownership preset: forcing JADX-style p####/C#### types to APK binary shadow")
                hybrid_shadow_jar, _, hybrid_binary_list = build_hybrid_shadow(
                    out, main / "java", orig, hybrid_app_prefixes, hybrid_manifest_roots,
                    apk_path=apk, permissive=(z.hybrid_shadow == "permissive"),
                    force_binary_regexes=hybrid_force_binary_regexes,
                    extra_source_roots=[hybrid_archive_root],
                    jadx_map=jadx_map,
                )
                q = quarantine_hybrid_binary_sources(
                    out, main / "java", hybrid_binary_list, z.hybrid_binary_source_action
                )
                if q.get("archive_root"):
                    hybrid_archive_root = q["archive_root"]
            except Exception as exc:
                if z.rebuild_apk:
                    die(
                        "Hybrid ABI shadow setup failed; --rebuild-apk requires the validated "
                        "source/binary boundary, so refusing unsafe ordinary-source fallback: " + str(exc)
                    )
                warn(f"Hybrid ABI shadow setup failed; falling back to ordinary source compilation: {exc}")
                hybrid_shadow_jar = hybrid_binary_list = None

    # If the user has apktool framework-res for this API, advertise it so AGP
    # forks that support android.aapt2FrameworkResPath pick it up automatically.
    if sdk is not None:
        fw_for_agp = find_apktool_framework(compile_sdk)
        if fw_for_agp:
            gp = out / "gradle.properties"
            existing = gp.read_text() if gp.exists() else ""
            if "android.aapt2FrameworkResPath=" not in existing:
                gp.write_text(
                    existing
                    + f"\nandroid.aapt2FrameworkResPath={fw_for_agp}\n"
                )
                log(f"Advertised apktool framework-res to AGP: {fw_for_agp}")

    # Direct selections are not the whole Android resource graph. Ask Gradle
    # for the complete runtime AAR set only after SDK/project configuration is
    # complete, then reconcile transitive attrs too.
    if resume_project and not z.refresh_dependencies:
        runtime_aars, runtime_attr_audit = [], []
        log("Resume checkpoint: skipping repeat runtime-AAR/resource reconciliation")
    else:
        runtime_aars, runtime_attr_audit = reconcile_all_gradle_aar_attrs(
            out, main / "res", out / "analysis", selected
        )
        runtime_aars = enrich_runtime_aars_with_classes(runtime_aars, tmp)

    # v25: resource handling needs AARs, but source/dependency ownership needs the
    # complete binary classpath. Inventory transitive JARs too (Guava, Gson, Okio,
    # Kotlin helpers, etc.) so broken decompiled copies can become binary islands.
    runtime_artifacts = []
    if z.binary_islands != "off":
        # Read-only even in resume mode: inspect the *existing* classpath without
        # regenerating dependencies. This is exactly when binary islands are most
        # valuable because a user's manually improved Java tree may still contain
        # damaged decompiled copies of jars already on that classpath.
        runtime_artifacts = resolve_gradle_runtime_artifacts(out, out / "analysis")
        runtime_artifacts = enrich_runtime_aars_with_classes(runtime_artifacts, tmp)
    if not runtime_artifacts and resume_project and not z.refresh_dependencies:
        prior_runtime = previous_report.get("runtime_library_artifacts") or []
        for item in prior_runtime:
            try:
                rec = dict(item)
                if isinstance(rec.get("gav"), list):
                    rec["gav"] = tuple(rec["gav"])
                if isinstance(rec.get("classes"), list):
                    rec["classes"] = set(rec["classes"])
                runtime_artifacts.append(rec)
            except Exception:
                continue
        if runtime_artifacts:
            log(f"Resume checkpoint: runtime task unavailable; restored {len(runtime_artifacts)} persisted JAR/AAR ownership records")
        else:
            log("Resume checkpoint: no runtime JAR/AAR ownership inventory available")

    ownership_selected = selected
    if resume_project and previous_report.get("selected_artifacts") and not z.refresh_dependencies:
        try:
            ownership_selected = []
            for item in previous_report.get("selected_artifacts", []):
                rec = dict(item)
                if isinstance(rec.get("classes"), list):
                    rec["classes"] = set(rec["classes"])
                ownership_selected.append(rec)
            log(f"Resume checkpoint: restored {len(ownership_selected)} prior dependency ownership records")
        except Exception as exc:
            warn(f"Could not restore prior dependency ownership records: {exc}")
            ownership_selected = selected
    # Use the *complete* runtime artifact graph for source ownership. De-duplicate
    # direct selections and runtime records by GAV+type+path while preserving class inventories.
    all_library_artifacts = []
    _artifact_seen = set()
    for _entry in list(ownership_selected) + list(runtime_artifacts):
        _key = (tuple(_entry.get("gav", ())), _entry.get("type"), _entry.get("file"))
        if _key in _artifact_seen:
            continue
        _artifact_seen.add(_key)
        all_library_artifacts.append(_entry)
    library_class_owners = build_library_class_owners(all_library_artifacts)
    log(
        f"Library-source pruning: mode={z.prune}, aggressive={z.aggressive_prune}, "
        f"direct={len(selected)}, runtime-binaries={len(runtime_artifacts)} "
        f"({sum(1 for x in runtime_artifacts if x.get('type') == 'jar')} JAR, "
        f"{sum(1 for x in runtime_artifacts if x.get('type') == 'aar')} AAR)"
    )
    if resume_project or z.hybrid_shadow != "off":
        decisions, moved, deleted = {}, [], []
        if resume_project:
            prune_diagnostics = [
                "resume checkpoint: repeated library-source pruning skipped; existing Java tree is authoritative"
            ]
            log("Resume checkpoint: skipping repeated library-source pruning")
        else:
            prune_diagnostics = [
                "hybrid shadow mode: physical library-source pruning skipped so Java/DEX alias evidence remains available; Gradle excludes binary-owned sources instead"
            ]
            log("Hybrid shadow: preserving decompiled library source on disk; javac filtering replaces physical pruning")
    else:
        decisions, moved, deleted, prune_diagnostics = prune(
            out, source_files, all_library_artifacts, z.prune, z.aggressive_prune
        )
    log(
        f"Pruning result: matched={len(decisions)}, moved={len(moved)}, deleted={len(deleted)}"
    )
    if VERBOSE >= 1:
        for c, d in list(sorted(decisions.items()))[:100]:
            detail(f"{c} -> {d['artifact']} [{d['confidence']}]", 1)
        if len(decisions) > 100:
            detail(f"... and {len(decisions) - 100} more", 1)
    analysis = out / "analysis"
    analysis.mkdir(exist_ok=True)
    if jadx_map.is_file():
        try:
            shutil.copy2(jadx_map, analysis / "jadx-renames.jobf")
        except OSError as exc:
            detail(f"Could not copy JADX JOBF map into analysis: {exc}", 2)
    (analysis / "pruning.log").write_text("\n".join(prune_diagnostics) + "\n")
    (analysis / "pruning-decisions.json").write_text(json.dumps(decisions, indent=2, sort_keys=True))
    (analysis / "selected-library-source-overlap.json").write_text(json.dumps({
        ":".join(sel["gav"]): {
            "jar_class_count": len(sel.get("classes", ())),
            "source_classes_contained": sorted(set(source_files) & {normalize_binary_class(c) for c in sel.get("classes", ())}),
            "transitive": bool(sel.get("transitive")),
        } for sel in all_library_artifacts
    }, indent=2, sort_keys=True))
    (analysis / "dependency-compatibility.json").write_text(
        json.dumps(DEPENDENCY_COMPAT_AUDIT, indent=2, sort_keys=True)
    )
    if VERBOSE >= 2:
        for line in prune_diagnostics:
            detail("PRUNE " + line, 2)
    # Human-readable and machine-readable records of misses/failures.
    unresolved_now = sorted(initial - provided)
    (analysis / "lookup-not-found.log").write_text(
        "".join(f"[{x.get('time')}] {x.get('kind')} {x.get('key')}\n"
                f"  {x.get('url')}\n  {x.get('error')} cached={x.get('cached')}\n"
                for x in LOOKUP_MISSES)
        + ("\nUNRESOLVED IMPORTS\n" + "\n".join(unresolved_now) + "\n" if unresolved_now else "")
    )
    (analysis / "lookup-failures.log").write_text(
        "".join(f"[{x.get('time')}] {x.get('kind')} {x.get('key')}\n"
                f"  {x.get('url')}\n  {x.get('error')}\n"
                for x in LOOKUP_FAILURES)
    )
    (analysis / "lookup-not-found.json").write_text(json.dumps({
        "misses": LOOKUP_MISSES,
        "failures": LOOKUP_FAILURES,
        "unresolved_imports": unresolved_now,
        "persistent_cache": str(LOOKUP_CACHE_PATH),
        "package_index": str(PACKAGE_INDEX_PATH),
        "ranking_policy": "valid/resolvable POM required; exact coverage dominates; package agreement, learned prior, Maven Central relevance, and cached MVNRepository hierarchy/page order are secondary; sparse one-class matches penalized",
    }, indent=2))
    if jadx_proc is not None:
        (analysis / "jadx.log").write_text(jadx_proc.stdout or "")
    if jadx_export_proc is not None:
        (analysis / "jadx-gradle-export.log").write_text(jadx_export_proc.stdout or "")
    if jadx_proc is not None or jadx_export_proc is not None:
        log(f"JADX exit codes: decompile={jadx_proc.returncode if jadx_proc else 'reused'}, gradle-export={jadx_export_proc.returncode if jadx_export_proc else 'reused'}")
    log(
        f"Source scan: {len(source_files)} primary Java classes, {len(imports)} unique imports, {len(bad)} obvious JADX-problem files"
    )
    report_selected = ownership_selected if "ownership_selected" in locals() else selected
    serial_selected = [
        {k: (sorted(v) if k == "classes" else v) for k, v in s.items()}
        for s in report_selected
    ]
    serial_runtime = [
        {k: (sorted(v) if k == "classes" else (list(v) if k == "gav" and isinstance(v, tuple) else v))
         for k, v in r.items()}
        for r in runtime_artifacts
    ]
    result = {
        "metadata": info,
        "selected_artifacts": serial_selected,
        "runtime_library_artifacts": serial_runtime,
        "coordinates": [":".join(x) for x in sorted(coords)],
        "initial_unresolved": sorted(initial),
        "still_unresolved": sorted(initial - provided),
        "queries": queries,
        "prune_mode": z.prune,
        "prune_decisions": decisions,
        "moved": moved,
        "deleted": deleted,
        "jadx_problem_files": bad,
    }
    (analysis / "report.json").write_text(json.dumps(result, indent=2))
    (analysis / "resolved-gradle.txt").write_text(
        "\n".join(f'implementation "{":".join(x)}"' for x in sorted(coords)) + "\n"
    )
    (analysis / "still-unresolved.txt").write_text(
        "\n".join(sorted(initial - provided)) + "\n"
    )
    (analysis / "library-source-pruning.json").write_text(
        json.dumps(
            {"decisions": decisions, "moved": moved, "deleted": deleted}, indent=2
        )
    )
    if hybrid_shadow_jar is not None and hybrid_binary_list is not None:
        try:
            hybrid_cp = write_hybrid_classpath_file(
                out, hybrid_shadow_jar, android_jar_for_sources, all_library_artifacts
            )
            # v27 second-stage semantic link: by this point the Android platform and
            # complete resolved library graph are known. Rebuild the same shadow path
            # while javac can attribute receiver types through framework/dependency
            # classes. The Java engine iterates to a fixed point and re-validates the
            # emitted ABI against DEX before Gradle ever consumes it.
            hybrid_shadow_jar, _, _refined_binary_list = build_hybrid_shadow(
                out, main / "java", orig, hybrid_app_prefixes, hybrid_manifest_roots,
                apk_path=apk, permissive=(z.hybrid_shadow == "permissive"),
                force_binary_regexes=hybrid_force_binary_regexes,
                extra_source_roots=[hybrid_archive_root],
                classpath_file=hybrid_cp,
                jadx_map=jadx_map,
            )
            if _refined_binary_list is not None:
                hybrid_binary_list = _refined_binary_list
            # Refresh the classpath file after replacing the shadow jar at the same path.
            hybrid_cp = write_hybrid_classpath_file(
                out, hybrid_shadow_jar, android_jar_for_sources, all_library_artifacts
            )
            log("Hybrid shadow semantic refinement completed against full javac classpath")
            if z.hybrid_source_normalize:
                run_hybrid_source_normalize(out, main / "java", hybrid_binary_list, hybrid_cp)
            if z.hybrid_java_analysis:
                rc = run_hybrid_javac_analysis(out, main / "java", hybrid_app_prefixes, hybrid_binary_list, hybrid_cp)
                detail(f"Java hybrid attributed analysis exit={rc}; see analysis/java-engine/attributed.jsonl", 1)
        except Exception as exc:
            warn(f"Java hybrid semantic refinement/analysis failed (existing validated shadow retained): {exc}")

    dependency_build_errors = []
    compile_succeeded = False
    if z.compile:
        attempts = max(1, z.resource_repair_attempts)
        if not z.no_resource_preflight:
            run_aapt2_resource_preflight(
                main / "res", analysis, attempts=attempts, api=compile_sdk,
                android_jar=resolve_android_jar_from_project(out, compile_sdk),
                framework_apk=find_apktool_framework(compile_sdk),
            )

        g = shutil.which("gradle")
        wrapper = out / "build-termux.sh"
        gradle_opts = _gradle_cli_options(z)
        if wrapper.exists():
            compile_cmd = [wrapper, *gradle_opts, ":app:compileDebugJavaWithJavac"]
        elif g:
            compile_cmd = [g, "--no-daemon", *gradle_opts, ":app:compileDebugJavaWithJavac"]
        else:
            compile_cmd = None

        if compile_cmd is None:
            (analysis / "compile.log").write_text("gradle not installed; compile skipped\n")
        else:
            compile_cmd = _maybe_wrap_strace(compile_cmd, z, analysis)
            gradle_env = _gradle_execution_env(z, analysis)
            compile_chunks = []
            compile_failure_classifications = []
            final_rc = None
            resource_repairs_used = 0
            javac_targeted_repair_used = False

            java_repair_session = None
            if z.java_repair != "off":
                if SourceRepairSession is None:
                    warn(
                        "Semantic Java repair module is unavailable; falling back to targeted JADX repair only: "
                        + str(_source_repair_import_error)
                    )
                else:
                    java_repair_session = SourceRepairSession(
                        main / "java", analysis,
                        library_class_owners=library_class_owners,
                        mode=z.java_repair,
                        min_confidence=max(0.0, min(1.0, z.java_repair_min_confidence)),
                        max_rounds=max(0, z.java_repair_rounds),
                        max_files=max(1, z.java_repair_max_files),
                        rollback=not z.no_java_repair_rollback,
                        logger=log,
                        tree_trace=z.java_tree_trace,
                    )

            binary_island_manager = None
            if z.binary_islands != "off":
                if BinaryIslandManager is None:
                    warn(
                        "Binary-island module is unavailable; broken dependency source will remain in javac: "
                        + str(_binary_island_import_error)
                    )
                else:
                    binary_island_manager = BinaryIslandManager(
                        out, main / "java", analysis, all_library_artifacts,
                        mode=z.binary_islands, logger=log,
                    )
                    log(
                        f"Binary-island ownership index: {len(all_library_artifacts)} resolved artifact record(s); "
                        f"mode={z.binary_islands}"
                    )
            binary_promotion_attempted_classes = set()

            # Every retry must be justified by a source/resource change or by a rollback.
            # Rollback evaluation can consume an extra compile, hence 2x Java rounds.
            effective_java_rounds = max(0, z.java_repair_rounds) if java_repair_session is not None else 0
            max_build_attempts = 1 + attempts + 1 + (2 * effective_java_rounds)
            attempt = 0
            while attempt < max_build_attempts:
                attempt += 1
                log(f"Gradle compile attempt {attempt}/{max_build_attempts}")
                p = run(compile_cmd, cwd=out, check=False, capture=True, env=gradle_env)
                final_rc = p.returncode
                gradle_output = p.stdout or ""
                compile_chunks.append(
                    f"===== Gradle attempt {attempt} rc={p.returncode} =====\n"
                    + gradle_output + "\n"
                )

                # Evaluate the previous semantic transaction against *this* javac result.
                # A non-improving repair is automatically restored from backup and the
                # exact edit signature is blacklisted for the remainder of this run.
                if java_repair_session is not None:
                    outcome = java_repair_session.observe_build(
                        gradle_output, build_succeeded=(p.returncode == 0)
                    )
                    if outcome.had_pending:
                        log(
                            f"Semantic repair outcome: {outcome.before_errors} -> {outcome.after_errors} javac errors; "
                            + ("ROLLED BACK: " if outcome.rolled_back else "kept: ")
                            + outcome.reason
                        )
                    if outcome.rolled_back:
                        # Source tree is now restored. Recompile it once before proposing
                        # a different repair so we never act on stale diagnostics.
                        continue

                if p.returncode == 0:
                    compile_succeeded = True
                    break

                failure_kind = classify_gradle_compile_failure(gradle_output)
                failed_task = _gradle_failed_task(gradle_output)
                classification = {
                    "attempt": attempt,
                    "returncode": p.returncode,
                    "kind": failure_kind,
                    "failed_task": failed_task,
                    "javac_diagnostics_present": bool(_JAVAC_DIAGNOSTIC_RE.search(gradle_output)),
                }
                compile_failure_classifications.append(classification)
                log(f"Gradle failure classified as: {failure_kind}" + (f" (failed task: {failed_task})" if failed_task else ""))

                if failure_kind == "javac":
                    javac_log = _extract_javac_diagnostics(gradle_output)
                    (analysis / "javac-errors.log").write_text(javac_log or gradle_output)

                    # v25 binary islands: if javac is failing *inside* decompiled
                    # library classes that are already physically present in a
                    # resolved JAR/AAR, stop compiling those damaged copies. Move
                    # the exact artifact/source overlap behind the binary dependency
                    # as one transactional cohort. This mirrors the author's original
                    # source-vs-dependency boundary and is especially effective for
                    # pure-JAR libraries such as Guava that v24 did not inventory.
                    if binary_island_manager is not None:
                        island = binary_island_manager.repair(gradle_output)
                        if island.changed:
                            classification["binary_island_artifact"] = island.plan.artifact if island.plan else None
                            classification["binary_island_files"] = len(island.changed_files)
                            classification["binary_island_error_count"] = island.plan.error_count if island.plan else None
                            if java_repair_session is not None:
                                java_repair_session.register_external_transaction(
                                    gradle_output,
                                    backups=island.backups,
                                    changed_files=island.changed_files,
                                    label="binary-island:" + (island.plan.artifact if island.plan else "unknown"),
                                    metadata={
                                        "artifact": island.plan.artifact if island.plan else None,
                                        "source_classes": island.plan.source_classes if island.plan else [],
                                        "reason": island.plan.reason if island.plan else "",
                                    },
                                )
                            log(
                                f"Binary island applied for {island.plan.artifact if island.plan else 'resolved dependency'}; "
                                f"removed {len(island.changed_files)} decompiled library source file(s) from javac; retrying"
                            )
                            continue

                    # If the failing source looks like a bundled third-party library
                    # but no resolved artifact owns it yet, perform a *late* dependency
                    # search driven only by the classes javac is currently choking on.
                    # This handles the case where a bundled library was considered
                    # local during early reconstruction or was missed by the normal
                    # query budget. Exact physical class coverage is mandatory before
                    # we add the dependency or move any source.
                    if z.binary_islands != "off":
                        _err_counts = javac_error_source_classes(gradle_output, main / "java")
                        _fresh_counts = collections.Counter({
                            fq: n for fq, n in _err_counts.items()
                            if fq not in binary_promotion_attempted_classes
                        })
                        if _fresh_counts:
                            _promoted, _promotion_evidence = discover_binary_artifact_for_error_sources(
                                _fresh_counts, all_library_artifacts, cache, tmp,
                                app_package=info.get("package"), max_classes=12,
                            )
                            binary_promotion_attempted_classes.update(_fresh_counts)
                            _promotion_dir = analysis / "binary-islands"
                            _promotion_dir.mkdir(parents=True, exist_ok=True)
                            with (_promotion_dir / "emergency-discovery.jsonl").open("a") as _fh:
                                _fh.write(json.dumps({
                                    "attempt": attempt,
                                    "error_classes": dict(_fresh_counts),
                                    "selected": ({
                                        "gav": list(_promoted["gav"]),
                                        "file": _promoted.get("file"),
                                        "type": _promoted.get("type"),
                                        "covers": _promoted.get("covers_error_classes"),
                                        "score": _promoted.get("discovery_score"),
                                    } if _promoted else None),
                                    "evidence": [
                                        {"class": fq, "gav": list(gav), "source": source}
                                        for fq, gav, source in _promotion_evidence[:500]
                                    ],
                                }, sort_keys=True) + "\n")
                            if _promoted is not None:
                                _gav = tuple(_promoted["gav"])
                                _added = ensure_gradle_dependency(out, _gav)
                                coords.add(_gav)
                                all_library_artifacts.append(_promoted)
                                library_class_owners = build_library_class_owners(all_library_artifacts)
                                if java_repair_session is not None:
                                    java_repair_session.library_class_owners = library_class_owners
                                log(
                                    f"Emergency binary-island promotion: {':'.join(_gav)} covers "
                                    f"{len(_promoted.get('covers_error_classes', []))} currently failing source class(es)"
                                    + ("; added to Gradle" if _added else "; Gradle already declared it")
                                )
                                if BinaryIslandManager is not None:
                                    binary_island_manager = BinaryIslandManager(
                                        out, main / "java", analysis, all_library_artifacts,
                                        mode=z.binary_islands, logger=log,
                                    )
                                    island = binary_island_manager.repair(gradle_output)
                                    if island.changed:
                                        classification["emergency_binary_island_artifact"] = island.plan.artifact if island.plan else None
                                        classification["emergency_binary_island_files"] = len(island.changed_files)
                                        if java_repair_session is not None:
                                            java_repair_session.register_external_transaction(
                                                gradle_output, backups=island.backups,
                                                changed_files=island.changed_files,
                                                label="binary-island-promoted:" + (island.plan.artifact if island.plan else ":".join(_gav)),
                                                metadata={
                                                    "artifact": ":".join(_gav),
                                                    "covers": _promoted.get("covers_error_classes", []),
                                                    "emergency_promotion": True,
                                                },
                                            )
                                        log(
                                            f"Promoted binary island quarantined {len(island.changed_files)} source file(s); "
                                            "retrying javac against the discovered dependency"
                                        )
                                        continue

                    # One targeted, non-identical retry is allowed when javac points
                    # to source containing JADX's invalid `?? rN`/type artifacts.
                    if not javac_targeted_repair_used and not resume_project:
                        javac_targeted_repair_used = True
                        # Targeted single-class JADX used to sit outside the semantic
                        # rollback system. Snapshot its exact candidate files first so
                        # a 3 -> 1000 style regression can never become a new baseline.
                        targeted_candidates = _javac_jadx_artifact_candidates(
                            gradle_output, main / "java"
                        )
                        targeted_backup_dir = (
                            analysis / "source-repair" / "external-backups" / f"targeted-jadx-attempt-{attempt:03d}"
                        )
                        targeted_backups = {}
                        for candidate_src in targeted_candidates:
                            try:
                                rel = candidate_src.resolve().relative_to((main / "java").resolve())
                                bp = targeted_backup_dir / rel
                                bp.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(candidate_src, bp)
                                targeted_backups[str(candidate_src.resolve())] = str(bp)
                            except Exception as exc:
                                detail(f"Could not snapshot targeted JADX candidate {candidate_src}: {exc}", 2)

                        changed_java, javac_repair_audit = targeted_jadx_javac_repair(
                            gradle_output, main / "java", jadx_command, apk, analysis,
                            no_deobf=z.no_deobf,
                            library_class_owners=library_class_owners,
                            jadx_map=jadx_map,
                            hybrid_binary_sources=hybrid_binary_list,
                        )
                        classification["targeted_jadx_candidates"] = len(javac_repair_audit)
                        classification["targeted_jadx_replacements"] = len(changed_java)
                        if changed_java:
                            if java_repair_session is not None:
                                changed_backup_map = {
                                    str(Path(f).resolve()): targeted_backups[str(Path(f).resolve())]
                                    for f in changed_java
                                    if str(Path(f).resolve()) in targeted_backups
                                }
                                java_repair_session.register_external_transaction(
                                    gradle_output,
                                    backups=changed_backup_map,
                                    changed_files=[str(Path(f).resolve()) for f in changed_java],
                                    label="targeted-jadx",
                                    metadata={"attempt": attempt},
                                )
                            log(
                                f"Targeted JADX repair changed {len(changed_java)} source file(s); "
                                "retrying javac under monotonic rollback protection"
                            )
                            continue
                    elif resume_project and not javac_targeted_repair_used:
                        javac_targeted_repair_used = True
                        log(
                            "Resume checkpoint: targeted JADX source replacement disabled; existing repaired source wins. "
                            "Use --refresh-sources for an intentional re-decompile."
                        )

                    # Targeted re-decompilation preserves the most semantics, so it runs
                    # first.  Once that is exhausted, use javac's diagnostics + the JDK AST
                    # helper to make bounded, confidence-scored structural repairs.
                    if java_repair_session is not None:
                        semantic = java_repair_session.repair(gradle_output)
                        classification["semantic_java_round"] = semantic.round_no
                        classification["semantic_java_edits"] = len(semantic.edits)
                        classification["semantic_java_files"] = len(semantic.changed_files)
                        classification["semantic_java_before_errors"] = semantic.before_error_count
                        if semantic.changed_files:
                            log(
                                f"Semantic Java repair applied {len(semantic.edits)} edit(s) in "
                                f"{len(semantic.changed_files)} file(s); retrying javac"
                            )
                            continue

                    warn(
                        "Javac compilation failed; targeted re-decompilation and semantic source repair "
                        "found no further justified edits. See analysis/javac-errors.log, "
                        "analysis/jadx-targeted-repair.json, and analysis/source-repair/."
                    )
                    break

                # Only genuine resource failures enter the AAPT2 repair path.
                if failure_kind != "resource":
                    warn(
                        f"Gradle failure classified as {failure_kind}; resource auto-repair "
                        "does not apply, so the compile retry loop is stopping"
                    )
                    break

                if resource_repairs_used >= attempts:
                    warn(
                        f"Resource repair limit ({attempts}) reached; stopping compile retry loop"
                    )
                    break

                repaired, repair_audit = diagnose_and_repair_merged_resources(
                    out, analysis, selected + runtime_aars, gradle_output,
                    deep_scan=z.resource_deep_scan,
                )
                if not repaired:
                    # One last source-level pass catches diagnostics that point
                    # directly at app/src/main/res rather than merged.dir.
                    diagnostics = parse_aapt_diagnostics(gradle_output)
                    repaired, direct_audit = repair_source_from_aapt_errors(
                        diagnostics, main / "res", analysis
                    )
                    repair_audit.extend(direct_audit)
                    if repaired:
                        shutil.rmtree(out / "app/build/intermediates", ignore_errors=True)
                        normalize_value_resources(main / "res", analysis)

                if not repaired:
                    # Last-chance: stub missing @android: references that the
                    # current platform jar does not expose.
                    extra_diags = parse_aapt_diagnostics(gradle_output)
                    extra, extra_audit = stub_missing_android_references(
                        extra_diags, main / "res", analysis
                    )
                    repair_audit.extend(extra_audit)
                    if extra:
                        repaired = True
                        shutil.rmtree(out / "app/build/intermediates", ignore_errors=True)
                        normalize_value_resources(main / "res", analysis)

                # Never rerun the exact same failed build.
                if not repaired:
                    warn(
                        "Resource compilation failed, but no safe automatic resource repair "
                        "was found; stopping instead of rerunning an identical build"
                    )
                    break

                resource_repairs_used += 1
                classification["resource_repair_applied"] = True
                classification["resource_repairs_used"] = resource_repairs_used
                if not z.no_resource_preflight:
                    run_aapt2_resource_preflight(
                        main / "res", analysis, attempts=attempts, api=compile_sdk,
                        android_jar=resolve_android_jar_from_project(out, compile_sdk),
                        framework_apk=find_apktool_framework(compile_sdk),
                    )

            if java_repair_session is not None:
                java_repair_session.finalize()

            full_compile_log = "".join(compile_chunks)
            (analysis / "compile-failure-classification.json").write_text(
                json.dumps(compile_failure_classifications, indent=2, sort_keys=True)
            )
            dependency_build_errors = sorted(set(re.findall(
                r"(Duplicate class [\w.$]+ found in modules [^\n]+|Could not (?:resolve|find) [\w.:\-]+)",
                full_compile_log)))[:50]
            (analysis / "compile.log").write_text(full_compile_log)
            (analysis / "gradle-deprecations.log").write_text(
                _extract_deprecation_context(full_compile_log)
            )
            if z.trace_gradle:
                _summarize_jfr(analysis)
            if final_rc:
                warn(f"Gradle compile still exits {final_rc}; see analysis/compile.log and resource diagnostics")
    if z.rebuild_apk:
        if not z.compile:
            die("--rebuild-apk requires --compile so the replacement .class files are known-good")
        if z.hybrid_shadow == "off":
            die("--rebuild-apk currently requires --hybrid-shadow safe|permissive")
        if not compile_succeeded:
            die("--rebuild-apk refused because compileDebugJavaWithJavac did not succeed")
        if HybridApkRebuilder is None:
            die("v28 hybrid APK module unavailable: " + str(_hybrid_apk_import_error))
        log("v28: javac succeeded; rebuilding hybrid runtime APK from original DEX + source-owned replacements")
        try:
            hybrid_result = HybridApkRebuilder.rebuild(
                apk, out,
                dexlib_jar=z.dexlib_jar,
                tools_dir=z.tools_dir.expanduser(),
                output=z.hybrid_apk_output,
                sign=z.hybrid_apk_sign,
            )
            produced = hybrid_result.get("signed_apk") or hybrid_result.get("package", {}).get("output")
            log("v28 hybrid APK ready: " + str(produced))
        except Exception as exc:
            die("v28 hybrid APK rebuild failed after successful javac: " + str(exc))

    if dependency_build_errors and not z.learn_from_failed_builds:
        warn(f"Not learning from this run: Gradle reported {len(dependency_build_errors)} "
             f"dependency errors (see analysis/dependency-build-errors.txt)")
        (analysis / "dependency-build-errors.txt").write_text("\n".join(dependency_build_errors) + "\n")
    else:
        learn_package_index(pending_learn)
        learn_package_map(pending_learn)
    (analysis / "shaded-rejections.json").write_text(json.dumps(SHADED_REJECTIONS, indent=2))
    (out / "README.md").write_text("""# Reconstructed APK project
This is a best-effort reconstruction, not original source.
Library sources are moved by default to `removed-library-sources/`.
See `analysis/report.json` and `analysis/library-source-pruning.json` for the audit trail.
Use `--prune delete` only when you accept destructive pruning.

Diagnostics:
- `analysis/compile-sdk-selection.json` records every installed SDK platform and its AAPT2 include probe.
- `analysis/gradle-environment.json` records the effective Java/SDK/Gradle environment.
- `analysis/gradle-deprecations.log` extracts concrete Gradle deprecation warnings.
- `analysis/source-repair/` contains semantic Java repair rounds, exact edits, backups, rollback history, and helper logs.
- Semantic Java repair is javac-guided and uses the JDK compiler-tree parser; `--java-repair safe` disables destructive edits.
- `--trace-processes` records execve() calls to `analysis/process-exec.log`.
- `--trace-gradle` records JFR samples to `analysis/gradle.jfr` and extracts AGP/Gradle stacks.
""")
    if not z.keep_work:
        shutil.rmtree(work_dir, ignore_errors=True)
    print(out)
    print(
        f"deps={len(coords)} unresolved={len(initial - provided)} library matches={len(decisions)} moved={len(moved)} deleted={len(deleted)}"
    )


if __name__ == "__main__":
    main()
