#!/usr/bin/env python3
"""Pinned apk2project toolchain bootstrap.

apk2project owns the versions of binary tools that materially affect its
reconstruction/runtime pipeline.  Callers choose only the cache root; they do not
inject individual jars or discover arbitrary system/Gradle/Maven copies.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import urllib.request
import zipfile
from pathlib import Path

APKTOOL_VERSION = "3.0.3"
JADX_VERSION = "1.5.6"
DEXLIB_VERSION = "3.0.10"

APKTOOL_URL = (
    f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VERSION}/"
    f"apktool_{APKTOOL_VERSION}.jar"
)
JADX_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"
APKTOOL_SHA256 = "dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423"
JADX_SHA256 = "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"

DEXLIB_PREFIX = "com/android/tools/smali/dexlib2"
DEXLIB_REQUIRED_SUFFIXES = (
    "Opcodes.class",
    "dexbacked/DexBackedDexFile.class",
    "iface/ClassDef.class",
    "iface/DexFile.class",
    "writer/pool/DexPool.class",
)

# Pinned public runtime surface used by DexHybridRebuilder.  These exact artifacts
# are kept together under tools/dexlib2-<version>/ so runtime classpath assembly is
# deterministic and never depends on Apktool shading or a user's Gradle/Maven cache.
DEXLIB_BUNDLE = (
    (
        f"smali-dexlib2-{DEXLIB_VERSION}.jar",
        f"https://dl.google.com/dl/android/maven2/com/android/tools/smali/smali-dexlib2/{DEXLIB_VERSION}/smali-dexlib2-{DEXLIB_VERSION}.jar",
    ),
    (
        "guava-31.1-android.jar",
        "https://repo1.maven.org/maven2/com/google/guava/guava/31.1-android/guava-31.1-android.jar",
    ),
    (
        "failureaccess-1.0.1.jar",
        "https://repo1.maven.org/maven2/com/google/guava/failureaccess/1.0.1/failureaccess-1.0.1.jar",
    ),
    (
        "listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
        "https://repo1.maven.org/maven2/com/google/guava/listenablefuture/9999.0-empty-to-avoid-conflict-with-guava/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
    ),
    (
        "jsr305-3.0.2.jar",
        "https://repo1.maven.org/maven2/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar",
    ),
    (
        "checker-qual-3.12.0.jar",
        "https://repo1.maven.org/maven2/org/checkerframework/checker-qual/3.12.0/checker-qual-3.12.0.jar",
    ),
    (
        "error_prone_annotations-2.11.0.jar",
        "https://repo1.maven.org/maven2/com/google/errorprone/error_prone_annotations/2.11.0/error_prone_annotations-2.11.0.jar",
    ),
    (
        "j2objc-annotations-1.3.jar",
        "https://repo1.maven.org/maven2/com/google/j2objc/j2objc-annotations/1.3/j2objc-annotations-1.3.jar",
    ),
)

USER_AGENT = "apk2project-v29"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def valid_zip(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            return any(not n.endswith("/") for n in zf.namelist())
    except Exception:
        return False


def download_atomic(url: str, dest: Path) -> Path:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + f".{os.getpid()}.part")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=90) as response, tmp.open("wb") as out:
            shutil.copyfileobj(response, out)
        if not valid_zip(tmp):
            raise RuntimeError(f"downloaded tool is not a valid ZIP/JAR: {url}")
        tmp.replace(dest)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
    return dest


def ensure_apktool(tools_dir: Path) -> Path:
    tools_dir = Path(tools_dir).expanduser()
    jar = tools_dir / f"apktool_{APKTOOL_VERSION}.jar"
    if not valid_zip(jar):
        print(f"[*] tools: downloading pinned Apktool {APKTOOL_VERSION}")
        download_atomic(APKTOOL_URL, jar)
    digest = sha256(jar)
    if digest != APKTOOL_SHA256:
        raise RuntimeError(
            f"pinned Apktool SHA-256 mismatch for {jar}: {digest} != {APKTOOL_SHA256}"
        )
    return jar.resolve()


def ensure_jadx(tools_dir: Path) -> Path:
    tools_dir = Path(tools_dir).expanduser()
    root = tools_dir / f"jadx-{JADX_VERSION}"
    launcher = root / "bin" / "jadx"
    if not launcher.is_file():
        archive = tools_dir / f"jadx-{JADX_VERSION}.zip"
        if not valid_zip(archive):
            print(f"[*] tools: downloading pinned JADX {JADX_VERSION}")
            download_atomic(JADX_URL, archive)
        digest = sha256(archive)
        if digest != JADX_SHA256:
            raise RuntimeError(
                f"pinned JADX SHA-256 mismatch for {archive}: {digest} != {JADX_SHA256}"
            )
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(root)
        if not launcher.is_file():
            hits = list(root.rglob("bin/jadx"))
            if hits:
                launcher = hits[0]
    if not launcher.is_file():
        raise RuntimeError(f"could not locate JADX {JADX_VERSION} launcher after extraction under {root}")
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)
    return launcher.resolve()


def ensure_decompiler_tools(tools_dir: Path) -> tuple[Path, Path]:
    """Return apktool jar + JADX launcher from apk2project's pinned cache."""
    return ensure_apktool(tools_dir), ensure_jadx(tools_dir)


def _validate_dexlib_primary(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
    except Exception as exc:
        raise RuntimeError(f"invalid pinned dexlib2 jar: {path}: {exc}") from exc
    missing = [suffix for suffix in DEXLIB_REQUIRED_SUFFIXES if f"{DEXLIB_PREFIX}/{suffix}" not in names]
    if missing:
        raise RuntimeError(f"pinned dexlib2 jar is missing required public API classes: {', '.join(missing)}")


def ensure_dexlib_classpath(tools_dir: Path) -> list[Path]:
    """Return apk2project's exact pinned standalone smali-dexlib2 runtime bundle."""
    bundle = Path(tools_dir).expanduser() / f"dexlib2-{DEXLIB_VERSION}"
    bundle.mkdir(parents=True, exist_ok=True)
    result: list[Path] = []
    for filename, url in DEXLIB_BUNDLE:
        path = bundle / filename
        if not valid_zip(path):
            print(f"[*] tools: downloading pinned dexlib dependency {filename}")
            download_atomic(url, path)
        result.append(path.resolve())
    _validate_dexlib_primary(result[0])
    return result


def tool_versions() -> dict[str, str]:
    return {
        "apktool": APKTOOL_VERSION,
        "jadx": JADX_VERSION,
        "smali-dexlib2": DEXLIB_VERSION,
    }
