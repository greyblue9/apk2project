from __future__ import annotations

import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Any

JAVA_DIAG_RE = re.compile(
    r"^(?P<file>.*?\.java):(?P<line>\d+)(?::(?P<column>\d+))?:\s*(?P<severity>error|warning):\s*(?P<message>.*)$"
)
SYMBOL_RE = re.compile(r"^\s*symbol:\s*(?P<kind>class|variable|method|constructor)\s+(?P<name>.+?)\s*$", re.I)
LOCATION_RE = re.compile(r"^\s*location:\s*(?P<location>.+?)\s*$", re.I)
PACKAGE_RE = re.compile(r"(?m)^\s*package\s+([\w.$]+)\s*;")
IMPORT_RE = re.compile(r"(?m)^\s*import\s+(?:static\s+)?([\w.$*]+)\s*;")
TYPE_RE = re.compile(r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)")
METHOD_DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:@[\w.$()\", ={}]+\s*)*"
    r"(?:(?:public|protected|private|static|final|synchronized|abstract|native|strictfp|default)\s+)*"
    r"(?P<ret>[A-Za-z_$][\w.$<>?, \[\]&]*?)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^;{}()]*)\)\s*(?:throws\s+[^\{;]+)?[\{;]"
)
FIELD_DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:public|protected|private|static|final|volatile|transient)\s+)*"
    r"(?P<type>[A-Za-z_$][\w.$<>?, \[\]&]*)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?:=|;)"
)

SYNTAX_MARKERS = (
    "illegal start of expression", "illegal start of type", "not a statement",
    "<identifier> expected", "';' expected", "class, interface, enum, or record expected",
    "reached end of file while parsing", "initializers not allowed in interfaces",
    "orphaned case", "case, default, or } expected", "else without if", "try without catch",
)

@dataclass(frozen=True)
class JavacDiagnostic:
    file: str
    line: int
    column: int | None
    severity: str
    message: str
    symbol_kind: str | None = None
    symbol_name: str | None = None
    location: str | None = None
    context: tuple[str, ...] = ()

    def key(self) -> tuple:
        # Deliberately omit absolute path prefix noise and source column drift.
        return (Path(self.file).name, self.line, self.severity, self.message, self.symbol_kind, self.symbol_name)

@dataclass
class Evidence:
    type_name: str
    score: float
    reason: str

@dataclass
class Edit:
    file: str
    start: int
    end: int
    replacement: str
    kind: str
    confidence: float
    reason: str
    diagnostic: dict | None = None
    destructive: bool = False

    def signature(self) -> str:
        raw = f"{self.file}\0{self.start}\0{self.end}\0{self.replacement}\0{self.kind}"
        return hashlib.sha256(raw.encode()).hexdigest()[:20]

    def strategy_key(self) -> str:
        """Stable key for one repair strategy against one compiler diagnostic.

        Unlike signature(), this deliberately ignores source offsets/replacement text so
        repeated variants of a strategy can be throttled after multiple failed attempts.
        """
        d = self.diagnostic or {}
        diag = (
            Path(str(d.get("file", ""))).name, d.get("line"), d.get("message"),
            d.get("symbol_kind"), d.get("symbol_name"),
        )
        raw = f"{self.kind}\0{self.file}\0{diag!r}"
        return hashlib.sha256(raw.encode()).hexdigest()[:20]

@dataclass
class RepairResult:
    changed_files: list[str] = field(default_factory=list)
    edits: list[Edit] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    before_error_count: int = 0
    fingerprint: str = ""
    round_no: int = 0

@dataclass
class ObserveResult:
    had_pending: bool = False
    rolled_back: bool = False
    committed: bool = False
    before_errors: int = 0
    after_errors: int = 0
    reason: str = ""

@dataclass
class ProjectIndex:
    by_simple_type: dict[str, set[str]] = field(default_factory=lambda: collections.defaultdict(set))
    method_owners: dict[str, set[str]] = field(default_factory=lambda: collections.defaultdict(set))
    method_params: dict[str, list[tuple[str, tuple[str, ...]]]] = field(default_factory=lambda: collections.defaultdict(list))
    method_returns: dict[str, list[tuple[str, str]]] = field(default_factory=lambda: collections.defaultdict(list))
    field_owners: dict[str, set[str]] = field(default_factory=lambda: collections.defaultdict(set))
    field_defs: dict[str, list[tuple[str, str, str]]] = field(default_factory=lambda: collections.defaultdict(list))
    methods_by_owner: dict[str, set[str]] = field(default_factory=lambda: collections.defaultdict(set))
    type_files: dict[str, str] = field(default_factory=dict)
    type_extends: dict[str, str] = field(default_factory=dict)
    file_primary: dict[str, str] = field(default_factory=dict)
    raw_to_source: dict[str, str] = field(default_factory=dict)
    source_to_raw: dict[str, str] = field(default_factory=dict)

    @classmethod
    def build(cls, root: Path, ignored_files: set[str] | None = None) -> "ProjectIndex":
        idx = cls()
        ignored_files = {str(Path(x).resolve()) for x in (ignored_files or set())}
        for path in root.rglob("*.java"):
            if str(path.resolve()) in ignored_files:
                continue
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            pkgm = PACKAGE_RE.search(text)
            pkg = pkgm.group(1) if pkgm else ""
            tm = TYPE_RE.search(text)
            if not tm:
                continue
            simple = tm.group(1)
            fq = f"{pkg}.{simple}" if pkg else simple
            idx.file_primary[str(path.resolve())] = fq
            idx.type_files[fq] = str(path.resolve())
            idx.by_simple_type[simple].add(fq)
            raw_fq = jadx_alias_to_raw_fqcn(fq)
            idx.source_to_raw[fq] = raw_fq
            # Prefer the first source spelling for a raw DEX name. In practice this
            # is the canonical JADX alias used consistently across the tree.
            idx.raw_to_source.setdefault(raw_fq, fq)
            head = text[tm.start(): text.find("{", tm.end()) if text.find("{", tm.end()) >= 0 else min(len(text), tm.end()+1000)]
            em = re.search(r"\bextends\s+([A-Za-z_$][\w.$<>?, ]*)", head)
            if em:
                idx.type_extends[fq] = _clean_type(em.group(1))
            # Lexical global indexes are evidence only; actual edits still target
            # AST ranges from javac's parser.
            for mm in METHOD_DECL_RE.finditer(text):
                name = mm.group("name")
                if name in {"if", "for", "while", "switch", "catch", "return", "new", "throw"}:
                    continue
                idx.method_owners[name].add(fq)
                idx.methods_by_owner[fq].add(name)
                idx.method_returns[name].append((fq, _clean_type(mm.group("ret"))))
                params = []
                raw = mm.group("params").strip()
                if raw:
                    for p in _split_top_level(raw, ','):
                        p = re.sub(r"\bfinal\s+", "", p.strip())
                        p = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", p)
                        bits = p.rsplit(None, 1)
                        if len(bits) == 2:
                            params.append(bits[0].strip())
                idx.method_params[name].append((fq, tuple(params)))
            # Exclude obvious locals by requiring declaration before first method-ish
            # brace would be ideal; false positives only lower uniqueness confidence.
            for fm in FIELD_DECL_RE.finditer(text[: min(len(text), 25000)]):
                idx.field_owners[fm.group("name")].add(fq)
                idx.field_defs[fq].append((fm.group("name"), _clean_type(fm.group("type")), str(path.resolve())))
        return idx


_JADX_CLASS_ALIAS_RE = re.compile(r"^(?:(?:Abstract|Interface|Enum|Runnable|Callable|Comparator|Iterator|View|Dialog|Activity|Fragment|Service|Receiver|Adapter|Builder|Factory|Listener|Callback|Manager|Provider|Controller|Layout|Behavior|Exception|Error|Task|Thread)?C\d+)(.+)$")
_JADX_PKG_ALIAS_RE = re.compile(r"^p\d+(.+)$")
_JADX_METHOD_ALIAS_RE = re.compile(r"^m\d+(.+)$")
_JADX_FIELD_ALIAS_RE = re.compile(r"^f\d+(.+)$")


def jadx_alias_simple_to_raw(name: str) -> str:
    """Best-effort inverse of JADX's generated deobfuscation aliases.

    Examples seen in reconstructed APKs:
      p036i1.AbstractC0570m -> i1.m
      androidx.emoji2.text.C0115w -> androidx.emoji2.text.w
      AbstractC0391b1 -> b1
    """
    if not name:
        return name
    # Preserve nested binary suffixes while decoding each component.
    parts = name.split('$')
    out = []
    for part in parts:
        m = _JADX_CLASS_ALIAS_RE.match(part)
        out.append(m.group(1) if m and m.group(1) else part)
    return '$'.join(out)


def jadx_alias_to_raw_fqcn(fqcn: str) -> str:
    if not fqcn:
        return fqcn
    parts = fqcn.split('.')
    # Package aliases are only used for leading package segments. The final segment
    # is a class and gets the class-alias inverse above.
    out = []
    for i, part in enumerate(parts):
        if i < len(parts) - 1:
            m = _JADX_PKG_ALIAS_RE.match(part)
            out.append(m.group(1) if m and m.group(1) else part)
        else:
            out.append(jadx_alias_simple_to_raw(part))
    return '.'.join(out)


def jadx_member_to_raw(name: str, kind: str) -> str:
    if kind == 'method':
        m = _JADX_METHOD_ALIAS_RE.match(name or '')
        return m.group(1) if m and m.group(1) else name
    if kind == 'field':
        m = _JADX_FIELD_ALIAS_RE.match(name or '')
        return m.group(1) if m and m.group(1) else name
    return name


def _parse_descriptor_one(desc: str, pos: int = 0) -> tuple[str, int]:
    arrays = 0
    while pos < len(desc) and desc[pos] == '[':
        arrays += 1; pos += 1
    if pos >= len(desc):
        return ('java.lang.Object' + '[]' * arrays, pos)
    ch = desc[pos]
    prim = {'V':'void','Z':'boolean','B':'byte','S':'short','C':'char','I':'int','J':'long','F':'float','D':'double'}
    if ch in prim:
        return (prim[ch] + '[]' * arrays, pos + 1)
    if ch == 'L':
        end = desc.find(';', pos)
        if end < 0:
            end = len(desc)
        raw = desc[pos + 1:end].replace('/', '.')
        return (raw + '[]' * arrays, min(len(desc), end + 1))
    return ('java.lang.Object' + '[]' * arrays, pos + 1)


def _parse_method_descriptor(args_desc: str, ret_desc: str) -> tuple[list[str], str]:
    args = []
    pos = 0
    while pos < len(args_desc):
        t, nxt = _parse_descriptor_one(args_desc, pos)
        if nxt <= pos: break
        args.append(t); pos = nxt
    ret, _ = _parse_descriptor_one(ret_desc, 0)
    return args, ret


@dataclass
class SmaliField:
    raw_name: str
    type_raw: str
    flags: set[str]


@dataclass
class SmaliMethod:
    raw_name: str
    args_raw: list[str]
    return_raw: str
    flags: set[str]


@dataclass
class SmaliClass:
    raw_fqcn: str
    flags: set[str] = field(default_factory=set)
    super_raw: str | None = None
    interfaces_raw: list[str] = field(default_factory=list)
    fields: list[SmaliField] = field(default_factory=list)
    methods: list[SmaliMethod] = field(default_factory=list)
    path: str | None = None


def _project_root_from_java_root(java_root: Path) -> Path:
    p = Path(java_root).resolve()
    # Canonical reconstructed layout: <project>/app/src/main/java.
    try:
        if p.name == "java" and p.parent.name == "main" and p.parent.parent.name == "src" and p.parent.parent.parent.name == "app":
            return p.parent.parent.parent.parent
    except Exception:
        pass
    # Tests and custom layouts may be shallower.
    return p.parent


class SmaliOracle:
    """Use apktool's original smali as an exact symbol oracle.

    Decompiled Java can lose declarations, merge registers, or use inconsistent JADX
    aliases. Smali is the APK's own bytecode representation and therefore answers a
    much narrower, safer question: *did this class/field/method actually exist in the
    DEX, and what was its JVM type signature?*
    """
    def __init__(self, java_root: Path, index: ProjectIndex | None = None):
        self.java_root = Path(java_root).resolve()
        self.project_root = _project_root_from_java_root(self.java_root)
        self.original = self.project_root / 'original'
        self.index = index
        self._class_cache: dict[str, SmaliClass | None] = {}
        self._smali_dirs = []
        if self.original.is_dir():
            self._smali_dirs = [p for p in self.original.iterdir() if p.is_dir() and (p.name == 'smali' or p.name.startswith('smali_classes'))]

    def set_index(self, index: ProjectIndex):
        self.index = index

    def _raw_to_source_type(self, raw: str, *, current_fq: str | None = None) -> str:
        suffix = ''
        while raw.endswith('[]'):
            suffix += '[]'; raw = raw[:-2]
        primitive = {'void','boolean','byte','short','char','int','long','float','double'}
        if raw in primitive:
            return raw + suffix
        if raw == 'java.lang.String': return 'String' + suffix
        if raw == 'java.lang.Object': return 'Object' + suffix
        if self.index:
            hit = self.index.raw_to_source.get(raw)
            if hit:
                if current_fq and hit.rsplit('.',1)[0] == current_fq.rsplit('.',1)[0]:
                    return hit.rsplit('.',1)[-1].replace('$', '.') + suffix
                return hit.replace('$', '.') + suffix
        return raw.replace('$', '.') + suffix

    def _candidate_path(self, raw_fqcn: str) -> Path | None:
        rel = Path(*raw_fqcn.split('.')).with_suffix('.smali')
        for d in self._smali_dirs:
            p = d / rel
            if p.is_file(): return p
        # Inner classes and odd multidex layouts can foil direct lookup; basename
        # fallback is intentionally constrained to the expected package tail.
        tail = rel.as_posix()
        for d in self._smali_dirs:
            hits = list(d.rglob(rel.name))
            for h in hits[:100]:
                if h.as_posix().endswith(tail): return h
        return None

    def get_class(self, source_or_raw_fqcn: str) -> SmaliClass | None:
        raw = source_or_raw_fqcn
        if self.index and source_or_raw_fqcn in self.index.source_to_raw:
            raw = self.index.source_to_raw[source_or_raw_fqcn]
        else:
            raw = jadx_alias_to_raw_fqcn(source_or_raw_fqcn)
        if raw in self._class_cache:
            return self._class_cache[raw]
        p = self._candidate_path(raw)
        if not p:
            self._class_cache[raw] = None; return None
        try:
            lines = p.read_text(errors='ignore').splitlines()
        except OSError:
            self._class_cache[raw] = None; return None
        c = SmaliClass(raw_fqcn=raw, path=str(p))
        for line in lines:
            st = line.strip()
            if st.startswith('.class '):
                bits = st.split()
                c.flags = set(x for x in bits[1:-1] if not x.startswith('L'))
            elif st.startswith('.super '):
                d = st.split(None,1)[1]
                c.super_raw = _parse_descriptor_one(d,0)[0]
            elif st.startswith('.implements '):
                d = st.split(None,1)[1]
                c.interfaces_raw.append(_parse_descriptor_one(d,0)[0])
            elif st.startswith('.field '):
                m = re.match(r'^\.field\s+(?P<head>.+?)\s+(?P<name>[^\s:]+):(?P<desc>\S+)', st)
                if m:
                    flags = set(m.group('head').split())
                    typ,_ = _parse_descriptor_one(m.group('desc'),0)
                    c.fields.append(SmaliField(m.group('name'), typ, flags))
            elif st.startswith('.method '):
                m = re.match(r'^\.method\s+(?P<head>.*?)\s*(?P<name>[^\s(]+)\((?P<args>[^)]*)\)(?P<ret>\S+)', st)
                if m:
                    flags = set(m.group('head').split())
                    args, ret = _parse_method_descriptor(m.group('args'), m.group('ret'))
                    c.methods.append(SmaliMethod(m.group('name'), args, ret, flags))
        self._class_cache[raw] = c
        return c

    def field(self, source_fqcn: str, alias_name: str) -> SmaliField | None:
        c = self.get_class(source_fqcn)
        if not c: return None
        raw = jadx_member_to_raw(alias_name, 'field')
        hits = [f for f in c.fields if f.raw_name == raw]
        return hits[0] if len(hits) == 1 else None

    def methods(self, source_fqcn: str, alias_name: str) -> list[SmaliMethod]:
        c = self.get_class(source_fqcn)
        if not c: return []
        raw = jadx_member_to_raw(alias_name, 'method')
        return [m for m in c.methods if m.raw_name == raw]

    def java_type(self, raw: str, current_fq: str | None = None) -> str:
        return self._raw_to_source_type(raw, current_fq=current_fq)

    def class_exists(self, source_fqcn: str) -> bool:
        return self.get_class(source_fqcn) is not None

    def source_name_for_raw(self, raw: str, current_fq: str | None = None) -> str:
        return self._raw_to_source_type(raw, current_fq=current_fq)

    @staticmethod
    def _raw_simple(raw: str) -> str:
        return raw.rsplit('.', 1)[-1].rsplit('$', 1)[-1]

    def _target_matches_raw(self, target: str, raw: str) -> bool:
        """Loose-but-safe identity check for a Java/JADX name vs a DEX name."""
        tb = _base_type(target or '').replace('$', '.')
        if not tb:
            return False
        # Exact source spelling when our reconstructed index knows this class.
        if self.index:
            hit = self.index.raw_to_source.get(raw)
            if hit and (tb == hit.replace('$', '.') or tb.rsplit('.', 1)[-1] == hit.rsplit('.', 1)[-1].split('$')[-1]):
                return True
        raw_java = raw.replace('$', '.')
        if tb == raw_java:
            return True
        # Normal framework/library names generally survive JADX unchanged.
        if tb.rsplit('.', 1)[-1] == self._raw_simple(raw):
            return True
        # Obfuscated source aliases encode the original raw single-letter/member
        # name after C####/AbstractC####/etc.
        if jadx_alias_simple_to_raw(tb.rsplit('.', 1)[-1]) == self._raw_simple(raw):
            return True
        return False

    def assignability_path(self, source_fqcn: str, target: str, max_depth: int = 20) -> list[str] | None:
        """Return a DEX hierarchy path proving source is assignable to target.

        This is intentionally an oracle query, not Java-source inference. It lets us
        repair a lost `implements`/`extends` clause when javac says two reconstructed
        types are unrelated even though the APK bytecode says they are related.
        """
        start = self.get_class(source_fqcn)
        if not start:
            return None
        q = collections.deque([(start.raw_fqcn, [start.raw_fqcn], 0)])
        seen = set()
        while q:
            raw, path, depth = q.popleft()
            if raw in seen or depth > max_depth:
                continue
            seen.add(raw)
            if self._target_matches_raw(target, raw):
                return path
            c = self.get_class(raw)
            if not c:
                continue
            parents = ([c.super_raw] if c.super_raw else []) + list(c.interfaces_raw)
            for parent in parents:
                if not parent:
                    continue
                if self._target_matches_raw(target, parent):
                    return path + [parent]
                if parent not in seen:
                    q.append((parent, path + [parent], depth + 1))
        return None


def _split_top_level(text: str, sep: str) -> list[str]:
    out, cur = [], []
    angle = paren = bracket = brace = 0
    quote = None
    esc = False
    for ch in text:
        if quote:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in "\"'": quote = ch
        elif ch == '<': angle += 1
        elif ch == '>': angle = max(0, angle - 1)
        elif ch == '(': paren += 1
        elif ch == ')': paren = max(0, paren - 1)
        elif ch == '[': bracket += 1
        elif ch == ']': bracket = max(0, bracket - 1)
        elif ch == '{': brace += 1
        elif ch == '}': brace = max(0, brace - 1)
        if ch == sep and not (angle or paren or bracket or brace):
            out.append(''.join(cur)); cur = []
        else:
            cur.append(ch)
    out.append(''.join(cur))
    return out


def parse_javac_diagnostics(text: str) -> list[JavacDiagnostic]:
    lines = (text or "").splitlines()
    out: list[JavacDiagnostic] = []
    i = 0
    while i < len(lines):
        m = JAVA_DIAG_RE.match(lines[i].strip())
        if not m:
            i += 1
            continue
        base = m.groupdict()
        context = [lines[i]]
        symbol_kind = symbol_name = location = None
        j = i + 1
        while j < len(lines) and j <= i + 8:
            if JAVA_DIAG_RE.match(lines[j].strip()):
                break
            line = lines[j]
            # Stop at Gradle task/report boundaries, but keep source/caret/symbol lines.
            if line.startswith("> Task ") or line.startswith("FAILURE:") or line.startswith("Execution failed"):
                break
            context.append(line)
            sm = SYMBOL_RE.match(line)
            if sm:
                symbol_kind, symbol_name = sm.group("kind").lower(), sm.group("name").strip()
            lm = LOCATION_RE.match(line)
            if lm:
                location = lm.group("location").strip()
            j += 1
        out.append(JavacDiagnostic(
            file=base["file"], line=int(base["line"]),
            column=int(base["column"]) if base.get("column") else None,
            severity=base["severity"], message=base["message"].strip(),
            symbol_kind=symbol_kind, symbol_name=symbol_name, location=location,
            context=tuple(context),
        ))
        i = max(i + 1, j)
    return out


def diagnostic_fingerprint(diags: Iterable[JavacDiagnostic]) -> str:
    keys = sorted(repr(d.key()) for d in diags if d.severity == "error")
    return hashlib.sha256("\n".join(keys).encode()).hexdigest()[:24]


def _diagnostic_weight(d: JavacDiagnostic) -> int:
    """Estimate how early/severe a javac failure is. Lower is better.

    Error count is always the primary objective. This weight is used only to decide
    whether an equal-count diagnostic frontier is actually an improvement.
    """
    text = (d.message + "\n" + "\n".join(d.context)).lower()
    if any(x in text for x in SYNTAX_MARKERS):
        return 100
    if "package does not exist" in text or (d.symbol_kind == "class" and "cannot find symbol" in text):
        return 70
    if "cannot find symbol" in text:
        return 55
    if "constructor" in text and "cannot be applied" in text:
        return 45
    if "incompatible types" in text:
        return 40
    if "does not override or implement" in text:
        return 35
    if "missing return statement" in text or "might not have been initialized" in text:
        return 30
    return 50


def diagnostic_cost(diags: Iterable[JavacDiagnostic]) -> tuple[int, int, int]:
    """Lexicographic compiler-state score. Smaller is better.

    1) total errors dominates everything; a 33 -> 100 transition is *always* worse.
    2) with equal counts, prefer later/less structural diagnostics.
    3) finally prefer errors concentrated in fewer source files.
    """
    ds = [d for d in diags if d.severity == "error"]
    files = len({str(Path(d.file)) for d in ds})
    return (len(ds), sum(_diagnostic_weight(d) for d in ds), files)



def _is_frontier_blocker(d: JavacDiagnostic) -> bool:
    text=(d.message+'\n'+'\n'.join(d.context)).lower()
    if any(x in text for x in SYNTAX_MARKERS): return True
    if 'must be first statement in constructor' in text: return True
    if 'cyclic inheritance' in text or 'cannot access' in text and 'bad class file' in text: return True
    if d.symbol_kind == 'class' and ('cannot find symbol' in text or 'package does not exist' in text): return True
    return False


def _diag_file_key(path: str) -> str:
    try: return str(Path(path).resolve())
    except Exception: return str(path)


def _caret_column(d: JavacDiagnostic) -> int | None:
    """Recover javac's visual caret column when file:line:column is absent."""
    if d.column:
        return max(0, d.column - 1)
    ctx = list(d.context)
    for i, line in enumerate(ctx):
        if '^' not in line:
            continue
        # javac normally prints the source line immediately before the caret. Gradle
        # may indent both by two spaces; using the caret line directly still points
        # to the right token in the source text once common leading indentation is
        # stripped by the line-level callers below.
        return line.index('^')
    return None


def _source_token_at_caret(d: JavacDiagnostic, source_line: str) -> tuple[int, int, str] | None:
    """Best-effort source token under javac's caret.

    This matters for register-reuse artifacts such as `new C1051f(0)` where the
    diagnostic is `int cannot be converted to C1055j`: replacing the *whole RHS*
    would be wrong; javac is pointing specifically at the numeric argument.
    """
    col = _caret_column(d)
    if col is None:
        return None
    # Account for javac/Gradle prefixes that may exist in the context source line by
    # clamping and then expanding around a nearby lexical token.
    col = min(max(0, col), max(0, len(source_line) - 1))
    # If caret landed on whitespace, search a small neighborhood.
    candidates = [col]
    candidates += [x for delta in range(1, 9) for x in (col-delta, col+delta) if 0 <= x < len(source_line)]
    pos = next((x for x in candidates if re.match(r"[A-Za-z0-9_$.'\"+-]", source_line[x])), None)
    if pos is None:
        return None
    # String/char literal.
    if source_line[pos] in "\"'":
        q = source_line[pos]; end = pos + 1; esc = False
        while end < len(source_line):
            ch = source_line[end]
            if esc: esc = False
            elif ch == '\\': esc = True
            elif ch == q:
                return pos, end + 1, source_line[pos:end+1]
            end += 1
    m = re.search(r"(?:null|true|false|[+-]?\d+(?:\.\d+)?[fFdDlL]?|[A-Za-z_$][\w$]*)", source_line[pos:])
    if m:
        return pos + m.start(), pos + m.end(), m.group(0)
    return None

def _batch_signature(edits: Iterable[Edit]) -> str:
    raw = "\n".join(sorted(e.signature() for e in edits))
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


class JavaAstHelper:
    TRACE_LEVELS = {"off": 0, "summary": 1, "detail": 2, "verbose": 3}

    def __init__(self, analysis_dir: Path, *, logger=None, trace_level: str | int = "detail"):
        self.analysis_dir = Path(analysis_dir)
        self.package_root = Path(__file__).resolve().parent
        self.source = self.package_root / "java_repair" / "SourceAnalyzer.java"
        self.classes = self.analysis_dir / "source-repair" / "helper-classes"
        self.main_class = "apk2project.repair.SourceAnalyzer"
        self.logger = logger or (lambda s: None)
        if isinstance(trace_level, str):
            self.trace_level = self.TRACE_LEVELS.get(trace_level.lower().strip(), 2)
        else:
            self.trace_level = max(0, min(3, int(trace_level)))
        self._ready = False
        self.cache: dict[tuple[str, int, int], list[dict]] = {}

    def _log(self, line: str):
        if not line:
            return
        try:
            self.logger(line)
        except Exception:
            pass

    def ensure(self) -> bool:
        if self._ready:
            return True
        javac = shutil.which("javac")
        java = shutil.which("java")
        if not javac or not java or not self.source.is_file():
            return False
        marker = self.classes / "apk2project" / "repair" / "SourceAnalyzer.class"
        try:
            if (not marker.exists() or marker.stat().st_mtime < self.source.stat().st_mtime):
                shutil.rmtree(self.classes, ignore_errors=True)
                self.classes.mkdir(parents=True, exist_ok=True)
                self._log("\033[95m[JAVA-TREE][BUILD]\033[0m compiling SourceAnalyzer.java")
                p = subprocess.run([javac, "-encoding", "UTF-8", "-d", str(self.classes), str(self.source)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
                log = self.analysis_dir / "source-repair" / "helper-build.log"
                log.parent.mkdir(parents=True, exist_ok=True)
                log.write_text(p.stdout or "")
                if p.returncode:
                    self._log("\033[91m[JAVA-TREE][BUILD] helper compilation failed; see helper-build.log\033[0m")
                    return False
                self._log("\033[92m[JAVA-TREE][BUILD] helper ready\033[0m")
            self._ready = True
            return True
        except Exception:
            return False

    def analyze(self, path: Path) -> list[dict]:
        path = path.resolve()
        try:
            st = path.stat()
        except OSError:
            return []
        key = (str(path), st.st_size, st.st_mtime_ns)
        if key in self.cache:
            return self.cache[key]
        # Drop stale entries for same path.
        for old in [k for k in self.cache if k[0] == str(path) and k != key]:
            self.cache.pop(old, None)
        if not self.ensure():
            return []
        env = os.environ.copy()
        env["APK2PROJECT_TREE_TRACE"] = str(self.trace_level)
        started = time.monotonic()
        proc = subprocess.Popen(
            [shutil.which("java") or "java", "-cp", str(self.classes), self.main_class, str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", env=env, bufsize=1,
        )
        facts: list[dict] = []
        stderr_lines: list[str] = []

        def drain_stderr():
            if proc.stderr is None:
                return
            for raw in proc.stderr:
                stderr_lines.append(raw)
                # Java stdout is reserved for JSON facts. Human tree-walk messages
                # arrive on stderr and are forwarded immediately, ANSI colors intact.
                self._log(raw.rstrip("\r\n"))

        t = threading.Thread(target=drain_stderr, name="apk2project-java-tree-stderr", daemon=True)
        t.start()
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    facts.append(obj)
            except json.JSONDecodeError:
                # Keep stdout machine-readable by design; a malformed line is still
                # retained in the helper log for debugging rather than printed as a fact.
                stderr_lines.append("[non-json stdout] " + raw)
        proc.stdout.close()
        rc = proc.wait()
        t.join(timeout=5)
        elapsed = time.monotonic() - started
        if stderr_lines or rc:
            logdir = self.analysis_dir / "source-repair" / "helper-errors"
            logdir.mkdir(parents=True, exist_ok=True)
            (logdir / (path.name + ".log")).write_text("".join(stderr_lines))
        if rc:
            self._log(f"\033[91m[JAVA-TREE][EXIT] {path.name}: helper rc={rc} after {elapsed:.2f}s\033[0m")
        elif self.trace_level >= 1:
            kinds = collections.Counter(str(x.get("kind", "?")) for x in facts)
            self._log(
                f"\033[92m[JAVA-TREE][FACTS]\033[0m {path.name}: {len(facts)} facts in {elapsed:.2f}s "
                f"(types={kinds.get('type',0)}, methods={kinds.get('method',0)}, vars={kinds.get('variable',0)}, "
                f"calls={kinds.get('call',0)}, erroneous={kinds.get('erroneous',0)})"
            )
        self.cache[key] = facts
        return facts


class SourceModel:
    def __init__(self, path: Path, text: str, facts: list[dict]):
        self.path = path.resolve()
        self.text = text
        self.facts = facts
        self.unit = next((x for x in facts if x.get("kind") == "unit"), {})
        self.package = self.unit.get("package", "")
        self.imports = [x for x in facts if x.get("kind") == "import"]
        self.types = [x for x in facts if x.get("kind") == "type"]
        self.methods = [x for x in facts if x.get("kind") == "method"]
        self.variables = [x for x in facts if x.get("kind") == "variable"]
        self.assignments = [x for x in facts if x.get("kind") == "assignment"]
        self.calls = [x for x in facts if x.get("kind") == "call"]
        self.news = [x for x in facts if x.get("kind") == "new"]
        self.members = [x for x in facts if x.get("kind") == "member"]
        self.casts = [x for x in facts if x.get("kind") == "cast"]
        self.instanceofs = [x for x in facts if x.get("kind") == "instanceof"]
        self.returns = [x for x in facts if x.get("kind") == "return"]
        self.enhanced_fors = [x for x in facts if x.get("kind") == "enhancedFor"]
        self.erroneous = [x for x in facts if x.get("kind") == "erroneous"]
        self.blocks = [x for x in facts if x.get("kind") == "block"]
        self.annotations = [x for x in facts if x.get("kind") == "annotation"]
        self.import_map = {}
        for it in self.imports:
            name = it.get("name", "")
            if name and not name.endswith(".*"):
                self.import_map[name.rsplit('.', 1)[-1]] = name

    def primary_fqcn(self) -> str:
        return self.types[0].get("fqcn", "") if self.types else ""

    def line_span(self, line: int) -> tuple[int, int]:
        if line <= 1: start = 0
        else:
            pos = 0
            for _ in range(line - 1):
                n = self.text.find('\n', pos)
                if n < 0: return len(self.text), len(self.text)
                pos = n + 1
            start = pos
        end = self.text.find('\n', start)
        return start, len(self.text) if end < 0 else end

    def method_at_line(self, line: int) -> dict | None:
        ls, le = self.line_span(line)
        candidates = [m for m in self.methods
                      if int(m.get("start", -1)) <= le and int(m.get("end", -1)) >= ls]
        return min(candidates, key=lambda x: (int(x.get("end", 1<<60)) - int(x.get("start", 0)))) if candidates else None

    def type_at_line(self, line: int) -> dict | None:
        ls, le = self.line_span(line)
        candidates = [m for m in self.types
                      if int(m.get("start", -1)) <= le and int(m.get("end", -1)) >= ls]
        return min(candidates, key=lambda x: (int(x.get("end", 1<<60)) - int(x.get("start", 0)))) if candidates else None

    def variable(self, name: str, line: int | None = None) -> dict | None:
        cand = [v for v in self.variables if v.get("name") == name]
        if line is not None:
            before = [v for v in cand if int(v.get("line", 0) or 0) <= line]
            if before: cand = before
        if not cand: return None
        return max(cand, key=lambda x: int(x.get("line", 0) or 0))

    def method_by_id(self, mid: str) -> dict | None:
        return next((m for m in self.methods if m.get("id") == mid), None)


def _fact_contains_line(f: dict, line: int) -> bool:
    # Facts only carry starting line, but source offsets let us cheaply compute
    # an approximate end line later if needed.  For methods/types, start<=line and
    # pick the nearest lexical start is generally enough for decompiler diagnostics.
    return int(f.get("line", 0) or 0) <= line


def _clean_type(t: str) -> str:
    t = (t or "").strip()
    t = re.sub(r"\s+", " ", t)
    return t


def _base_type(t: str) -> str:
    t = _clean_type(t)
    t = re.sub(r"<.*>", "", t)
    t = t.replace("[]", "").strip()
    return t


def _default_value(t: str) -> str:
    b = _base_type(t)
    if b == "boolean": return "false"
    if b == "char": return "'\\0'"
    if b in {"byte", "short", "int"}: return "0"
    if b == "long": return "0L"
    if b == "float": return "0.0f"
    if b == "double": return "0.0d"
    return "null"


def _infer_expr(expr: str, model: SourceModel, index: ProjectIndex, seen=None) -> list[Evidence]:
    expr = (expr or "").strip()
    if not expr: return []
    seen = set(seen or ())
    if expr in seen: return []
    seen.add(expr)
    ev: list[Evidence] = []
    m = re.match(r"^new\s+([A-Za-z_$][\w.$]*(?:\s*<[^;{}()]+>)?(?:\[\])*)", expr)
    if m: ev.append(Evidence(_clean_type(m.group(1)), .99, "initializer constructs this type"))
    m = re.match(r"^\(\s*([A-Za-z_$][\w.$<>?, \[\]&]*)\s*\)\s*", expr)
    if m: ev.append(Evidence(_clean_type(m.group(1)), .97, "explicit cast supplies this type"))
    if re.match(r'^"(?:\\.|[^"\\])*"$', expr, re.S): ev.append(Evidence("String", .99, "string literal"))
    elif expr in {"true", "false"}: ev.append(Evidence("boolean", .99, "boolean literal"))
    elif re.match(r"^[+-]?\d+[lL]$", expr): ev.append(Evidence("long", .98, "long literal"))
    elif re.match(r"^[+-]?\d+$", expr): ev.append(Evidence("int", .98, "integer literal"))
    elif re.match(r"^[+-]?(?:\d+\.\d*|\d*\.\d+)[fF]$", expr): ev.append(Evidence("float", .98, "float literal"))
    elif re.match(r"^[+-]?(?:\d+\.\d*|\d*\.\d+)(?:[dD])?$", expr): ev.append(Evidence("double", .98, "double literal"))
    elif re.match(r"^'(?:\\.|[^'\\])'$", expr, re.S): ev.append(Evidence("char", .98, "char literal"))
    elif expr == "null": pass
    else:
        callm = re.match(r"^(?:[A-Za-z_$][\w$]*\.)?(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)$", expr)
        if callm:
            returns = {ret for _owner, ret in index.method_returns.get(callm.group("name"), [])
                       if ret and _base_type(ret) not in {"void", "Object", "java.lang.Object"}}
            if len(returns) == 1:
                ev.append(Evidence(next(iter(returns)), .84,
                                   f"unique source-tree return type for {callm.group('name')}(...)"))
    if re.match(r"^[A-Za-z_$][\w$]*$", expr):
        v = model.variable(expr)
        if v:
            dt = _clean_type(v.get("declaredType", ""))
            if dt and dt not in {"Object", "java.lang.Object", "?", "??"}:
                ev.append(Evidence(dt, .92, f"{expr} is declared as {dt}"))
            if v.get("init"):
                ev.extend(_infer_expr(v.get("init", ""), model, index, seen))
    return ev


def _resolve_owner_type(fq: str, model: SourceModel) -> str:
    fq = (fq or "").replace('$', '.')
    if not fq: return fq
    if fq.startswith(model.package + ".") and model.package:
        return fq[len(model.package)+1:]
    simple = fq.rsplit('.', 1)[-1]
    if model.import_map.get(simple) == fq:
        return simple
    if fq.startswith("java.lang."):
        return simple
    return fq


def _best_evidence(evidence: list[Evidence], current_type: str = "") -> Evidence | None:
    useful = [e for e in evidence if e.type_name and _base_type(e.type_name) not in {"Object", "java.lang.Object", "?", "??", "null"}]
    if not useful: return None
    grouped: dict[str, list[Evidence]] = collections.defaultdict(list)
    for e in useful: grouped[_clean_type(e.type_name)].append(e)
    ranked = []
    for typ, es in grouped.items():
        # Independent corroboration modestly boosts confidence.
        score = max(e.score for e in es) + min(.06, .02 * (len(es)-1))
        ranked.append((score, typ, es))
    ranked.sort(reverse=True)
    best = ranked[0]
    if len(ranked) > 1 and best[0] - ranked[1][0] < .08 and _base_type(best[1]) != _base_type(ranked[1][1]):
        return None
    reasons = "; ".join(dict.fromkeys(e.reason for e in best[2]))
    return Evidence(best[1], min(.995, best[0]), reasons)


def infer_variable_type(name: str, model: SourceModel, index: ProjectIndex, diagnostic: JavacDiagnostic | None = None) -> Evidence | None:
    v = model.variable(name, diagnostic.line if diagnostic else None)
    ev: list[Evidence] = []
    if v and v.get("init"):
        ev.extend(_infer_expr(v.get("init", ""), model, index))
    for a in model.assignments:
        if a.get("lhs", "").strip() == name:
            ev.extend(Evidence(e.type_name, min(e.score, .96), "assignment " + e.reason) for e in _infer_expr(a.get("rhs", ""), model, index))
    for c in model.casts:
        if c.get("expr", "").strip() == name:
            ev.append(Evidence(_clean_type(c.get("type", "")), .96, "variable is explicitly cast to this type"))
    for ins in model.instanceofs:
        if ins.get("expr", "").strip() == name:
            ev.append(Evidence(_clean_type(ins.get("type", "")), .90, "instanceof test constrains variable type"))
    for other in model.variables:
        if other.get("init", "").strip() == name:
            dt = _clean_type(other.get("declaredType", ""))
            if dt:
                ev.append(Evidence(dt, .91, f"assigned into {dt} variable {other.get('name')}"))
    for r in model.returns:
        if r.get("expr", "").strip() == name:
            m = model.method_by_id(r.get("method", ""))
            if m:
                rt = _clean_type(m.get("returnType", ""))
                if rt and rt not in {"void", "<constructor>"}:
                    ev.append(Evidence(rt, .90, f"returned from method declared {rt}"))
    for call in model.calls:
        call_name = call.get("name", "")
        if call.get("receiver", "").strip() == name:
            # JDK interfaces are not part of the reconstructed source index, so
            # seed a few extremely characteristic receiver protocols explicitly.
            if call_name in {"hasNext", "next", "forEachRemaining"}:
                ev.append(Evidence("java.util.Iterator", .96, f"{name}.{call_name}(...) is Iterator protocol"))
            elif call_name in {"get", "clear", "enqueue"} and name.lower().startswith("weakreference"):
                ev.append(Evidence("java.lang.ref.WeakReference", .90, f"{name}.{call_name}(...) matches WeakReference"))
            owners = index.method_owners.get(call_name, set())
            if len(owners) == 1:
                owner = next(iter(owners))
                ev.append(Evidence(_resolve_owner_type(owner, model), .86,
                                   f"{name} is receiver of {call_name}(...) uniquely declared by {owner}"))
        args = call.get("args") or []
        for i, arg in enumerate(args):
            if str(arg).strip() != name:
                continue
            param_types = set()
            for _owner, params in index.method_params.get(call_name, []):
                if i < len(params):
                    pt = _clean_type(params[i])
                    if pt and _base_type(pt) not in {"Object", "java.lang.Object", "?"}:
                        param_types.add(pt)
            if len(param_types) == 1:
                pt = next(iter(param_types))
                ev.append(Evidence(pt, .84, f"argument {i+1} of {call_name}(...) has unique source-tree parameter type {pt}"))
    for mem in model.members:
        if mem.get("receiver", "").strip() == name:
            owners = index.field_owners.get(mem.get("name", ""), set())
            if len(owners) == 1:
                owner = next(iter(owners))
                ev.append(Evidence(_resolve_owner_type(owner, model), .81,
                                   f"{name}.{mem.get('name')} uniquely maps to field owner {owner}"))
    if diagnostic:
        full = "\n".join(diagnostic.context)
        mt = re.search(r"incompatible types:\s*.+?\s+cannot be converted to\s+([^\n]+)", full, re.I)
        if mt:
            ev.append(Evidence(_clean_type(mt.group(1)), .95, "javac required this target type"))
        # javac format: symbol: method foo(...), location: variable x of type java.lang.Object
        if diagnostic.symbol_kind == "method" and diagnostic.symbol_name:
            method_name = diagnostic.symbol_name.split('(', 1)[0].strip()
            loc = diagnostic.location or ""
            if re.search(rf"\bvariable\s+{re.escape(name)}\s+of type\s+(?:java\.lang\.)?Object\b", loc):
                owners = index.method_owners.get(method_name, set())
                if len(owners) == 1:
                    owner = next(iter(owners))
                    ev.append(Evidence(_resolve_owner_type(owner, model), .86,
                                       f"{name}.{method_name}(...) and only {owner} declares {method_name} in the source tree"))
        if diagnostic.symbol_kind == "variable" and diagnostic.symbol_name:
            member = diagnostic.symbol_name.strip()
            loc = diagnostic.location or ""
            if re.search(rf"\bvariable\s+{re.escape(name)}\s+of type\s+(?:java\.lang\.)?Object\b", loc):
                owners = index.field_owners.get(member, set())
                if len(owners) == 1:
                    owner = next(iter(owners))
                    ev.append(Evidence(_resolve_owner_type(owner, model), .82,
                                       f"member {member} uniquely belongs to {owner} in the source tree"))
    current = v.get("declaredType", "") if v else ""
    return _best_evidence(ev, current)


def _diag_dict(d: JavacDiagnostic) -> dict:
    x = asdict(d); x["context"] = list(d.context); return x


def _path_for_diag(d: JavacDiagnostic, java_root: Path) -> Path | None:
    p = Path(d.file)
    if not p.is_absolute():
        # Gradle often prints project-relative paths; try root and basename search.
        candidates = [(java_root / p), (java_root.parent.parent.parent / p)]
        for q in candidates:
            if q.is_file(): p = q; break
        else:
            hits = list(java_root.rglob(p.name))
            if len(hits) == 1: p = hits[0]
    try:
        p = p.resolve()
        p.relative_to(java_root.resolve())
    except Exception:
        return None
    return p if p.is_file() else None


def _edit_import_for_missing_class(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex) -> Edit | None:
    if d.symbol_kind != "class" or not d.symbol_name:
        return None
    simple = d.symbol_name.strip().split()[-1]
    if not re.match(r"^[A-Za-z_$][\w$]*$", simple): return None
    cands = index.by_simple_type.get(simple, set())
    if len(cands) != 1: return None
    fq = next(iter(cands))
    if fq.startswith(model.package + ".") or fq.startswith("java.lang.") or simple in model.import_map:
        return None
    # Insert after last import, otherwise after package declaration.
    if model.imports:
        pos = max(int(x.get("end", 0)) for x in model.imports)
        repl = "\nimport " + fq.replace('$', '.') + ";"
    else:
        pm = PACKAGE_RE.search(model.text)
        pos = pm.end() if pm else 0
        repl = ("\n\n" if pos else "") + "import " + fq.replace('$', '.') + ";"
    return Edit(str(model.path), pos, pos, repl, "add-missing-import", .94,
                f"javac cannot find {simple}; exactly one source-tree type matches: {fq}", _diag_dict(d))


def _object_specialization_edits(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex) -> list[Edit]:
    out = []
    # Prefer javac's location field because it tells us the actual receiver variable.
    names = []
    loc = d.location or ""
    lm = re.search(r"\bvariable\s+([A-Za-z_$][\w$]*)\s+of type\s+(?:java\.lang\.)?Object\b", loc)
    if lm: names.append(lm.group(1))
    # For incompatible conversion, inspect identifiers on the diagnostic line.
    if "incompatible types" in d.message.lower() or any("incompatible types" in x.lower() for x in d.context):
        a, b = model.line_span(d.line)
        names.extend(re.findall(r"\b([A-Za-z_$][\w$]*)\b", model.text[a:b]))
    for name in dict.fromkeys(names):
        v = model.variable(name, d.line)
        if not v: continue
        old = _clean_type(v.get("declaredType", ""))
        if _base_type(old) not in {"Object", "java.lang.Object", "?", "??"}: continue
        ts, te = int(v.get("typeStart", -1)), int(v.get("typeEnd", -1))
        if ts < 0 or te <= ts: continue
        inferred = infer_variable_type(name, model, index, d)
        if inferred:
            out.append(Edit(str(model.path), ts, te, inferred.type_name, "specialize-object-type", inferred.score,
                            f"{name}: {old} -> {inferred.type_name}; {inferred.reason}", _diag_dict(d)))
    return out


def _placeholder_type_edits(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex) -> list[Edit]:
    out = []
    # Invalid JADX `?? rN = expression;` is not always represented as VariableTree,
    # so use a bounded source regex and infer from the initializer/use graph.
    for m in re.finditer(r"(?m)(?P<indent>^[ \t]*)\?\?\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?P<tail>=\s*(?P<expr>[^;\n]+))?\s*;", model.text):
        line = model.text.count('\n', 0, m.start()) + 1
        if abs(line - d.line) > 40 and d.symbol_name not in {m.group('name'), None}: continue
        ev = _infer_expr(m.group("expr") or "", model, index)
        ev.extend([e for e in [infer_variable_type(m.group("name"), model, index, d)] if e])
        best = _best_evidence(ev)
        if not best: continue
        qstart = model.text.find("??", m.start(), m.end())
        out.append(Edit(str(model.path), qstart, qstart+2, best.type_name, "replace-jadx-unknown-type", best.score,
                        f"replaced JADX ?? type for {m.group('name')}; {best.reason}", _diag_dict(d)))
    return out


def _undeclared_temp_edit(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex) -> Edit | None:
    """Reconstruct a local that JADX uses without declaring.

    Synthetic rN/vN/tmpN variables are declared at their first assignment.  Ordinary
    names (especially e/ex/cNNNNx) are declared at method scope because JADX often
    hoists values out of catch/if blocks while losing the original declaration.
    """
    if d.symbol_kind != "variable" or not d.symbol_name:
        return None
    name = d.symbol_name.strip()
    if not re.match(r"^[A-Za-z_$][\w$]*$", name):
        return None
    method = model.method_at_line(d.line)
    if not method:
        return None
    bs, be = int(method.get("bodyStart", -1)), int(method.get("bodyEnd", -1))
    if bs < 0 or be <= bs:
        return None
    # If javac says the name is missing but the parser has a declaration in this
    # exact method, this is probably a scope problem; method-scope insertion can
    # still repair it as long as that declaration uses a different nested scope.
    assignments = [a for a in model.assignments
                   if a.get("lhs", "").strip() == name
                   and a.get("method") == method.get("id")]
    ev: list[Evidence] = []
    for a in assignments:
        ev.extend(Evidence(e.type_name, min(e.score, .96), "assignment " + e.reason)
                  for e in _infer_expr(a.get("rhs", ""), model, index))
    # A common pattern is e = e2/e4/e7 where the RHS is a catch parameter.
    body = model.text[bs:be]
    for am in re.finditer(rf"(?m)^\s*{re.escape(name)}\s*=\s*(?P<rhs>[A-Za-z_$][\w$]*)\s*;", body):
        rhs = am.group("rhs")
        rv = model.variable(rhs, d.line)
        if rv:
            typ = _clean_type(rv.get("declaredType", ""))
            if typ:
                ev.append(Evidence(typ, .97, f"{name} receives catch/local variable {rhs} declared as {typ}"))
    best = _best_evidence(ev)
    if not best and ev:
        # JADX very commonly merges sibling catch variables (e2/e4/e7) into one
        # lost outer `e`. Their concrete exception classes may differ, so infer a
        # safe common Java supertype instead of giving up on a tied score.
        bases = {_base_type(e.type_name).rsplit('.', 1)[-1] for e in ev if e.type_name}
        if bases and all(x.endswith("Exception") for x in bases):
            best = Evidence("Exception", .92, "multiple assigned catch values share Exception as a safe common supertype")
        elif bases and all(x.endswith(("Exception", "Error", "Throwable")) for x in bases):
            best = Evidence("Throwable", .90, "multiple assigned catch values share Throwable as a safe common supertype")
    if not best:
        lname = name.lower()
        if lname in {"e", "ex", "exception"} or re.fullmatch(r"e\d+", lname):
            best = Evidence("Exception", .86, "decompiler exception-temporary naming convention")
        elif lname in {"th", "throwable"} or re.fullmatch(r"th\d+", lname):
            best = Evidence("Throwable", .86, "decompiler throwable-temporary naming convention")
        elif re.fullmatch(r"i\d*", lname):
            best = Evidence("int", .82, "decompiler integer-temporary naming convention")
        elif re.fullmatch(r"z\d*", lname):
            best = Evidence("boolean", .82, "decompiler boolean-temporary naming convention")
        elif lname.startswith("str"):
            best = Evidence("String", .82, "decompiler string-temporary naming convention")
        elif lname.startswith("arraylist"):
            best = Evidence("java.util.ArrayList", .84, "decompiler collection-temporary naming convention")
        elif lname.startswith("treemap"):
            best = Evidence("java.util.Map", .82, "decompiler map-temporary naming convention")
    if not best:
        return None
    synthetic = bool(re.match(r"^(?:r\d+|obj\d*|tmp\d*|v\d+)$", name, re.I))
    if synthetic and assignments:
        a = min(assignments, key=lambda x: int(x.get("start", 1 << 60)))
        apos = int(a.get("start", -1))
        if apos >= 0:
            line_end = model.text.find('=', apos, int(a.get("end", apos + 300)))
            if line_end >= 0:
                token = re.search(rf"\b{re.escape(name)}\b", model.text[apos:line_end])
                if token:
                    pos = apos + token.start()
                    return Edit(str(model.path), pos, pos, best.type_name + " ",
                                "declare-decompiler-temp", min(.96, best.score),
                                f"declare synthetic temporary {name}; {best.reason}", _diag_dict(d))
    # Ordinary missing locals are method-scoped so sibling catch/if blocks share
    # the same variable. Constructors are special: an explicit this()/super() call
    # MUST remain the first statement, so insert immediately after it rather than
    # accidentally creating the very "call to this/super must be first" errors we
    # are trying to eliminate.
    pos = bs + 1
    if method.get("returnType") == "<constructor>":
        inner = model.text[bs + 1:be - 1]
        cm = re.match(r"(?s)\s*(?:this|super)\s*\([^;]*\)\s*;", inner)
        if cm:
            pos = bs + 1 + cm.end()
    indent = _indent_before(model.text, bs) + "    "
    init = _default_value(best.type_name)
    repl = f"\n{indent}{best.type_name} {name} = {init};"
    return Edit(str(model.path), pos, pos, repl, "declare-lost-local", min(.95, best.score),
                f"restore method-scope local {name}; {best.reason}", _diag_dict(d))



def _resolve_unique_type_file(type_name: str, index: ProjectIndex) -> tuple[str, Path] | None:
    simple = _base_type(type_name).rsplit('.', 1)[-1]
    cands = index.by_simple_type.get(simple, set())
    if len(cands) != 1:
        return None
    fq = next(iter(cands))
    path = index.type_files.get(fq)
    return (fq, Path(path)) if path and Path(path).is_file() else None


def _matching_brace(text: str, open_pos: int) -> int:
    """Return matching } while ignoring strings/chars/comments; -1 on failure."""
    depth = 0; i = open_pos; quote = None; esc = False; line_comment = False; block_comment = False
    while i < len(text):
        ch = text[i]; nxt = text[i+1] if i + 1 < len(text) else ''
        if line_comment:
            if ch == '\n': line_comment = False
            i += 1; continue
        if block_comment:
            if ch == '*' and nxt == '/': block_comment = False; i += 2; continue
            i += 1; continue
        if quote:
            if esc: esc = False
            elif ch == '\\': esc = True
            elif ch == quote: quote = None
            i += 1; continue
        if ch == '/' and nxt == '/': line_comment = True; i += 2; continue
        if ch == '/' and nxt == '*': block_comment = True; i += 2; continue
        if ch in "\"'": quote = ch; i += 1; continue
        if ch == '{': depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0: return i
        i += 1
    return -1


def _type_body_insert_pos(text: str, simple: str) -> int:
    m = re.search(rf"\b(?:class|interface|enum|record)\s+{re.escape(simple)}\b", text)
    if not m: return -1
    op = text.find('{', m.end())
    if op < 0: return -1
    return _matching_brace(text, op)


def _usage_after_member(line: str, member: str) -> tuple[str, str | None]:
    mm = re.search(rf"\.{re.escape(member)}\b(?P<tail>.*)", line)
    if not mm: return ("unknown", None)
    tail = mm.group('tail')
    cm = re.match(r"\s*\.\s*([A-Za-z_$][\w$]*)\s*\(", tail)
    if cm: return ("call:" + cm.group(1), None)
    am = re.match(r"\s*=\s*(.+?);", tail)
    if am: return ("assign", am.group(1).strip())
    return ("read", None)


def _field_usage_compatible(field_type: str, usage: str, rhs_type: str | None = None) -> bool:
    b = _base_type(field_type).rsplit('.', 1)[-1]
    if usage == "call:add":
        return any(x in b for x in ("List", "Collection", "Set", "Queue", "Deque", "ArrayList", "Vector"))
    if usage == "call:put":
        return any(x in b for x in ("Map", "SparseArray", "ArrayMap", "TreeMap", "HashMap"))
    if usage in {"call:size", "call:clear", "call:remove", "call:contains"}:
        return any(x in b for x in ("List", "Collection", "Set", "Queue", "Deque", "Map", "Array", "Sparse"))
    if usage == "assign" and rhs_type:
        return _base_type(field_type) == _base_type(rhs_type)
    return False


def _rhs_type(expr: str | None, model: SourceModel, index: ProjectIndex) -> str | None:
    if not expr: return None
    expr = expr.strip()
    if re.match(r"^(?:Integer|Short|Byte)\.(?:MAX_VALUE|MIN_VALUE)$", expr): return "int"
    if re.match(r"^Long\.(?:MAX_VALUE|MIN_VALUE)$", expr): return "long"
    if re.match(r"^(?:Float|Double)\.(?:MAX_VALUE|MIN_VALUE|NaN|POSITIVE_INFINITY|NEGATIVE_INFINITY)$", expr):
        return "float" if expr.startswith("Float.") else "double"
    ev = _best_evidence(_infer_expr(expr, model, index))
    return ev.type_name if ev else None


def _missing_member_edit(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex,
                         mode: str, helper: JavaAstHelper | None) -> Edit | None:
    if d.symbol_kind != "variable" or not d.symbol_name:
        return None
    member = d.symbol_name.strip()
    if not re.match(r"^[A-Za-z_$][\w$]*$", member): return None
    a, b = model.line_span(d.line); line = model.text[a:b]
    if f".{member}" not in line: return None
    target_type = None
    loc = d.location or ""
    lm = re.search(r"\bvariable\s+[A-Za-z_$][\w$]*\s+of type\s+([A-Za-z_$][\w.$<>?]*)", loc)
    if lm: target_type = lm.group(1)
    if not target_type:
        cm = re.search(r"\bclass\s+([A-Za-z_$][\w.$]*)", loc)
        if cm: target_type = cm.group(1)
    if not target_type:
        # Cast receiver: ((PreferenceGroup) expr).field
        cm = re.search(rf"\(\s*([A-Za-z_$][\w.$]*)\s*\)[^;\n]*\.{re.escape(member)}\b", line)
        if cm: target_type = cm.group(1)
    if not target_type: return None
    resolved = _resolve_unique_type_file(target_type, index)
    usage, rhs = _usage_after_member(line, member)
    rhs_t = _rhs_type(rhs, model, index) if rhs else None
    if resolved:
        fq, tp = resolved
        try: ttext = tp.read_text(errors="ignore")
        except OSError: ttext = ""
        tfacts = helper.analyze(tp) if helper else []
        tmodel = SourceModel(tp, ttext, tfacts) if tfacts else None
        fields = []
        if tmodel:
            fields = [v for v in tmodel.variables if not v.get("method") and v.get("name") != member]
        compat = [v for v in fields if _field_usage_compatible(v.get("declaredType", ""), usage, rhs_t)]
        if len(compat) == 1:
            replacement = compat[0].get("name", "")
            hit = re.search(rf"(?<=\.){re.escape(member)}\b", line)
            if hit and replacement:
                return Edit(str(model.path), a + hit.start(), a + hit.end(), replacement,
                            "map-missing-member", .90,
                            f"{target_type}.{member} is absent; unique field {replacement} has usage-compatible type {compat[0].get('declaredType')}",
                            _diag_dict(d))
        # If no safe alias exists, synthesize a field in the reconstructed target type.
        if mode in {"balanced", "aggressive"} and ttext:
            simple = fq.rsplit('.', 1)[-1].split('$')[-1]
            pos = _type_body_insert_pos(ttext, simple)
            if pos >= 0 and not re.search(rf"\b{re.escape(member)}\b\s*(?:=|;)", ttext):
                decl = None
                if usage == "call:add":
                    decl = f"public final java.util.ArrayList<Object> {member} = new java.util.ArrayList<>();"
                elif usage == "call:put":
                    decl = f"public final java.util.HashMap<Object,Object> {member} = new java.util.HashMap<>();"
                elif usage in {"call:size", "call:clear", "call:remove", "call:contains"}:
                    decl = f"public final java.util.ArrayList<Object> {member} = new java.util.ArrayList<>();"
                elif usage == "assign" and rhs_t:
                    decl = f"public {rhs_t} {member};"
                if decl:
                    indent = _indent_before(ttext, pos) + "    "
                    return Edit(str(tp.resolve()), pos, pos, f"\n{indent}{decl}\n", "synthesize-missing-field", .79,
                                f"no compatible reconstructed member for {target_type}.{member}; synthesize {decl}",
                                _diag_dict(d), destructive=True)
    # Last resort for inaccessible/missing dependency internals: drop a standalone
    # bookkeeping statement.  This is deliberately aggressive and transactional.
    if mode == "aggressive" and re.match(r"^\s*[^;]+;\s*$", line) and (usage.startswith("call:") or usage == "assign"):
        end = b + (1 if b < len(model.text) and model.text[b:b+1] == '\n' else 0)
        return Edit(str(model.path), a, end, "", "remove-unrecoverable-missing-member-statement", .70,
                    f"target member {target_type}.{member} is unavailable and cannot be reconstructed", _diag_dict(d), destructive=True)
    return None


def _constructor_overload_edit(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex) -> Edit | None:
    full = d.message + "\n" + "\n".join(d.context)
    m = re.search(r"constructor\s+([A-Za-z_$][\w$]*)\s+in class\s+([A-Za-z_$][\w$]*)\s+cannot be applied", full, re.I)
    if not m: return None
    simple = m.group(1)
    fm = re.search(r"(?m)^\s*found:\s*(.+?)\s*$", full)
    if not fm: return None
    found = fm.group(1).strip()
    if found.lower() in {"no arguments", "<none>"}: return None
    params = [x.strip() for x in _split_top_level(found, ',') if x.strip()]
    if not params or any(x in {"...", "null"} for x in params): return None
    resolved = _resolve_unique_type_file(simple, index)
    if not resolved: return None
    fq, tp = resolved
    text = tp.read_text(errors="ignore")
    pos = _type_body_insert_pos(text, simple)
    if pos < 0: return None
    # Diagnostic says the currently applicable constructor takes no arguments;
    # delegate to it. This is much safer than deleting message/context arguments at
    # every call site and works for all repeated calls to the missing overload.
    signature = ", ".join(f"{t} arg{i}" for i, t in enumerate(params))
    if re.search(rf"\b{re.escape(simple)}\s*\(\s*{re.escape(params[0]) if len(params)==1 else ''}", text):
        # Loose duplicate guard; javac/rollback remains authoritative.
        pass
    indent = _indent_before(text, pos) + "    "
    repl = f"\n{indent}public {simple}({signature}) {{ this(); }}\n"
    return Edit(str(tp.resolve()), pos, pos, repl, "restore-missing-constructor-overload", .88,
                f"reconstructed callers require {simple}({found}) while javac reports only a no-arg constructor; add delegating overload",
                _diag_dict(d), destructive=True)


def _impossible_explicit_cast_edit(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    full = d.message + "\n" + "\n".join(d.context)
    m = re.search(r"incompatible types:\s*([^\n]+?)\s+cannot be converted to\s+([^\n]+)", full, re.I)
    if not m: return None
    src, target = _clean_type(m.group(1)), _clean_type(m.group(2))
    if not target or _base_type(target) in {"byte","short","int","long","float","double","boolean","char"}: return None
    a, b = model.line_span(d.line); line = model.text[a:b]
    # If the decompiled source already explicitly asks for the target cast, javac's
    # complaint means the static source type is provably unrelated. Cast through
    # Object to preserve the intended runtime check without globally widening fields.
    pat = re.compile(rf"\(\s*{re.escape(target)}\s*\)")
    hit = pat.search(line)
    if not hit:
        simple = _base_type(target).rsplit('.',1)[-1]
        hit = re.search(rf"\(\s*{re.escape(simple)}\s*\)", line)
    if not hit: return None
    original = hit.group(0)
    return Edit(str(model.path), a + hit.start(), a + hit.end(), original + " (Object)",
                "bridge-impossible-explicit-cast", .96,
                f"source explicitly intends cast to {target}, but javac proves static type {src} is unrelated; bridge through Object",
                _diag_dict(d))


def _enhanced_for_cast_edit(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    full = d.message + "\n" + "\n".join(d.context)
    m = re.search(r"incompatible types:\s*Object\s+cannot be converted to\s+([^\n]+)", full, re.I)
    if not m: return None
    target = _clean_type(m.group(1))
    cand = [x for x in model.enhanced_fors if abs(int(x.get("line", 0) or 0) - d.line) <= 2]
    if not cand: return None
    ef = min(cand, key=lambda x: abs(int(x.get("line", 0) or 0) - d.line))
    typ = _clean_type(ef.get("varType", "")) or target
    es = int(ef.get("exprStart", -1))
    if es < 0: return None
    return Edit(str(model.path), es, es, f"(java.lang.Iterable<{typ}>) (Object) ",
                "cast-enhanced-for-iterable", .91,
                f"enhanced-for expects {typ} but decompiler left raw/Object iterable; cast iteration source explicitly",
                _diag_dict(d))


def _enum_compat_edit(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex) -> Edit | None:
    if d.symbol_kind != "method" or not d.symbol_name: return None
    meth = d.symbol_name.split('(', 1)[0].strip()
    if meth not in {"ordinal", "compareTo"}: return None
    loc = d.location or ""
    lm = re.search(r"\bvariable\s+[A-Za-z_$][\w$]*\s+of type\s+([A-Za-z_$][\w.$]*)", loc)
    if not lm: return None
    typ = lm.group(1); simple = typ.rsplit('.',1)[-1]
    resolved = _resolve_unique_type_file(simple, index)
    if not resolved: return None
    fq, tp = resolved
    text = tp.read_text(errors="ignore")
    if re.search(rf"\benum\s+{re.escape(simple)}\b", text): return None
    # Strongest signal is JADX's conventional EnumCxxxx name or multiple static
    # singleton instances of the same reconstructed type.
    same_fields = re.findall(rf"(?m)^\s*(?:public|protected|private)?\s*static\s+final\s+{re.escape(simple)}\s+([A-Za-z_$][\w$]*)\b", text)
    if not (simple.startswith("Enum") or len(same_fields) >= 2): return None
    pos = _type_body_insert_pos(text, simple)
    if pos < 0: return None
    additions = []
    has_ordinal = bool(re.search(r"\bint\s+ordinal\s*\(\s*\)", text))
    has_compare = bool(re.search(rf"\bint\s+compareTo\s*\(\s*{re.escape(simple)}\b", text))
    indent = _indent_before(text, pos) + "    "
    if not has_ordinal:
        if same_fields:
            body = " ".join(f"if (this == {name}) return {i};" for i, name in enumerate(same_fields)) + " return -1;"
        elif re.search(rf"\b{re.escape(simple)}\s*\[\]\s+values\s*\(\s*\)", text):
            body = f"{simple}[] v = values(); for (int i=0;i<v.length;i++) if (v[i] == this) return i; return -1;"
        else:
            body = "return System.identityHashCode(this);"
        additions.append(f"public int ordinal() {{ {body} }}")
    if not has_compare:
        additions.append(f"public int compareTo({simple} other) {{ return Integer.compare(this.ordinal(), other.ordinal()); }}")
    if not additions: return None
    repl = "\n" + "\n".join(indent + x for x in additions) + "\n"
    return Edit(str(tp.resolve()), pos, pos, repl, "restore-enum-compat-methods", .84,
                f"{simple} is used as an enum but was reconstructed as a plain class; restore ordinal/compareTo compatibility",
                _diag_dict(d), destructive=True)

def _remove_override(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    if "does not override or implement" not in d.message.lower() and not any("does not override or implement" in x.lower() for x in d.context):
        return None
    method = model.method_at_line(d.line)
    if not method: return None
    ms = int(method.get("start", 0))
    body_start = int(method.get("bodyStart", method.get("end", 0)) or method.get("end", 0))
    candidates = [a for a in model.annotations
                  if a.get("name", "").endswith("Override")
                  and ms <= int(a.get("start", -1)) <= body_start]
    if not candidates: return None
    a = min(candidates, key=lambda x: int(x.get("start", -1)))
    end = int(a["end"])
    while end < len(model.text) and model.text[end] in " \t": end += 1
    if end < len(model.text) and model.text[end] == '\r': end += 1
    if end < len(model.text) and model.text[end] == '\n': end += 1
    return Edit(str(model.path), int(a["start"]), end, "", "remove-invalid-override", .97,
                "javac says method is not an override; remove only the @Override annotation", _diag_dict(d))


def _remove_interface_initializer(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    """Only remove a truly empty illegal interface static block.

    v27.2 deliberately stopped deleting non-empty blocks here.  A JVM/DEX interface
    may legitimately contain <clinit>; JADX sometimes reconstructs it as Java
    `static { ... }`, which javac forbids.  The Java hybrid normalizer now rewrites
    simple field-assignment <clinit> blocks into legal field initializers.  Complex
    blocks are preserved for binary-shadow ownership or a later structured repair.
    Silently deleting them would throw away executable initialization.
    """
    full = (d.message + "\n" + "\n".join(d.context)).lower()
    if "initializers not allowed in interfaces" not in full: return None
    interfaces = {t.get("fqcn") for t in model.types if t.get("typeKind") in {"INTERFACE", "ANNOTATION_TYPE"}}
    cand = [b for b in model.blocks if b.get("static") and not b.get("method") and b.get("owner") in interfaces]
    if not cand: return None
    b = min(cand, key=lambda x: abs(int(x.get("line", 0)) - d.line))
    chunk = model.text[int(b["start"]):int(b["end"])]
    inner = chunk[chunk.find("{")+1:chunk.rfind("}")] if "{" in chunk and "}" in chunk else chunk
    inner = re.sub(r"/\*.*?\*/|//[^\n]*", "", inner, flags=re.S).strip()
    if inner:
        return None
    return Edit(str(model.path), int(b["start"]), int(b["end"]), "", "remove-empty-interface-static-initializer", .995,
                "illegal interface static block is empty after comments/whitespace; safe to remove", _diag_dict(d))


def _dedupe_repeated_interface(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    full = d.message.lower() + "\n" + "\n".join(x.lower() for x in d.context)
    if "repeated interface" not in full: return None
    typ = model.type_at_line(d.line)
    if not typ: return None
    s = int(typ.get("start", -1)); e = int(typ.get("end", -1))
    if s < 0: return None
    brace = model.text.find('{', s, min(len(model.text), s + 4000, e if e > s else len(model.text)))
    if brace < 0: return None
    header = model.text[s:brace]
    mm = re.search(r"\bimplements\s+(.+)$", header, re.S)
    if not mm: return None
    raw = mm.group(1)
    parts = [x.strip() for x in _split_top_level(raw, ',')]
    seen, kept = set(), []
    for p in parts:
        norm = re.sub(r"\s+", "", p)
        if norm not in seen:
            seen.add(norm); kept.append(p)
    if len(kept) == len(parts): return None
    rs = s + mm.start(1); re_ = s + mm.end(1)
    replacement = ", ".join(kept) + (" " if raw[-1:].isspace() else "")
    return Edit(str(model.path), rs, re_, replacement, "dedupe-repeated-interface", .995,
                "javac reports a repeated interface; remove duplicate implements entry", _diag_dict(d))


def _remove_duplicate_decl(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    full = d.message + "\n" + "\n".join(d.context)
    cm = re.search(r"class\s+([A-Za-z_$][\w$]*)\s+is already defined", full, re.I)
    if cm:
        name = cm.group(1)
        cand = [t for t in model.types if t.get("name") == name]
        if len(cand) >= 2:
            victim = min(cand, key=lambda x: abs(int(x.get("line", 0)) - d.line))
            # Prefer later duplicate if diagnostic location is ambiguous.
            if victim == cand[0]: victim = cand[-1]
            return Edit(str(model.path), int(victim["start"]), int(victim["end"]), "",
                        "remove-duplicate-type", .97, f"remove duplicate declaration of {name}", _diag_dict(d), destructive=True)
    mm = re.search(r"method\s+([A-Za-z_$][\w$]*)\([^)]*\)\s+is already defined", full, re.I)
    if mm:
        name = mm.group(1)
        cand = [m for m in model.methods if m.get("name") == name]
        if len(cand) >= 2:
            victim = min(cand, key=lambda x: abs(int(x.get("line", 0)) - d.line))
            if victim == cand[0]: victim = cand[-1]
            return Edit(str(model.path), int(victim["start"]), int(victim["end"]), "",
                        "remove-duplicate-method", .94, f"remove duplicate method declaration {name}", _diag_dict(d), destructive=True)
    return None


def _missing_return_edit(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    full = (d.message + "\n" + "\n".join(d.context)).lower()
    if "missing return statement" not in full: return None
    method = model.method_at_line(d.line)
    if not method or int(method.get("bodyEnd", -1)) <= 0: return None
    rt = _clean_type(method.get("returnType", ""))
    if rt in {"void", "<constructor>", ""}: return None
    pos = int(method["bodyEnd"]) - 1
    indent = _indent_before(model.text, int(method.get("start", 0))) + "    "
    repl = f"\n{indent}throw new UnsupportedOperationException(\"decompiler repair: missing return\");\n"
    return Edit(str(model.path), pos, pos, repl, "satisfy-missing-return", .93,
                "append an explicit throw on the fall-through path; preserves existing returned paths", _diag_dict(d), destructive=False)


def _uninitialized_edit(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    full = d.message + "\n" + "\n".join(d.context)
    m = re.search(r"variable\s+([A-Za-z_$][\w$]*)\s+might not have been initialized", full, re.I)
    if not m: return None
    name = m.group(1)
    v = model.variable(name, d.line)
    if not v or v.get("init"): return None
    end = int(v.get("end", -1)); start = int(v.get("start", -1))
    if end <= start: return None
    decl = model.text[start:end]
    if '=' in decl: return None
    dt = _clean_type(v.get("declaredType", "Object"))
    insert = end - 1 if decl.rstrip().endswith(';') else end
    # If whitespace follows the semicolon inside the AST range, walk back to it.
    if decl.rstrip().endswith(';'):
        insert = start + decl.rfind(';')
    return Edit(str(model.path), insert, insert, " = " + _default_value(dt), "initialize-local", .90,
                f"initialize {name} with Java default for {dt} to satisfy definite assignment", _diag_dict(d))


def _remove_raw_goto(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    a, b = model.line_span(d.line)
    line = model.text[a:b]
    if re.match(r"^\s*goto\s+(?:L[_A-Za-z0-9$]+|0x[0-9a-f]+)\s*;?\s*$", line, re.I):
        end = b + (1 if b < len(model.text) and model.text[b:b+1] == '\n' else 0)
        return Edit(str(model.path), a, end, "", "remove-raw-goto", .98,
                    "raw goto is not Java syntax and is a decompiler artifact", _diag_dict(d), destructive=True)
    return None


def _erroneous_node_edit(d: JavacDiagnostic, model: SourceModel, mode: str) -> Edit | None:
    if mode == "safe": return None
    full = (d.message + "\n" + "\n".join(d.context)).lower()
    if not any(x in full for x in SYNTAX_MARKERS): return None
    cand = []
    for e in model.erroneous:
        s, en = int(e.get("start", -1)), int(e.get("end", -1))
        if s < 0 or en <= s: continue
        ln = int(e.get("line", 0) or 0)
        size = en - s
        if abs(ln - d.line) <= 3 and size <= (300 if mode == "balanced" else 2500):
            cand.append((size, e))
    if not cand: return None
    _, e = min(cand, key=lambda x: x[0])
    s, en = int(e["start"]), int(e["end"])
    # Avoid deleting braces themselves; prefer only non-structural erroneous text.
    fragment = model.text[s:en]
    if fragment.count('{') != fragment.count('}'):
        return None
    return Edit(str(model.path), s, en, "/* removed invalid decompiler fragment */", "remove-erroneous-node",
                .80 if mode == "balanced" else .74,
                "javac parser marks this small, brace-balanced fragment erroneous near the reported syntax error",
                _diag_dict(d), destructive=True)


def _stub_invalid_method(d: JavacDiagnostic, model: SourceModel, mode: str) -> Edit | None:
    if mode not in {"balanced", "aggressive"}: return None
    full = (d.message + "\n" + "\n".join(d.context)).lower()
    if not any(x in full for x in SYNTAX_MARKERS): return None
    method = model.method_at_line(d.line)
    if not method: return None
    bs, be = int(method.get("bodyStart", -1)), int(method.get("bodyEnd", -1))
    if bs < 0 or be <= bs + 1: return None
    # Balanced only stubs a method when javac itself found an erroneous AST node
    # inside that method or the method body contains a known hard decompiler token.
    body = model.text[bs:be]
    err_inside = any(bs <= int(e.get("start", -1)) < be for e in model.erroneous)
    hard_token = bool(re.search(r"(?m)^\s*(?:\?\?|goto\s+L|move-result|throw\s+null\s*;)\b", body))
    if mode == "balanced" and not (err_inside or hard_token): return None
    indent = _indent_before(model.text, bs) + "    "
    preserve = ""
    # Constructor invocation, when present, must remain the first statement.
    if method.get("returnType") == "<constructor>":
        inner = body[1:-1]
        sm = re.match(r"(?s)\s*((?:super|this)\s*\([^;]*\)\s*;)", inner)
        if sm: preserve = "\n" + indent + sm.group(1)
    repl = "{" + preserve + f"\n{indent}throw new UnsupportedOperationException(\"decompiler repair: invalid method body\");\n" + _indent_before(model.text, bs) + "}"
    return Edit(str(model.path), bs, be, repl, "stub-invalid-method-body",
                .74 if mode == "balanced" else .66,
                "last-resort compile repair: replace only this malformed method body, preserving its signature",
                _diag_dict(d), destructive=True)



def _target_type_from_diag(d: JavacDiagnostic, line: str = "") -> str | None:
    loc = d.location or ""
    m = re.search(r"\bvariable\s+[A-Za-z_$][\w$]*\s+of type\s+([A-Za-z_$][\w.$<>?]*)", loc)
    if m: return _base_type(m.group(1))
    m = re.search(r"\bclass\s+([A-Za-z_$][\w.$]*)", loc)
    if m: return _base_type(m.group(1))
    # Static call: Type.member(...)
    if d.symbol_name:
        member = d.symbol_name.split('(',1)[0].strip()
        m = re.search(rf"\b([A-Za-z_$][\w.$]*)\s*\.\s*{re.escape(member)}\b", line)
        if m: return m.group(1)
    return None


def _resolve_type_fq(type_name: str | None, model: SourceModel, index: ProjectIndex) -> str | None:
    if not type_name: return None
    b = _base_type(type_name).replace('$','.')
    simple = b.rsplit('.',1)[-1]
    if '.' in b and b in index.type_files: return b
    if simple in model.import_map:
        fq = model.import_map[simple].replace('$','.')
        if fq in index.type_files: return fq
    cands = index.by_simple_type.get(simple, set())
    if len(cands) == 1: return next(iter(cands))
    same = f"{model.package}.{simple}" if model.package else simple
    if same in index.type_files: return same
    return None


def _binary_nested_name_edit(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    """Fix Java source that incorrectly uses JVM binary '$' nested-class spelling."""
    a,b = model.line_span(d.line); line = model.text[a:b]
    if '$' not in line: return None
    # Common decompiler artifact: android.view.WindowInsetsAnimation$Callback.
    m = re.search(r"\b([A-Za-z_$][\w.]*\$[A-Za-z_$][\w$]*)\b", line)
    if not m: return None
    old = m.group(1); new = old.replace('$','.')
    return Edit(str(model.path), a+m.start(), a+m.end(), new, "normalize-binary-nested-class-name", .995,
                f"Java source uses JVM binary nested-class spelling {old}; source syntax is {new}", _diag_dict(d))


def _smali_oracle_member_edit(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex,
                              oracle: SmaliOracle | None) -> Edit | None:
    if oracle is None or d.symbol_kind not in {"variable","method"} or not d.symbol_name:
        return None
    a,b = model.line_span(d.line); line = model.text[a:b]
    alias = d.symbol_name.split('(',1)[0].strip()
    if not re.match(r"^[A-Za-z_$][\w$]*$", alias): return None
    target = _target_type_from_diag(d, line)
    fq = _resolve_type_fq(target, model, index)
    if not fq: return None
    tp_s = index.type_files.get(fq)
    if not tp_s or not Path(tp_s).is_file(): return None
    tp = Path(tp_s); ttext = tp.read_text(errors='ignore')
    simple = fq.rsplit('.',1)[-1].split('$')[-1]
    pos = _type_body_insert_pos(ttext, simple)
    if pos < 0: return None
    indent = _indent_before(ttext,pos) + '    '
    if d.symbol_kind == 'variable':
        sf = oracle.field(fq, alias)
        if not sf: return None
        typ = oracle.java_type(sf.type_raw, current_fq=fq)
        static = 'static ' if 'static' in sf.flags else ''
        # Never synthesize final: later decompiled source often assigns these fields.
        init = _default_value(typ)
        decl = f"public {static}{typ} {alias} = {init};"
        if re.search(rf"\b{re.escape(alias)}\b\s*(?:=|;)", ttext): return None
        return Edit(str(tp.resolve()), pos, pos, f"\n{indent}{decl}\n", "smali-oracle-field-stub", .995,
                    f"APK smali confirms raw field {sf.raw_name}:{sf.type_raw} on {oracle.get_class(fq).raw_fqcn}; restore JADX alias {alias}",
                    _diag_dict(d), destructive=True)
    methods = oracle.methods(fq, alias)
    if not methods: return None
    # Use javac's printed argument list to select an overload by arity when possible.
    arity = None
    sm = re.search(r"\((.*)\)", d.symbol_name)
    if sm:
        rawargs = sm.group(1).strip()
        arity = 0 if not rawargs else len(_split_top_level(rawargs, ','))
    if arity is not None:
        same = [m for m in methods if len(m.args_raw) == arity]
        if same: methods = same
    # If several overloads remain, emit all distinct descriptors in one insertion.
    decls=[]; seen=set()
    is_interface = bool(re.search(rf"\binterface\s+{re.escape(simple)}\b", ttext))
    for smeth in methods[:8]:
        args = [oracle.java_type(x,current_fq=fq) for x in smeth.args_raw]
        ret = oracle.java_type(smeth.return_raw,current_fq=fq)
        key=(tuple(args),ret,'static' in smeth.flags)
        if key in seen: continue
        seen.add(key)
        if 'static' in smeth.flags:
            mods = 'public static '
        elif is_interface:
            mods = 'public default '
        else:
            mods = 'public '
        params=', '.join(f"{t} p{i}" for i,t in enumerate(args))
        if ret == 'void': body='{ }'
        else: body='{ return ' + _default_value(ret) + '; }'
        decls.append(f"{mods}{ret} {alias}({params}) {body}")
    if not decls: return None
    repl='\n' + '\n'.join(indent+x for x in decls) + '\n'
    return Edit(str(tp.resolve()), pos, pos, repl, "smali-oracle-method-stub", .992,
                f"APK smali confirms method {jadx_member_to_raw(alias,'method')} on {oracle.get_class(fq).raw_fqcn}; synthesize compile-compatible JADX alias",
                _diag_dict(d), destructive=True)


def _smali_oracle_field_type_edit(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex,
                                  helper: JavaAstHelper | None, oracle: SmaliOracle | None) -> Edit | None:
    """Correct a reconstructed field declaration from its exact DEX descriptor.

    This targets errors such as `this.f487a = new C1051f(0)` where javac reports an
    impossible assignment because JADX attached the wrong source type to f487a. The
    bytecode descriptor is more authoritative than source inference, so change the
    provider declaration once rather than casting every assignment/use.
    """
    if oracle is None or 'incompatible types:' not in (d.message + '\n' + '\n'.join(d.context)).lower():
        return None
    a,b = model.line_span(d.line); line = model.text[a:b]
    # Assignment to this.field or receiver.field. Avoid locals and array elements.
    m = re.search(r'(?:(?P<this>\bthis\b)|(?P<recv>\b[A-Za-z_$][\w$]*\b))\s*\.\s*(?P<field>[A-Za-z_$][\w$]*)\s*=', line)
    if not m:
        return None
    alias = m.group('field')
    if m.group('this'):
        fq = model.primary_fqcn()
    else:
        recv = m.group('recv')
        v = model.variable(recv, d.line)
        if not v:
            return None
        fq = _resolve_type_fq(v.get('declaredType'), model, index)
    if not fq:
        return None
    sf = oracle.field(fq, alias)
    if not sf:
        return None
    exact = oracle.java_type(sf.type_raw, current_fq=fq)
    ps = index.type_files.get(fq)
    if not ps or not Path(ps).is_file():
        return None
    tp = Path(ps)
    try:
        text = tp.read_text(errors='ignore')
    except OSError:
        return None
    tm = SourceModel(tp, text, helper.analyze(tp) if helper else [])
    fields = [v for v in tm.variables if not v.get('method') and v.get('name') == alias]
    if len(fields) != 1:
        return None
    fld = fields[0]
    ts,te = int(fld.get('typeStart',-1)), int(fld.get('typeEnd',-1))
    if ts < 0 or te <= ts:
        return None
    current = _clean_type(fld.get('declaredType',''))
    if _base_type(current) == _base_type(exact):
        return None
    return Edit(str(tp.resolve()), ts, te, exact, 'smali-oracle-correct-field-type', .999,
                f"APK DEX descriptor says {fq}.{alias} is {sf.type_raw} -> {exact}; reconstructed source declared {current}",
                _diag_dict(d), destructive=True)


def _access_widen_edit(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex,
                       helper: JavaAstHelper | None) -> Edit | None:
    full = d.message + "\n" + "\n".join(d.context)
    m = re.search(r"(?P<member>[A-Za-z_$][\w$]*)(?:\([^)]*\))?\s+has\s+(?:protected|private)\s+access\s+in\s+(?P<owner>[A-Za-z_$][\w.$]*)", full, re.I)
    if not m:
        m = re.search(r"(?P<member>[A-Za-z_$][\w$]*)(?:\([^)]*\))?\s+is not public in\s+(?P<owner>[A-Za-z_$][\w.$]*);", full, re.I)
    if not m: return None
    member, owner = m.group('member'), m.group('owner')
    fq = _resolve_type_fq(owner, model, index)
    if not fq: return None
    ps=index.type_files.get(fq)
    if not ps or not Path(ps).is_file(): return None
    tp=Path(ps); text=tp.read_text(errors='ignore')
    facts=helper.analyze(tp) if helper else []
    tm=SourceModel(tp,text,facts)
    candidates=[]
    for x in tm.methods:
        if x.get('name')==member: candidates.append(x)
    for x in tm.variables:
        if not x.get('method') and x.get('name')==member: candidates.append(x)
    if not candidates: return None
    x=min(candidates,key=lambda z: abs(int(z.get('line',0) or 0)-d.line))
    st=int(x.get('start',-1)); en=int(x.get('bodyStart',x.get('end',-1)) or x.get('end',-1))
    if st<0: return None
    head=text[st:max(st+1,min(len(text), en if en>st else st+500))]
    mm=re.search(r"\b(protected|private)\b",head)
    if mm:
        return Edit(str(tp.resolve()),st+mm.start(),st+mm.end(),'public','widen-member-access',.97,
                    f"javac reports {fq}.{member} is inaccessible; source is present, widen only this declaration",_diag_dict(d),destructive=True)
    if re.search(r"\bpublic\b",head): return None
    return Edit(str(tp.resolve()),st,st,'public ','widen-package-private-member',.95,
                f"javac reports {fq}.{member} is package-private; widen only this declaration",_diag_dict(d),destructive=True)


def _find_balanced_call_end(text: str, open_paren: int) -> int:
    depth=0; quote=None; esc=False
    for i in range(open_paren,len(text)):
        ch=text[i]
        if quote:
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch==quote: quote=None
            continue
        if ch in "\"'": quote=ch; continue
        if ch=='(': depth+=1
        elif ch==')':
            depth-=1
            if depth==0: return i+1
    return -1


def _bridge_incompatible_argument_edit(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    full=d.message+'\n'+'\n'.join(d.context)
    m=re.search(r"incompatible types:\s*([^\n]+?)\s+cannot be converted to\s+([^\n]+)",full,re.I)
    if not m: return None
    src,target=_clean_type(m.group(1)),_clean_type(m.group(2))
    if _base_type(target) in {'byte','short','int','long','float','double','boolean','char'}: return None
    a,b=model.line_span(d.line); line=model.text[a:b]
    srcsimple=_base_type(src).rsplit('.',1)[-1]; targetsimple=_base_type(target).rsplit('.',1)[-1]
    # Constructor expression as an argument.
    nm=re.search(rf"\bnew\s+{re.escape(srcsimple)}\s*\(",line)
    if nm:
        op=line.find('(',nm.start()); end=_find_balanced_call_end(line,op)
        if end>0:
            expr=line[nm.start():end]
            return Edit(str(model.path),a+nm.start(),a+end,f"({targetsimple}) (Object) ({expr})",'bridge-incompatible-argument',.93,
                        f"decompiler lost interface/supertype relationship {src} -> {target}; preserve runtime cast through Object",_diag_dict(d))
    # `this` is a frequent decompiler mismatch when an implements clause vanished.
    primary_simple=model.primary_fqcn().rsplit('.',1)[-1] if model.primary_fqcn() else ''
    if primary_simple and primary_simple==srcsimple:
        hit=re.search(r"\bthis\b",line)
        if hit:
            return Edit(str(model.path),a+hit.start(),a+hit.end(),f"({targetsimple}) (Object) this",'bridge-incompatible-this',.92,
                        f"decompiler lost interface/supertype relationship {src} -> {target} for this",_diag_dict(d))
    # Unique variable of the reported source type on the line.
    vars=[]
    for v in model.variables:
        if _base_type(v.get('declaredType','')).rsplit('.',1)[-1]==srcsimple:
            name=v.get('name','')
            if re.search(rf"\b{re.escape(name)}\b",line): vars.append(name)
    vars=list(dict.fromkeys(vars))
    if len(vars)==1:
        hit=re.search(rf"\b{re.escape(vars[0])}\b",line)
        if hit:
            return Edit(str(model.path),a+hit.start(),a+hit.end(),f"({targetsimple}) (Object) {vars[0]}",'bridge-incompatible-variable',.90,
                        f"bridge decompiler type mismatch {src} -> {target} at this use only",_diag_dict(d))
    # Assignment expression: wrap entire RHS, useful for DecorToolbar -> interface.
    eq=line.find('=')
    semi=line.rfind(';')
    if eq>=0 and semi>eq:
        rhs=line[eq+1:semi].strip()
        if rhs:
            rs=line.find(rhs,eq+1)
            return Edit(str(model.path),a+rs,a+rs+len(rhs),f"({targetsimple}) (Object) ({rhs})",'bridge-incompatible-assignment',.82,
                        f"last-resort local bridge for decompiler type mismatch {src} -> {target}",_diag_dict(d),destructive=True)
    return None


def _collection_conversion_edit(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    full=d.message+'\n'+'\n'.join(d.context)
    m=re.search(r"incompatible types:\s*([^\n]+?)\s+cannot be converted to\s+([^\n]+)",full,re.I)
    if not m: return None
    src,target=_clean_type(m.group(1)),_clean_type(m.group(2))
    a,b=model.line_span(d.line); line=model.text[a:b]
    eq=line.find('='); semi=line.rfind(';')
    if eq<0 or semi<=eq: return None
    rhs=line[eq+1:semi].strip(); rs=line.find(rhs,eq+1)
    sb=_base_type(src).rsplit('.',1)[-1]; tb=_base_type(target).rsplit('.',1)[-1]
    if tb=='ArrayList' and sb in {'List','Collection','Iterable'}:
        repl='new java.util.ArrayList<>()' if rhs in {'Collections.EMPTY_LIST','java.util.Collections.EMPTY_LIST'} else f"new java.util.ArrayList<>({rhs})"
        return Edit(str(model.path),a+rs,a+rs+len(rhs),repl,'materialize-arraylist-from-list',.96,
                    f"javac requires ArrayList but expression is {src}; materialize a real ArrayList rather than unsafe cast",_diag_dict(d))
    if sb.startswith('SparseArray') and tb.startswith('SparseArray'):
        return Edit(str(model.path),a+rs,a+rs+len(rhs),f"({target}) (Object) ({rhs})",'bridge-generic-sparsearray',.90,
                    "generic capture mismatch from decompilation; bridge through erased Object at this assignment",_diag_dict(d))
    return None


def _numeric_sentinel_edit(d: JavacDiagnostic, model: SourceModel, mode: str) -> Edit | None:
    full=d.message+'\n'+'\n'.join(d.context)
    m=re.search(r"incompatible types:\s*int\s+cannot be converted to\s+([^\n]+)",full,re.I)
    if not m: return None
    target=_clean_type(m.group(1)); a,b=model.line_span(d.line); line=model.text[a:b]
    eq=line.find('='); semi=line.rfind(';')
    if eq<0 or semi<=eq: return None
    rhs=line[eq+1:semi].strip(); rs=line.find(rhs,eq+1)
    if _base_type(target)=='boolean':
        if rhs=='0': repl='false'
        elif rhs=='1': repl='true'
        else:
            tm=re.match(r"^(.+?)\?\s*1\s*:\s*0$",rhs)
            repl=f"({tm.group(1).strip()})" if tm else f"(({rhs}) != 0)"
        return Edit(str(model.path),a+rs,a+rs+len(rhs),repl,'repair-int-as-boolean',.96,
                    "DEX register reuse/decompiler boolean lowering left an int expression in a boolean slot",_diag_dict(d))
    if _base_type(target) not in {'byte','short','int','long','float','double','char'}:
        if rhs=='0' or (mode=='aggressive' and (re.fullmatch(r"[+-]?\d+",rhs) or re.match(r"^.+?\?\s*[01]\s*:\s*[01]$",rhs))):
            conf=.96 if rhs=='0' else .74
            return Edit(str(model.path),a+rs,a+rs+len(rhs),'null','repair-int-as-reference-sentinel',conf,
                        f"numeric register sentinel {rhs} appears in reference slot {target}; use null",_diag_dict(d),destructive=(rhs!='0'))
    return None


def _bad_binary_sentinel_edit(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    full=(d.message+'\n'+'\n'.join(d.context)).lower()
    if 'bad operand types for binary operator' not in full: return None
    a,b=model.line_span(d.line); line=model.text[a:b]
    for v in model.variables:
        name=v.get('name',''); typ=_base_type(v.get('declaredType',''))
        if not name or typ in {'byte','short','int','long','float','double','char','boolean'}: continue
        m=re.search(rf"\b{re.escape(name)}\b\s*(==|!=)\s*0\b",line)
        if not m:
            m=re.search(rf"\b0\s*(==|!=)\s*{re.escape(name)}\b",line)
        if m:
            z=line.find('0',m.start(),m.end())
            return Edit(str(model.path),a+z,a+z+1,'null','repair-reference-zero-comparison',.98,
                        f"{name} has reference type {typ}; decompiler emitted DEX zero/null sentinel in comparison",_diag_dict(d))
    return None


def _enum_valueof_edit(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    full=d.message+'\n'+'\n'.join(d.context)
    if not re.search(r"method\s+valueOf\s+in class\s+Enum",full,re.I): return None
    a,b=model.line_span(d.line); line=model.text[a:b]
    hit=re.search(r"\bEnum\.valueOf\s*\(",line)
    if not hit: return None
    target=None
    dm=re.search(r"\b(Enum[A-Za-z0-9_$]*|[A-Za-z_$][\w$]*)\s+[A-Za-z_$][\w$]*\s*=",line[:hit.start()])
    if dm: target=dm.group(1)
    if not target:
        cm=re.search(r"\(\s*([A-Za-z_$][\w$]*)\s*\)\s*Enum\.valueOf",line)
        if cm: target=cm.group(1)
    if not target: return None
    op=line.find('(',hit.start())
    return Edit(str(model.path),a+op+1,a+op+1,f"{target}.class, ",'repair-enum-valueof-arity',.97,
                f"java.lang.Enum.valueOf requires Class<T>, String; infer {target} from assignment/cast",_diag_dict(d))


def _constructor_chain_first_edit(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex) -> Edit | None:
    full=(d.message+'\n'+'\n'.join(d.context)).lower()
    if 'call to this must be first statement in constructor' not in full and 'call to super must be first statement in constructor' not in full:
        return None
    method=model.method_at_line(d.line)
    if not method or method.get('returnType')!='<constructor>': return None
    bs,be=int(method.get('bodyStart',-1)),int(method.get('bodyEnd',-1))
    if bs<0 or be<=bs: return None
    inner=model.text[bs+1:be-1]
    cm=re.search(r"(?ms)^\s*(this|super)\s*\((?P<args>.*?)\)\s*;",inner)
    if not cm: return None
    pre=inner[:cm.start()]
    # Accept only whitespace/comments/simple assignments/declarations before the chain call.
    stripped=re.sub(r"(?s)/\*.*?\*/|//[^\n]*",'',pre)
    assigns={}
    for stmt in [x.strip() for x in stripped.split(';') if x.strip()]:
        am=re.match(r"(?:(?:final\s+)?[A-Za-z_$][\w.$<>?, \[\]]*\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+)$",stmt,re.S)
        if not am: return None
        assigns[am.group(1)]=am.group(2).strip()
    args=cm.group('args')
    # Resolve last-assignment expressions recursively. This specifically repairs
    # JADX constructor preludes such as treeMap=0; treeMap=EMPTY_MAP; treeMap=new...; this(...treeMap...).
    def expand(expr):
        for _ in range(6):
            changed=False
            for name,rhs in assigns.items():
                pat=rf"\b{re.escape(name)}\b"
                if re.search(pat,expr):
                    expr=re.sub(pat,f"({rhs})",expr); changed=True
            if not changed: break
        return expr
    newargs=expand(args)
    indent=_indent_before(model.text,bs)+'    '
    replacement='\n'+indent+cm.group(1)+'('+newargs+');'
    start=bs+1; end=bs+1+cm.end()
    return Edit(str(model.path),start,end,replacement,'normalize-constructor-chain-first',.985,
                "inline decompiler pre-constructor temporaries so this()/super() becomes the first Java statement",_diag_dict(d),destructive=True)



def _static_super_stub_edit(d: JavacDiagnostic, model: SourceModel) -> Edit | None:
    full=(d.message+'\n'+'\n'.join(d.context)).lower()
    if 'non-static variable super cannot be referenced from a static context' not in full:
        return None
    method=model.method_at_line(d.line)
    if not method or 'STATIC' not in set(method.get('modifiers') or []): return None
    bs,be=int(method.get('bodyStart',-1)),int(method.get('bodyEnd',-1))
    if bs<0 or be<=bs: return None
    indent=_indent_before(model.text,bs)+'    '
    repl='{\n'+indent+'throw new UnsupportedOperationException("decompiler repair: invalid static super reference");\n'+_indent_before(model.text,bs)+'}'
    return Edit(str(model.path),bs,be,repl,'stub-static-super-artifact',.94,
                'static method contains impossible super reference; quarantine this decompiler-corrupted body',_diag_dict(d),destructive=True)


def _implicit_super_constructor_edit(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex,
                                     helper: JavaAstHelper | None) -> Edit | None:
    full=d.message+'\n'+'\n'.join(d.context)
    if not re.search(r"no suitable constructor found for\s+[A-Za-z_$][\w$]*\(no arguments\)",full,re.I):
        return None
    method=model.method_at_line(d.line)
    if not method or method.get('returnType')!='<constructor>': return None
    fq=model.primary_fqcn()
    sup=index.type_extends.get(fq)
    if not sup: return None
    resolved=_resolve_unique_type_file(sup,index)
    if not resolved: return None
    sfq,sp=resolved
    text=sp.read_text(errors='ignore'); facts=helper.analyze(sp) if helper else []
    smodel=SourceModel(sp,text,facts)
    ctors=[m for m in smodel.methods if m.get('returnType')=='<constructor>']
    if not ctors: return None
    ctor=min(ctors,key=lambda x: len(x.get('params') or []))
    params=list(ctor.get('params') or [])
    args=', '.join(_default_value(t) for t in params)
    bs=int(method.get('bodyStart',-1))
    if bs<0: return None
    indent=_indent_before(model.text,bs)+'    '
    return Edit(str(model.path),bs+1,bs+1,f"\n{indent}super({args});",'supply-explicit-super-constructor',.89,
                f"{fq} implicitly calls unavailable {sfq}(); use smallest reconstructed superclass constructor with defaults",_diag_dict(d),destructive=True)

def _quarantine_error_method(d: JavacDiagnostic, model: SourceModel, method: dict, class_error_count: int) -> Edit | None:
    """Aggressive frontier tool: stub one method participating in a toxic class island.

    Unlike the older >=8-errors-in-one-method rule, this is activated only when a
    single source file has a large distributed error cohort. It lets us quarantine
    twenty individually-small broken methods instead of waiting for one method to
    become spectacularly broken. Every body is still a normal transactional edit.
    """
    bs, be = int(method.get('bodyStart', -1)), int(method.get('bodyEnd', -1))
    if bs < 0 or be <= bs:
        return None
    owner = method.get('owner') or ''
    if owner and owner != model.primary_fqcn():
        return None
    base_indent = _indent_before(model.text, bs)
    indent = base_indent + '    '
    body = model.text[bs:be]
    preserve = ''
    if method.get('returnType') == '<constructor>':
        # Preserve an explicit constructor chain if one can be located. Decompiler
        # temporaries before it are discarded so the chain is first by construction.
        m = re.search(r'(?s)\b(this|super)\s*\(', body)
        if m:
            op = body.find('(', m.start())
            end = _find_balanced_call_end(body, op)
            if end > 0:
                semi = body.find(';', end)
                if semi >= 0:
                    preserve = '\n' + indent + body[m.start():semi+1].strip()
        repl = '{' + preserve + '\n' + base_indent + '}'
    else:
        repl = '{\n' + indent + 'throw new UnsupportedOperationException("decompiler repair: quarantined error-island method");\n' + base_indent + '}'
    conf = .79 if class_error_count >= 60 else .755
    return Edit(str(model.path), bs, be, repl, 'quarantine-error-island-method', conf,
                f"{class_error_count} javac errors are distributed across this source file; quarantine this failing method body to expose/stabilize the remaining API surface",
                _diag_dict(d), destructive=True)


def _toxic_method_stub(d: JavacDiagnostic, model: SourceModel, error_count: int) -> Edit | None:
    if error_count < 8: return None
    method=model.method_at_line(d.line)
    if not method or method.get('returnType')=='<constructor>': return None
    bs,be=int(method.get('bodyStart',-1)),int(method.get('bodyEnd',-1))
    if bs<0 or be<=bs: return None
    indent=_indent_before(model.text,bs)+'    '
    repl='{\n'+indent+'throw new UnsupportedOperationException("decompiler repair: toxic method quarantined");\n'+_indent_before(model.text,bs)+'}'
    conf=.80 if error_count>=20 else .74
    return Edit(str(model.path),bs,be,repl,'stub-toxic-method',conf,
                f"{error_count} compiler errors originate in this one method; quarantine its body to unblock the rest of the compilation frontier",
                _diag_dict(d),destructive=True)

def _indent_before(text: str, pos: int) -> str:
    ls = text.rfind('\n', 0, max(0, pos)) + 1
    m = re.match(r"[ \t]*", text[ls:pos])
    return m.group(0) if m else ""


def propose_edits(d: JavacDiagnostic, model: SourceModel, index: ProjectIndex, mode: str, helper: JavaAstHelper | None = None, oracle: SmaliOracle | None = None) -> list[Edit]:
    edits: list[Edit] = []
    # Structural spelling / exact bytecode-backed repairs go first. They are much
    # stronger evidence than source-only inference.
    x = _binary_nested_name_edit(d, model)
    if x: edits.append(x)
    x = _smali_oracle_member_edit(d, model, index, oracle)
    if x: edits.append(x)
    x = _smali_oracle_field_type_edit(d, model, index, helper, oracle)
    if x: edits.append(x)
    x = _access_widen_edit(d, model, index, helper)
    if x: edits.append(x)
    x = _constructor_chain_first_edit(d, model, index)
    if x: edits.append(x)
    x = _implicit_super_constructor_edit(d, model, index, helper)
    if x: edits.append(x)
    x = _static_super_stub_edit(d, model)
    if x: edits.append(x)
    x = _enum_valueof_edit(d, model)
    if x: edits.append(x)
    x = _bad_binary_sentinel_edit(d, model)
    if x: edits.append(x)
    x = _numeric_sentinel_edit(d, model, mode)
    if x: edits.append(x)
    x = _collection_conversion_edit(d, model)
    if x: edits.append(x)
    x = _bridge_incompatible_argument_edit(d, model)
    if x: edits.append(x)

    imp = _edit_import_for_missing_class(d, model, index)
    if imp: edits.append(imp)
    edits.extend(_object_specialization_edits(d, model, index))
    edits.extend(_placeholder_type_edits(d, model, index))
    for fn in (_undeclared_temp_edit,):
        x = fn(d, model, index)
        if x: edits.append(x)
    x = _missing_member_edit(d, model, index, mode, helper)
    if x: edits.append(x)
    x = _constructor_overload_edit(d, model, index)
    if x: edits.append(x)
    x = _impossible_explicit_cast_edit(d, model)
    if x: edits.append(x)
    x = _enhanced_for_cast_edit(d, model)
    if x: edits.append(x)
    x = _enum_compat_edit(d, model, index)
    if x: edits.append(x)
    for fn in (_remove_override, _remove_interface_initializer, _dedupe_repeated_interface,
               _remove_duplicate_decl, _missing_return_edit, _uninitialized_edit, _remove_raw_goto):
        x = fn(d, model)
        if x: edits.append(x)
    x = _erroneous_node_edit(d, model, mode)
    if x: edits.append(x)
    # Method stubbing is intentionally considered last and will lose overlap
    # arbitration to more surgical edits with higher confidence.
    x = _stub_invalid_method(d, model, mode)
    if x: edits.append(x)
    return edits


def _overlap(a: Edit, b: Edit) -> bool:
    if a.file != b.file: return False
    # Insertions at same position conflict; insertion at boundary does not conflict.
    if a.start == a.end and b.start == b.end:
        if a.start != b.start: return False
        # Multiple bytecode-oracle member declarations intentionally share the
        # class closing-brace insertion point and are coalesced before writing.
        if a.kind.startswith("smali-oracle-") and b.kind.startswith("smali-oracle-"):
            return False
        return True
    if a.start == a.end: return b.start < a.start < b.end
    if b.start == b.end: return a.start < b.start < a.end
    return not (a.end <= b.start or b.end <= a.start)


def _select_edits(edits: list[Edit], min_conf: float, mode: str, rejected: set[str],
                  rejected_strategies: set[str] | None = None) -> tuple[list[Edit], list[dict]]:
    allowed_destructive = mode in {"balanced", "aggressive"}
    rejected_strategies = rejected_strategies or set()
    ranked = sorted(edits, key=lambda e: (e.confidence, not e.destructive, -(e.end-e.start)), reverse=True)
    chosen: list[Edit] = []
    skipped = []
    seen_signatures = set()
    for e in ranked:
        sig = e.signature()
        if sig in seen_signatures:
            skipped.append({"edit": asdict(e), "reason": "duplicate candidate generated by multiple diagnostics"}); continue
        seen_signatures.add(sig)
        if sig in rejected:
            skipped.append({"edit": asdict(e), "reason": "previous attempt with this exact edit was rolled back"}); continue
        if e.strategy_key() in rejected_strategies:
            skipped.append({"edit": asdict(e), "reason": "repair strategy was blacklisted for this diagnostic after repeated failed variants"}); continue
        threshold = min_conf
        if e.destructive and mode == "balanced": threshold = max(threshold, .72)
        if e.destructive and not allowed_destructive:
            skipped.append({"edit": asdict(e), "reason": "destructive repair disabled in safe mode"}); continue
        if e.confidence < threshold:
            skipped.append({"edit": asdict(e), "reason": f"confidence below threshold {threshold:.2f}"}); continue
        if any(_overlap(e, c) for c in chosen):
            skipped.append({"edit": asdict(e), "reason": "overlaps a higher-confidence edit"}); continue
        chosen.append(e)
    return chosen, skipped


class SourceRepairSession:
    def __init__(self, java_root: Path, analysis_dir: Path, *, library_class_owners=None,
                 mode: str = "balanced", min_confidence: float = .72, max_rounds: int = 8,
                 max_files: int = 40, rollback: bool = True, logger=None, tree_trace: str | int = "detail"):
        self.java_root = Path(java_root).resolve()
        self.analysis_dir = Path(analysis_dir).resolve()
        self.ignored_source_files: set[str] = set()
        hybrid_ownership = self.analysis_dir / "hybrid-source-ownership.json"
        if hybrid_ownership.is_file():
            try:
                payload = json.loads(hybrid_ownership.read_text())
                for rel in payload.get("binary_sources", []):
                    self.ignored_source_files.add(str((self.java_root / rel).resolve()))
            except Exception:
                pass
        self.mode = mode
        self.min_confidence = float(min_confidence)
        self.max_rounds = int(max_rounds)
        self.max_files = int(max_files)
        self.rollback_enabled = bool(rollback)
        self.library_class_owners = library_class_owners or {}
        self.logger = logger or (lambda s: None)
        self.helper = JavaAstHelper(self.analysis_dir, logger=self.logger, trace_level=tree_trace)
        self.tree_trace_level = self.helper.trace_level
        self.index: ProjectIndex | None = None
        self.oracle = SmaliOracle(self.java_root)
        self.round_no = 0
        self.pending: dict | None = None
        self.rejected: set[str] = set()
        self.rejected_batches: set[str] = set()
        self.strategy_failures: collections.Counter[str] = collections.Counter()
        self.rejected_strategies: set[str] = set()
        # Failed multi-edit transactions are intentionally NOT persisted because
        # their source offsets are tied to one exact compiler/source snapshot.
        self.retry_batches: list[dict] = []
        self.best_cost: tuple[int, int, int] | None = None
        self.best_fingerprint: str | None = None
        self.frontier_epoch: int = 0
        self.frontier_expansions: list[dict] = []
        self.history: list[dict] = []
        self.root = self.analysis_dir / "source-repair"
        self.root.mkdir(parents=True, exist_ok=True)
        self.state_path = self.root / "state.json"
        self._load_persistent_state()

    def _load_persistent_state(self):
        """Load proven-bad repairs across script invocations.

        v22 kept this only in RAM, which meant a resumed project could immediately
        retry a repair that an earlier run had already rolled back. Retry batches are
        deliberately not restored because their offsets are snapshot-specific.
        """
        # Preserve the append-only audit history when starting a new process.
        hist = self.root / "history.json"
        if hist.is_file():
            try:
                loaded = json.loads(hist.read_text())
                if isinstance(loaded, list):
                    self.history = loaded
            except Exception:
                pass
        if not self.state_path.is_file():
            return
        try:
            state = json.loads(self.state_path.read_text())
        except Exception as exc:
            self._log(f"could not load semantic repair state: {exc}")
            return
        state_version = int(state.get("version", 1) or 1)
        self.rejected = set(state.get("rejected", []))
        self.rejected_batches = set(state.get("rejected_batches", []))
        self.strategy_failures = collections.Counter({
            str(k): int(v) for k, v in (state.get("strategy_failures") or {}).items()
        })
        self.rejected_strategies = set(state.get("rejected_strategies", []))
        # v24 changes the compiler frontier and adds exact smali evidence. Broad
        # strategy bans learned under v22/v23 are no longer trustworthy in this new
        # search space. Keep exact bad edits, but release broad bans/checkpoint score.
        if state_version < 2:
            self.strategy_failures.clear()
            self.rejected_strategies.clear()
            state["best_cost"] = None
            state["best_fingerprint"] = None
            self._log("migrated pre-v24 repair state: preserved exact edit blacklist, reset broad strategy bans/frontier score")
        bc = state.get("best_cost")
        if isinstance(bc, list) and len(bc) == 3:
            self.best_cost = tuple(int(x) for x in bc)
        self.best_fingerprint = state.get("best_fingerprint") or None
        self.frontier_epoch = int(state.get("frontier_epoch", 0) or 0)
        self.frontier_expansions = list(state.get("frontier_expansions") or [])
        if self.rejected or self.rejected_strategies:
            self._log(
                f"loaded semantic repair blacklist: {len(self.rejected)} exact edit(s), "
                f"{len(self.rejected_strategies)} strategy/diagnostic pair(s)"
            )

    def _save_persistent_state(self):
        state = {
            "version": 2,
            "rejected": sorted(self.rejected),
            "rejected_batches": sorted(self.rejected_batches),
            "strategy_failures": dict(self.strategy_failures),
            "rejected_strategies": sorted(self.rejected_strategies),
            "best_cost": list(self.best_cost) if self.best_cost is not None else None,
            "best_fingerprint": self.best_fingerprint,
            "frontier_epoch": self.frontier_epoch,
            "frontier_expansions": self.frontier_expansions[-50:],
        }
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        tmp.replace(self.state_path)

    def _log(self, s: str):
        try: self.logger(s)
        except Exception: pass

    def _errors(self, text: str) -> list[JavacDiagnostic]:
        return [d for d in parse_javac_diagnostics(text) if d.severity == "error"]

    def _write_diagnostic_graph(self, diags: list[JavacDiagnostic]):
        """Persist a compact error graph so cascades are visible as provider/method cohorts."""
        by_message=collections.Counter(); by_symbol=collections.Counter(); by_provider=collections.Counter(); by_file=collections.Counter()
        for d in diags:
            by_message[d.message] += 1
            by_file[str(Path(d.file).name)] += 1
            if d.symbol_name: by_symbol[f"{d.symbol_kind}:{d.symbol_name}"] += 1
            loc=d.location or ''
            m=re.search(r"\b(?:class|type)\s+([A-Za-z_$][\w.$]*)",loc)
            if not m:
                m=re.search(r"\bvariable\s+[A-Za-z_$][\w$]*\s+of type\s+([A-Za-z_$][\w.$<>?]*)",loc)
            if m: by_provider[_base_type(m.group(1))] += 1
        payload={
            'error_count': len(diags),
            'by_message': by_message.most_common(200),
            'by_symbol': by_symbol.most_common(500),
            'by_provider': by_provider.most_common(200),
            'by_file': by_file.most_common(200),
            'interpretation': 'large provider clusters indicate one poisoned/missing declaration can fan out into many call-site errors',
        }
        (self.root/'diagnostic-graph.json').write_text(json.dumps(payload,indent=2)+"\n")
        if self.tree_trace_level >= 1:
            top_providers = ", ".join(f"{k}={v}" for k,v in by_provider.most_common(6)) or "<none>"
            top_files = ", ".join(f"{k}={v}" for k,v in by_file.most_common(6)) or "<none>"
            self._log(f"\033[93m[JAVA-GRAPH][FRONTIER]\033[0m {len(diags)} javac errors; providers: {top_providers}")
            self._log(f"\033[93m[JAVA-GRAPH][FILES]\033[0m {top_files}")

    def _restore_smali_provider_source(self, diags: list[JavacDiagnostic], current_fp: str, current_cost: tuple[int,int,int]) -> RepairResult | None:
        """Undo over-aggressive library pruning when APK-private/R8 members are used.

        A Maven RecyclerView.class can satisfy the public class name while *not*
        containing APK-specific obfuscated private members such as m814I/f1103t0.
        If smali proves the missing member exists in the APK and we previously moved
        that provider source to removed-library-sources, the correct action is to
        resurrect the whole decompiled provider class, not invent hundreds of callsite
        casts or stubs.
        """
        project=_project_root_from_java_root(self.java_root)
        removed_roots=[project/'removed-library-sources', project/'removed-platform-sources']
        for d in diags:
            if d.symbol_kind not in {'method','variable'} or not d.symbol_name:
                continue
            caller=_path_for_diag(d,self.java_root)
            if not caller: continue
            try: ctext=caller.read_text(errors='ignore')
            except OSError: continue
            cm=SourceModel(caller,ctext,self.helper.analyze(caller))
            a,b=cm.line_span(d.line); line=ctext[a:b]
            target=_target_type_from_diag(d,line)
            if not target: continue
            simple=_base_type(target).rsplit('.',1)[-1]
            candidates=[]
            for rr in removed_roots:
                if not rr.is_dir(): continue
                candidates.extend(rr.rglob(simple+'.java'))
            # If the target is fully qualified, prefer exact package match.
            if '.' in _base_type(target):
                tfq=_base_type(target)
                exact=[]
                for src in candidates:
                    try:
                        txt=src.read_text(errors='ignore'); pm=PACKAGE_RE.search(txt)
                        fq=(pm.group(1)+'.'+simple) if pm else simple
                        if fq==tfq: exact.append(src)
                    except OSError: pass
                if exact: candidates=exact
            if len(candidates)!=1:
                continue
            src=candidates[0]
            try:
                txt=src.read_text(errors='ignore'); pm=PACKAGE_RE.search(txt)
            except OSError:
                continue
            fq=((pm.group(1)+'.') if pm else '')+simple
            alias=d.symbol_name.split('(',1)[0].strip()
            confirmed=False
            if d.symbol_kind=='method': confirmed=bool(self.oracle.methods(fq,alias))
            else: confirmed=self.oracle.field(fq,alias) is not None
            # The moved source itself is also strong evidence when JADX's inverse
            # alias mapping cannot recover an especially odd raw DEX name.
            if not confirmed:
                if d.symbol_kind=='method':
                    confirmed=bool(re.search(rf"\b{re.escape(alias)}\s*\(",txt))
                else:
                    confirmed=bool(re.search(rf"\b{re.escape(alias)}\b\s*(?:=|;)",txt))
            if not confirmed:
                continue
            try: rel=src.relative_to(next(rr for rr in removed_roots if src.is_relative_to(rr)))
            except Exception:
                rel=Path(*fq.split('.')).with_suffix('.java')
            dst=self.java_root/rel
            if dst.exists(): continue
            edit=Edit(str(dst.resolve()),0,0,'','restore-smali-provider-source',.999,
                      f"APK smali confirms {fq}.{alias}; restore whole provider source pruned in favor of a Maven binary that lacks APK-private/R8 members",
                      _diag_dict(d),destructive=True)
            if edit.signature() in self.rejected or edit.strategy_key() in self.rejected_strategies:
                continue
            dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,dst)
            changed=[str(dst.resolve())]
            self.pending={
                'round':self.round_no,'before_error_count':current_cost[0],
                'before_fingerprint':current_fp,'before_cost':list(current_cost),
                'before_keys':sorted(repr(x.key()) for x in diags),
                'before_files':sorted({_diag_file_key(x.file) for x in diags}),
                'before_blocker_count':sum(1 for x in diags if _is_frontier_blocker(x)),
                'backups':{str(dst.resolve()):None},'edit_signatures':[edit.signature()],
                'strategy_keys':[edit.strategy_key()],'batch_signature':_batch_signature([edit]),
                'changed_files':changed,'edits':[asdict(edit)],'created_files':changed,
            }
            result=RepairResult(changed,[edit],[],len(diags),current_fp,self.round_no)
            self._write_round(result)
            self._log(f"smali provider rescue: restored {fq} from {src}; one provider may satisfy many unresolved symbols")
            return result
        return None

    def _bulk_smali_provider_members(self, diags: list[JavacDiagnostic], current_fp: str, current_cost: tuple[int,int,int]) -> RepairResult | None:
        """Repair missing provider members directly from the APK's DEX signatures.

        This deliberately runs before the ordinary caller-file ownership filter. A
        decompiled AndroidX caller may itself look Maven-owned, yet it can reference
        APK-private/R8 members that no stock Maven class contains. Smali is stronger
        evidence than either side of that ambiguity, so repair the provider surface
        once instead of casting/stubbing hundreds of callers.
        """
        model_cache: dict[str, SourceModel] = {}
        candidates: list[Edit] = []
        seen = set()
        for d in diags:
            if d.symbol_kind not in {"method", "variable"} or not d.symbol_name:
                continue
            caller = _path_for_diag(d, self.java_root)
            if not caller:
                continue
            key = str(caller.resolve())
            model = model_cache.get(key)
            if model is None:
                try:
                    text = caller.read_text(errors="ignore")
                except OSError:
                    continue
                model = SourceModel(caller, text, self.helper.analyze(caller))
                model_cache[key] = model
            edit = _smali_oracle_member_edit(d, model, self.index, self.oracle)
            if not edit:
                continue
            sig = edit.signature()
            if sig in seen or sig in self.rejected or edit.strategy_key() in self.rejected_strategies:
                continue
            seen.add(sig)
            candidates.append(edit)

        if not candidates:
            return None

        # Exact bytecode-backed edits are intentionally allowed to form one provider
        # transaction.  This is the opposite of speculative inference: every member
        # has a concrete DEX descriptor and rollback still protects the whole batch.
        candidates = sorted(candidates, key=lambda e: (e.file, e.start, e.kind, e.signature()))[:400]
        by_file: dict[str, list[Edit]] = collections.defaultdict(list)
        for e in candidates:
            by_file[e.file].append(e)

        backup_dir = self.root / "backups" / f"round-{self.round_no:02d}-smali-provider"
        backups: dict[str, str] = {}
        changed: list[str] = []
        applied: list[Edit] = []
        for file, edits in by_file.items():
            target = Path(file)
            try:
                original = target.read_text(errors="ignore")
            except OSError:
                continue
            try:
                rel = target.resolve().relative_to(self.java_root)
            except Exception:
                rel = Path(target.name)
            bp = backup_dir / rel
            bp.parent.mkdir(parents=True, exist_ok=True)
            bp.write_text(original)
            backups[str(target.resolve())] = str(bp)

            # All current oracle repairs are insertions at the owning type's closing
            # brace. Coalesce equal offsets so declarations retain deterministic order.
            insertion_groups: dict[int, list[Edit]] = collections.defaultdict(list)
            replacements: list[Edit] = []
            for e in edits:
                if e.start == e.end:
                    insertion_groups[e.start].append(e)
                else:
                    replacements.append(e)
            for pos, group in insertion_groups.items():
                uniq = []
                bodies = set()
                for e in group:
                    if e.replacement in bodies:
                        continue
                    bodies.add(e.replacement); uniq.append(e)
                if not uniq:
                    continue
                base = max(uniq, key=lambda x: x.confidence)
                replacements.append(Edit(
                    base.file, pos, pos, ''.join(e.replacement for e in uniq),
                    'bulk-smali-oracle-provider-surface', min(e.confidence for e in uniq),
                    f"coalesced {len(uniq)} exact DEX-backed missing member(s) into provider",
                    base.diagnostic, destructive=True,
                ))
                applied.extend(uniq)

            new = original
            for e in sorted(replacements, key=lambda x: (x.start, x.end), reverse=True):
                if 0 <= e.start <= e.end <= len(new):
                    new = new[:e.start] + e.replacement + new[e.end:]
            if new != original:
                target.write_text(new)
                changed.append(str(target.resolve()))

        if not changed:
            return None
        applied = [e for e in applied if e.file in changed]
        if not applied:
            # Defensive: retain the original candidate audit when all declarations
            # were grouped into the changed provider files.
            applied = [e for e in candidates if e.file in changed]
        provider_counts = collections.Counter(Path(e.file).name for e in applied)
        self.pending = {
            'round': self.round_no,
            'before_error_count': current_cost[0],
            'before_fingerprint': current_fp,
            'before_cost': list(current_cost),
            'before_keys': sorted(repr(d.key()) for d in diags),
            'before_files': sorted({_diag_file_key(d.file) for d in diags}),
            'before_blocker_count': sum(1 for d in diags if _is_frontier_blocker(d)),
            'backups': backups,
            'edit_signatures': [e.signature() for e in applied],
            'strategy_keys': [e.strategy_key() for e in applied],
            'batch_signature': _batch_signature(applied),
            'changed_files': changed,
            'edits': [asdict(e) for e in applied],
            'smali_provider_bulk': True,
        }
        result = RepairResult(changed, applied, [], len(diags), current_fp, self.round_no)
        self._write_round(result)
        summary = ', '.join(f"{k}={v}" for k,v in provider_counts.most_common(10))
        self._log(
            f"\033[95m[SMALI-ORACLE][PROVIDER] \033[0mrestored {len(applied)} exact member declaration(s) "
            f"across {len(changed)} provider source file(s): {summary}; validating as one compiler transaction"
        )
        return result

    def _restore_or_generate_missing_import(self, diags: list[JavacDiagnostic], current_fp: str, current_cost: tuple[int,int,int]) -> RepairResult | None:
        """Rescue source files moved by pruning, or create a minimal DEX-backed shell.

        This runs before line-level repairs because one missing imported class can hide
        dozens of downstream diagnostics. Newly created/restored files are fully
        transactional and are deleted again if the next full javac frontier is worse.
        """
        project=_project_root_from_java_root(self.java_root)
        removed=[project/'removed-library-sources', project/'removed-platform-sources']
        candidates=[]
        for d in diags:
            p=_path_for_diag(d,self.java_root)
            if not p: continue
            try: text=p.read_text(errors='ignore')
            except OSError: continue
            a,b=SourceModel(p,text,[]).line_span(d.line)
            line=text[a:b]
            m=re.search(r"^\s*import\s+([A-Za-z_$][\w.$]*)\s*;",line)
            if not m: continue
            fq=m.group(1).replace('$','.')
            # Java nested-class binary spelling is handled surgically elsewhere.
            if '$' in m.group(1): continue
            rel=Path(*fq.split('.')).with_suffix('.java')
            dst=self.java_root/rel
            if dst.exists(): continue
            src=next((r/rel for r in removed if (r/rel).is_file()),None)
            if src:
                candidates.append(('restore',fq,src,dst,d)); continue
            # If DEX itself confirms the class, create a deliberately tiny shell.
            if self.oracle.class_exists(fq):
                candidates.append(('shell',fq,None,dst,d))
        if not candidates: return None
        # Restore/create one missing class at a time. This makes rollback attribution
        # exact and prevents a bad compatibility shell from condemning good rescues.
        candidates=candidates[:1]
        changed=[]; edits=[]; backups={}
        for action,fq,src,dst,d in candidates:
            dst.parent.mkdir(parents=True,exist_ok=True)
            backups[str(dst.resolve())]=None
            if action=='restore':
                shutil.copy2(src,dst)
                reason=f"restore source pruned earlier: {src}"
            else:
                pkg, simple=fq.rsplit('.',1) if '.' in fq else ('',fq)
                sc=self.oracle.get_class(fq)
                if simple.startswith('Interface') or (sc and 'interface' in sc.flags): kind='interface'
                elif simple.startswith('Abstract') or (sc and 'abstract' in sc.flags): kind='abstract class'
                else: kind='class'
                body=(f"package {pkg};\n\n" if pkg else '') + f"public {kind} {simple} {{\n}}\n"
                dst.write_text(body)
                reason=f"APK smali confirms missing class {sc.raw_fqcn if sc else fq}; create minimal compatibility shell"
            candidate_edit = Edit(str(dst.resolve()),0,0,'',f'orphan-{action}',.99,reason,_diag_dict(d),destructive=True)
            if candidate_edit.signature() in self.rejected or candidate_edit.strategy_key() in self.rejected_strategies:
                try: dst.unlink(missing_ok=True)
                except Exception: pass
                continue
            changed.append(str(dst.resolve()))
            edits.append(candidate_edit)
        if not changed:
            return None
        self.pending={
            'round': self.round_no,
            'before_error_count': current_cost[0],
            'before_fingerprint': current_fp,
            'before_cost': list(current_cost),
            'before_keys': sorted(repr(d.key()) for d in diags),
            'before_files': sorted({_diag_file_key(d.file) for d in diags}),
            'before_blocker_count': sum(1 for d in diags if _is_frontier_blocker(d)),
            'backups': backups,
            'edit_signatures': [e.signature() for e in edits],
            'strategy_keys': [e.strategy_key() for e in edits],
            'batch_signature': _batch_signature(edits),
            'changed_files': changed,
            'edits': [asdict(e) for e in edits],
            'created_files': changed,
        }
        result=RepairResult(changed,edits,[],len(diags),current_fp,self.round_no)
        self._write_round(result)
        self._log(f"semantic Java repair: restored/generated {len(changed)} missing imported source class(es); validating full compiler frontier")
        return result

    def register_external_transaction(
        self, gradle_output: str, *, backups: dict[str, str], changed_files: list[str],
        label: str, metadata: dict | None = None,
    ) -> bool:
        """Put a non-AST source mutation (for example targeted JADX) under the
        exact same monotonic javac checkpoint/rollback policy as semantic edits.
        """
        if self.pending or not changed_files:
            return False
        diags = self._errors(gradle_output)
        current_fp = diagnostic_fingerprint(diags)
        current_cost = diagnostic_cost(diags)
        before_keys = sorted(repr(d.key()) for d in diags)
        self.pending = {
            "round": self.round_no,
            "external": True,
            "external_label": label,
            "external_metadata": metadata or {},
            "before_error_count": len(diags),
            "before_fingerprint": current_fp,
            "before_cost": list(current_cost),
            "before_keys": before_keys,
            "before_files": sorted({_diag_file_key(d.file) for d in diags}),
            "before_blocker_count": sum(1 for d in diags if _is_frontier_blocker(d)),
            "backups": dict(backups),
            "edit_signatures": [],
            "strategy_keys": [],
            "batch_signature": f"external:{label}:" + hashlib.sha256(
                "\n".join(sorted(changed_files)).encode()
            ).hexdigest(),
            "changed_files": list(changed_files),
            "edits": [],
        }
        if self.best_cost is None or current_cost < self.best_cost:
            self.best_cost, self.best_fingerprint = current_cost, current_fp
            self._save_persistent_state()
        self._log(
            f"registered external source transaction '{label}' at {len(diags)} javac error(s); "
            "next compile must improve or it will be restored"
        )
        return True

    def observe_build(self, gradle_output: str, *, build_succeeded: bool = False) -> ObserveResult:
        if not self.pending:
            return ObserveResult()
        after = self._errors(gradle_output)
        # A prerequisite/resource/manifest failure can occur before javac runs.
        # In that case an empty diagnostic set is NOT evidence that Java improved.
        if not after and not build_succeeded:
            return ObserveResult()
        before_count = self.pending["before_error_count"]
        after_count = len(after)
        fp = diagnostic_fingerprint(after)
        before_fp = self.pending["before_fingerprint"]
        before_keys = set(self.pending.get("before_keys", []))
        after_keys = {repr(d.key()) for d in after}
        resolved = len(before_keys - after_keys)
        introduced = len(after_keys - before_keys)
        before_cost = tuple(self.pending.get("before_cost") or (before_count, 0, 0))
        after_cost = diagnostic_cost(after)

        # javac/Gradle has a *diagnostic frontier*: fixing a parser/constructor/type
        # blocker can make attribution proceed into hundreds of files that were never
        # meaningfully checked before. That is not the same thing as a bad repair.
        before_files=set(self.pending.get("before_files") or [])
        after_files={_diag_file_key(d.file) for d in after}
        changed_files={_diag_file_key(f) for f in self.pending.get("changed_files", [])}
        new_in_changed=sum(1 for d in after if _diag_file_key(d.file) in changed_files)
        blockers=int(self.pending.get("before_blocker_count",0) or 0)
        frontier_expansion = (
            after_count > before_count
            and resolved >= max(1, int(before_count * 0.90))
            and new_in_changed == 0
            and len(after_files) >= max(len(before_files) + 3, 5)
            and (before_count <= 20 or blockers >= max(1, before_count // 2))
        )

        should_rollback = False
        reason = ""
        if frontier_expansion:
            self.frontier_epoch += 1
            expansion={
                "epoch": self.frontier_epoch, "before_errors": before_count, "after_errors": after_count,
                "before_files": len(before_files), "after_files": len(after_files),
                "resolved": resolved, "introduced": introduced, "changed_files": sorted(changed_files),
            }
            self.frontier_expansions.append(expansion)
            # A new attribution frontier changes the surrounding type graph. Keep
            # exact proven-bad edits blacklisted, but release broad strategy bans so
            # a strategy rejected in the old frontier can be reconsidered with the
            # newly available declarations/types.
            self.strategy_failures.clear()
            self.rejected_strategies.clear()
            reason=(f"compiler frontier expanded after blocker repair: {before_count} visible errors/{len(before_files)} files "
                    f"-> {after_count} errors/{len(after_files)} files; old blocker diagnostics resolved and no new error is in changed source")
            self._log(f"\033[95m[JAVA-FRONTIER][EXPANDED]\033[0m {reason}")
        elif after_count > before_count:
            should_rollback = True
            reason = (f"compiler state regressed from {before_count} to {after_count} errors "
                      f"(resolved={resolved}, introduced={introduced}, new_in_changed={new_in_changed})")
        elif fp == before_fp:
            should_rollback = True
            reason = "javac diagnostics were identical after repair"
        elif after_count == before_count and after_cost >= before_cost:
            should_rollback = True
            reason = (f"error count stayed at {after_count} and diagnostic frontier did not improve "
                      f"({before_cost} -> {after_cost})")
        elif introduced > resolved and after_count >= before_count:
            should_rollback = True
            reason = (f"repair replaced too many original diagnostics with new ones "
                      f"(resolved={resolved}, introduced={introduced})")

        if should_rollback and self.rollback_enabled:
            self._rollback_pending(reason)
            return ObserveResult(True, True, False, before_count, after_count, reason)

        reason = reason or (
            f"compiler state improved {before_cost} -> {after_cost}; "
            f"resolved={resolved}, introduced={introduced}"
        )
        self._commit_pending(reason, after_count, after_cost, fp)
        return ObserveResult(True, False, True, before_count, after_count, reason)

    def _queue_split_retry(self, p: dict, reason: str):
        edits = [Edit(**e) for e in p.get("edits", [])]
        if len(edits) <= 1:
            return
        # Split by edit count, retaining deterministic confidence order. Testing
        # smaller subsets identifies the culprit instead of condemning every edit in
        # a mixed transaction. Subsets are valid only against this exact baseline.
        edits.sort(key=lambda e: (e.confidence, not e.destructive), reverse=True)
        mid = max(1, len(edits) // 2)
        subsets = [edits[:mid], edits[mid:]]
        for subset in subsets:
            if not subset:
                continue
            bsig = _batch_signature(subset)
            if bsig in self.rejected_batches:
                continue
            self.retry_batches.append({
                "baseline_fingerprint": p["before_fingerprint"],
                "baseline_cost": p.get("before_cost"),
                "edits": subset,
                "parent_batch": p.get("batch_signature"),
                "reason": reason,
            })

    def _rollback_pending(self, reason: str):
        p = self.pending
        if not p: return
        for file, backup in p["backups"].items():
            dst = Path(file)
            if not backup:
                try: dst.unlink(missing_ok=True)
                except Exception: pass
                continue
            bp = Path(backup)
            if bp.is_file(): shutil.copy2(bp, dst)

        batch_sig = p.get("batch_signature") or _batch_signature(Edit(**e) for e in p.get("edits", []))
        self.rejected_batches.add(batch_sig)
        edits = [Edit(**e) for e in p.get("edits", [])]
        if p.get("external"):
            # External mutations are atomic; their source offsets/alternatives are
            # controlled by the caller, so never enqueue semantic bisection.
            pass
        elif len(edits) > 1:
            self._queue_split_retry(p, reason)
        else:
            # A failed singleton identifies a bad candidate precisely. Reject the
            # exact edit; only blacklist the broader strategy after two failed
            # variants for the same diagnostic so alternative repairs still get a try.
            for e in edits:
                self.rejected.add(e.signature())
                sk = e.strategy_key()
                self.strategy_failures[sk] += 1
                if self.strategy_failures[sk] >= 2:
                    self.rejected_strategies.add(sk)

        rec = dict(p); rec.update({
            "outcome": "rolled-back", "outcome_reason": reason,
            "retry_subsets_queued": len(self.retry_batches),
        })
        self.history.append(rec); self._write_history(); self._save_persistent_state(); self.pending = None
        self.helper.cache.clear(); self.index = None
        self._log(f"semantic Java repair rolled back: {reason}; "
                  f"{len(self.retry_batches)} subset trial(s) queued")

    def _commit_pending(self, reason: str, after_count: int, after_cost=None, after_fingerprint=None):
        p = self.pending
        if not p: return
        rec = dict(p); rec.update({
            "outcome": "kept", "outcome_reason": reason,
            "after_error_count": after_count,
            "after_cost": list(after_cost) if after_cost is not None else None,
            "after_fingerprint": after_fingerprint,
        })
        self.history.append(rec); self._write_history(); self.pending = None
        # The source tree moved to a new checkpoint, so subset candidates calculated
        # against the old source offsets/diagnostics are stale. Recompute fresh.
        self.retry_batches.clear()
        if after_cost is not None:
            self.best_cost = tuple(after_cost)
        if after_fingerprint is not None:
            self.best_fingerprint = after_fingerprint
        self._save_persistent_state()
        self.helper.cache.clear(); self.index = None

    def _write_history(self):
        (self.root / "history.json").write_text(json.dumps(self.history, indent=2, default=str) + "\n")

    def repair(self, gradle_output: str) -> RepairResult:
        if self.mode == "off" or self.round_no >= self.max_rounds or self.pending:
            return RepairResult()
        diags = self._errors(gradle_output)
        if not diags:
            return RepairResult()
        current_fp = diagnostic_fingerprint(diags)
        current_cost = diagnostic_cost(diags)
        if self.best_cost is None or current_cost < self.best_cost:
            self.best_cost, self.best_fingerprint = current_cost, current_fp
            self._save_persistent_state()
        # Discard stale subset trials if anything outside the transaction changed the
        # source/compiler frontier (for example a targeted JADX replacement).
        self.retry_batches = [b for b in self.retry_batches if b.get("baseline_fingerprint") == current_fp]
        self.round_no += 1
        if self.index is None:
            self._log("indexing Java source tree for semantic repair evidence")
            self.index = ProjectIndex.build(self.java_root, self.ignored_source_files)
        self.oracle.set_index(self.index)
        self._write_diagnostic_graph(diags)
        provider = self._restore_smali_provider_source(diags, current_fp, current_cost)
        if provider is not None:
            return provider
        orphan = self._restore_or_generate_missing_import(diags, current_fp, current_cost)
        if orphan is not None:
            return orphan
        provider_surface = self._bulk_smali_provider_members(diags, current_fp, current_cost)
        if provider_surface is not None:
            return provider_surface
        # Group diagnostics by app-owned source file.
        grouped: dict[Path, list[JavacDiagnostic]] = collections.defaultdict(list)
        skipped = []
        for d in diags:
            p = _path_for_diag(d, self.java_root)
            if not p:
                skipped.append({"diagnostic": _diag_dict(d), "reason": "diagnostic is not an app Java source file"}); continue
            primary = self.index.file_primary.get(str(p.resolve()), "")
            owners = self.library_class_owners.get(primary.replace('$', '.'), []) or self.library_class_owners.get(primary, [])
            intentionally_restored = False
            if owners:
                try:
                    rel = p.resolve().relative_to(self.java_root)
                    project = _project_root_from_java_root(self.java_root)
                    intentionally_restored = (project / "removed-library-sources" / rel).is_file()
                except Exception:
                    intentionally_restored = False
            if owners and not intentionally_restored:
                skipped.append({"diagnostic": _diag_dict(d), "reason": f"source is library-owned ({', '.join(owners)})"}); continue
            if owners and intentionally_restored:
                self._log(f"repairing restored APK-specific provider source {primary} despite Maven ownership")
            grouped[p].append(d)
        files = list(grouped)[: self.max_files]
        all_edits: list[Edit] = []
        for p in files:
            try: text = p.read_text(errors="ignore")
            except OSError: continue
            facts = self.helper.analyze(p)
            model = SourceModel(p, text, facts)
            method_diags = collections.defaultdict(list)
            for d in grouped[p]:
                all_edits.extend(propose_edits(d, model, self.index, self.mode, self.helper, self.oracle))
                mm = model.method_at_line(d.line)
                if mm:
                    method_diags[mm.get("id")].append(d)
            # When one decompiled method alone produces a large error island, it can
            # prevent javac from exposing the next useful frontier. In aggressive
            # mode quarantine that body as a fallback; higher-confidence surgical
            # edits still win overlap arbitration.
            if self.mode == "aggressive":
                for mid, mds in method_diags.items():
                    if len(mds) >= 8:
                        tx = _toxic_method_stub(mds[0], model, len(mds))
                        if tx: all_edits.append(tx)
                # Distributed toxic class: many methods have only 1-3 errors each,
                # so the older per-method threshold never fires even though the file
                # as a whole is clearly decompiler-corrupted. Quarantine the failing
                # method cohort transactionally; exact/surgical edits outrank these
                # and overlap arbitration keeps them instead whenever possible.
                if len(grouped[p]) >= 30 and len(method_diags) >= 6:
                    by_id = {m.get('id'): m for m in model.methods}
                    island = 0
                    for mid, mds in method_diags.items():
                        m = by_id.get(mid)
                        if not m:
                            continue
                        tx = _quarantine_error_method(mds[0], model, m, len(grouped[p]))
                        if tx:
                            all_edits.append(tx); island += 1
                    if island and self.tree_trace_level >= 1:
                        self._log(
                            f"\033[91m[JAVA-REPAIR][QUARANTINE]\033[0m {p.name}: {len(grouped[p])} errors across "
                            f"{len(method_diags)} methods; proposed {island} transactional method-body quarantine(s)"
                        )
        if self.tree_trace_level >= 1:
            kinds = collections.Counter(e.kind for e in all_edits)
            top = ", ".join(f"{k}={v}" for k,v in kinds.most_common(12)) or "<none>"
            self._log(f"\033[96m[JAVA-REPAIR][CANDIDATES]\033[0m {len(all_edits)} candidate edit(s): {top}")
        chosen = []
        selection_skips = []
        retry_batch = self.retry_batches.pop(0) if self.retry_batches else None
        if retry_batch is not None:
            # Re-test one half of a failed mixed transaction. Exact baseline matching
            # above guarantees these offsets refer to the restored source tree.
            chosen = [e for e in retry_batch["edits"]
                      if e.signature() not in self.rejected
                      and e.strategy_key() not in self.rejected_strategies]
            if chosen:
                self._log(f"semantic Java repair: trying isolated subset of {len(chosen)} edit(s) "
                          f"from failed batch {retry_batch.get('parent_batch') or '?'}")
        if not chosen:
            chosen, selection_skips = _select_edits(
                all_edits, self.min_confidence, self.mode, self.rejected, self.rejected_strategies
            )
        skipped.extend(selection_skips)
        if chosen and self.tree_trace_level >= 1:
            self._log(f"\033[92m[JAVA-REPAIR][SELECT]\033[0m selected {len(chosen)} edit(s) for transactional compile validation")
            if self.tree_trace_level >= 2:
                for e in chosen[:40]:
                    self._log(
                        f"\033[92m[JAVA-REPAIR][EDIT]\033[0m {Path(e.file).name}: {e.kind} "
                        f"conf={e.confidence:.3f}{' destructive' if e.destructive else ''} — {e.reason}"
                    )
                if len(chosen) > 40:
                    self._log(f"\033[92m[JAVA-REPAIR][EDIT]\033[0m … {len(chosen)-40} additional selected edit(s)")
        if not chosen:
            result = RepairResult([], [], skipped, len(diags), diagnostic_fingerprint(diags), self.round_no)
            self._write_round(result)
            return result
        # Group and backup files, then apply edits from right to left.
        by_file: dict[str, list[Edit]] = collections.defaultdict(list)
        for e in chosen: by_file[e.file].append(e)
        backup_dir = self.root / "backups" / f"round-{self.round_no:02d}"
        backups = {}
        changed = []
        for file, edits in by_file.items():
            p = Path(file)
            try: original = p.read_text(errors="ignore")
            except OSError: continue
            try: rel = p.resolve().relative_to(self.java_root)
            except Exception: rel = Path(p.name)
            bp = backup_dir / rel
            bp.parent.mkdir(parents=True, exist_ok=True)
            bp.write_text(original)
            backups[file] = str(bp)
            new = original
            # Coalesce multiple exact-position insertions (especially several
            # smali-backed members on one poisoned provider class) so one compile
            # round can repair the provider rather than one call site at a time.
            merged = []
            insertion_groups = collections.defaultdict(list)
            for e in edits:
                if e.start == e.end:
                    insertion_groups[(e.start,e.end)].append(e)
                else:
                    merged.append(e)
            for (st,en), group in insertion_groups.items():
                if len(group) == 1:
                    merged.append(group[0])
                else:
                    base = max(group, key=lambda x: x.confidence)
                    merged.append(Edit(base.file, st, en, ''.join(x.replacement for x in group),
                                       'coalesced-provider-insertions', min(x.confidence for x in group),
                                       '; '.join(x.reason for x in group), base.diagnostic,
                                       destructive=any(x.destructive for x in group)))
            for e in sorted(merged, key=lambda x: (x.start, x.end), reverse=True):
                if not (0 <= e.start <= e.end <= len(new)):
                    continue
                new = new[:e.start] + e.replacement + new[e.end:]
            if new != original:
                p.write_text(new)
                changed.append(file)
        chosen = [e for e in chosen if e.file in changed]
        result = RepairResult(changed, chosen, skipped, len(diags), diagnostic_fingerprint(diags), self.round_no)
        self._write_round(result)
        if changed:
            self.pending = {
                "round": self.round_no,
                "before_error_count": len(diags),
                "before_fingerprint": current_fp,
                "before_cost": list(current_cost),
                "before_keys": sorted(repr(d.key()) for d in diags),
                "before_files": sorted({_diag_file_key(d.file) for d in diags}),
                "before_blocker_count": sum(1 for d in diags if _is_frontier_blocker(d)),
                "backups": backups,
                "edit_signatures": [e.signature() for e in chosen],
                "strategy_keys": [e.strategy_key() for e in chosen],
                "batch_signature": _batch_signature(chosen),
                "changed_files": changed,
                "edits": [asdict(e) for e in chosen],
            }
            self._log(f"semantic Java repair round {self.round_no}: {len(chosen)} edit(s) in {len(changed)} file(s)")
        return result

    def _write_round(self, result: RepairResult):
        p = self.root / f"round-{result.round_no:02d}.json"
        p.write_text(json.dumps({
            "round": result.round_no,
            "before_error_count": result.before_error_count,
            "fingerprint": result.fingerprint,
            "changed_files": result.changed_files,
            "edits": [asdict(e) | {"signature": e.signature()} for e in result.edits],
            "skipped": result.skipped,
            "mode": self.mode,
            "min_confidence": self.min_confidence,
        }, indent=2, default=str) + "\n")

    def finalize(self):
        # If the caller stops before javac can validate a pending source mutation,
        # the safe state is the exact pre-transaction source, not an unproven edit.
        if self.pending and self.rollback_enabled:
            self._rollback_pending("run ended before javac could validate the source transaction")
        elif self.pending:
            rec = dict(self.pending); rec.update({
                "outcome": "pending-at-exit",
                "outcome_reason": "not enough compile evidence to evaluate and rollback was disabled",
            })
            self.history.append(rec); self._write_history()
        self._save_persistent_state()


__all__ = [
    "SourceRepairSession", "RepairResult", "ObserveResult",
    "parse_javac_diagnostics", "diagnostic_fingerprint", "diagnostic_cost",
]
