from __future__ import annotations

import collections
import hashlib
import json
import re
import shutil
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Iterable

PACKAGE_RE = re.compile(r"(?m)^\s*package\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;")
TYPE_RE = re.compile(
    r"\b(?:public\s+|protected\s+|private\s+|abstract\s+|final\s+|static\s+|strictfp\s+)*"
    r"(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)"
)
JAVAC_FILE_RE = re.compile(
    r"(?m)^(?P<file>[^\n]*?\.java):(?P<line>\d+)(?::\d+)?:\s*(?:error|warning):\s*(?P<message>.*)$"
)
JADX_MEMBER_ALIAS_RE = re.compile(r"\b(?:m|f)\d+[A-Za-z_$][\w$]*\b")


@dataclass
class IslandArtifact:
    gav: tuple[str, str, str]
    file: str | None
    artifact_type: str | None
    classes: set[str] = field(default_factory=set)
    transitive: bool = False

    @property
    def notation(self) -> str:
        return ":".join(self.gav)


@dataclass
class IslandPlan:
    artifact: str
    error_files: list[str]
    error_count: int
    source_classes: list[str]
    source_files: list[str]
    skipped_alias_risk: list[str]
    confidence: float
    reason: str


@dataclass
class IslandApplyResult:
    changed_files: list[str] = field(default_factory=list)
    backups: dict[str, str] = field(default_factory=dict)
    quarantined: dict[str, str] = field(default_factory=dict)
    plan: IslandPlan | None = None

    @property
    def changed(self) -> bool:
        return bool(self.changed_files)


def normalize_binary_class(name: str) -> str:
    return str(name).split("$", 1)[0]


def source_fqcn(path: Path) -> str | None:
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return None
    pm = PACKAGE_RE.search(text)
    tm = TYPE_RE.search(text)
    if not tm:
        return None
    pkg = pm.group(1) if pm else ""
    return f"{pkg}.{tm.group(1)}" if pkg else tm.group(1)


def source_alias_risk(path: Path) -> bool:
    """Conservative signal that a source class exposes APK/R8-specific members.

    Such a class may not be ABI-compatible with the upstream Maven binary even when
    the outer FQCN matches.  Safe/balanced binary-island modes leave it in source;
    aggressive mode may still quarantine it.
    """
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return True
    return len(set(JADX_MEMBER_ALIAS_RE.findall(text))) >= 2


def _coerce_artifact(entry: dict) -> IslandArtifact | None:
    gav = tuple(entry.get("gav") or ())
    if len(gav) != 3:
        return None
    classes = {normalize_binary_class(c) for c in (entry.get("classes") or ())}
    return IslandArtifact(
        gav=(str(gav[0]), str(gav[1]), str(gav[2])),
        file=str(entry.get("file")) if entry.get("file") else None,
        artifact_type=str(entry.get("type")) if entry.get("type") else None,
        classes=classes,
        transitive=bool(entry.get("transitive")),
    )


class BinaryIslandManager:
    """Move broken decompiled library source behind an existing binary dependency.

    The important invariant is that we *never* build a jar from broken JADX Java.
    A source file may be quarantined only when an already-resolved binary artifact
    physically contains the exact outer class.  Gradle therefore compiles callers
    against the author's binary dependency rather than against a damaged decompile.

    This is intentionally error-driven.  Initial pruning remains conservative; when
    javac proves that a library-owned source cohort itself is failing, this manager
    can quarantine the whole overlapping artifact/source island in one transaction.
    """

    STATE_VERSION = 1

    def __init__(
        self,
        project_root: Path,
        java_root: Path,
        analysis_dir: Path,
        artifacts: Iterable[dict],
        *,
        mode: str = "safe",
        logger=None,
    ):
        self.project_root = Path(project_root)
        self.java_root = Path(java_root).resolve()
        self.analysis_dir = Path(analysis_dir)
        self.root = self.analysis_dir / "binary-islands"
        self.root.mkdir(parents=True, exist_ok=True)
        self.mode = mode
        self.log = logger or (lambda s: None)
        self.artifacts = [x for x in (_coerce_artifact(e) for e in artifacts) if x and x.classes]
        self.by_class: dict[str, list[IslandArtifact]] = collections.defaultdict(list)
        for artifact in self.artifacts:
            for cls in artifact.classes:
                self.by_class[cls].append(artifact)
        self.state_path = self.root / "state.json"
        self.state = self._load_state()

    def _load_state(self) -> dict:
        if self.state_path.is_file():
            try:
                data = json.loads(self.state_path.read_text())
                if isinstance(data, dict):
                    data.setdefault("version", self.STATE_VERSION)
                    data.setdefault("attempted_artifacts", [])
                    data.setdefault("history", [])
                    return data
            except Exception:
                pass
        return {"version": self.STATE_VERSION, "attempted_artifacts": [], "history": []}

    def _save_state(self):
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.state, indent=2, sort_keys=True) + "\n")
        tmp.replace(self.state_path)

    def _active_source_index(self) -> tuple[dict[str, Path], dict[Path, str]]:
        by_class: dict[str, Path] = {}
        by_file: dict[Path, str] = {}
        if not self.java_root.is_dir():
            return by_class, by_file
        for p in self.java_root.rglob("*.java"):
            fq = source_fqcn(p)
            if fq:
                rp = p.resolve()
                by_class[fq] = rp
                by_file[rp] = fq
        return by_class, by_file

    def _javac_error_files(self, text: str) -> collections.Counter[Path]:
        out: collections.Counter[Path] = collections.Counter()
        for m in JAVAC_FILE_RE.finditer(text or ""):
            p = Path(m.group("file"))
            try:
                p = p.resolve() if p.is_absolute() else (self.project_root / p).resolve()
                p.relative_to(self.java_root)
            except Exception:
                continue
            if p.is_file():
                out[p] += 1
        return out

    def _plan_for_artifact(
        self,
        artifact: IslandArtifact,
        *,
        errors_by_file: collections.Counter[Path],
        source_by_class: dict[str, Path],
        class_by_file: dict[Path, str],
    ) -> IslandPlan | None:
        err_files = [p for p in errors_by_file if class_by_file.get(p) in artifact.classes]
        if not err_files:
            return None
        error_count = sum(errors_by_file[p] for p in err_files)

        overlap = sorted(set(source_by_class) & artifact.classes)
        if not overlap:
            return None

        # One bad decompiled library class can be quarantined individually.  Once
        # javac implicates multiple classes from one binary artifact, treat the whole
        # source overlap as one "binary island". This is the glob behavior that
        # mirrors an author's source-vs-dependency boundary rather than repairing
        # dozens/hundreds of library files independently.
        expand_whole_artifact = len(err_files) >= 2 or error_count >= 4
        target_classes = overlap if expand_whole_artifact else sorted({class_by_file[p] for p in err_files})

        skipped: list[str] = []
        safe_targets: list[str] = []
        for fq in target_classes:
            p = source_by_class[fq]
            if self.mode != "aggressive" and source_alias_risk(p):
                skipped.append(fq)
            else:
                safe_targets.append(fq)
        if not safe_targets:
            return None

        # Error-bearing classes are high confidence because the class is both
        # physically in the dependency and demonstrably failing as source. Expanding
        # siblings from the same exact artifact is slightly less certain but still
        # much stronger than package-name heuristics alone.
        confidence = 0.999 if not expand_whole_artifact else 0.992
        reason = (
            f"javac reports {error_count} error(s) in {len(err_files)} decompiled source class(es) "
            f"that are physically contained in resolved artifact {artifact.notation}; "
            + ("quarantine the complete source/artifact overlap" if expand_whole_artifact else "quarantine the failing exact class")
        )
        return IslandPlan(
            artifact=artifact.notation,
            error_files=[str(p) for p in sorted(err_files)],
            error_count=error_count,
            source_classes=safe_targets,
            source_files=[str(source_by_class[fq]) for fq in safe_targets],
            skipped_alias_risk=skipped,
            confidence=confidence,
            reason=reason,
        )

    def choose_plan(self, gradle_output: str) -> IslandPlan | None:
        if self.mode == "off":
            return None
        source_by_class, class_by_file = self._active_source_index()
        errors_by_file = self._javac_error_files(gradle_output)
        if not errors_by_file:
            return None

        attempted = set(self.state.get("attempted_artifacts") or [])
        plans: list[IslandPlan] = []
        seen_artifacts = set()
        for p in errors_by_file:
            fq = class_by_file.get(p)
            if not fq:
                continue
            for artifact in self.by_class.get(fq, ()):
                if artifact.notation in attempted or artifact.notation in seen_artifacts:
                    continue
                seen_artifacts.add(artifact.notation)
                plan = self._plan_for_artifact(
                    artifact,
                    errors_by_file=errors_by_file,
                    source_by_class=source_by_class,
                    class_by_file=class_by_file,
                )
                if plan:
                    plans.append(plan)

        if not plans:
            return None
        plans.sort(
            key=lambda p: (p.error_count, len(p.error_files), len(p.source_classes), p.confidence),
            reverse=True,
        )
        return plans[0]

    def apply(self, plan: IslandPlan) -> IslandApplyResult:
        if plan.artifact in set(self.state.get("attempted_artifacts") or []):
            return IslandApplyResult(plan=plan)
        token = hashlib.sha256((plan.artifact + "\n" + "\n".join(plan.source_classes)).encode()).hexdigest()[:12]
        backup_root = self.root / "backups" / token
        quarantine_root = self.project_root / "binary-island-sources" / re.sub(r"[^A-Za-z0-9_.-]+", "_", plan.artifact)
        changed: list[str] = []
        backups: dict[str, str] = {}
        quarantined: dict[str, str] = {}

        for src_s in plan.source_files:
            src = Path(src_s).resolve()
            if not src.is_file():
                continue
            try:
                rel = src.relative_to(self.java_root)
            except ValueError:
                continue
            backup = backup_root / rel
            q = quarantine_root / rel
            backup.parent.mkdir(parents=True, exist_ok=True)
            q.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, backup)
            if q.exists():
                q.unlink()
            shutil.move(str(src), str(q))
            changed.append(str(src))
            backups[str(src)] = str(backup)
            quarantined[str(src)] = str(q)

        # Remove empty package directories only under source root.
        if self.java_root.is_dir():
            for d in sorted(self.java_root.rglob("*"), reverse=True):
                if d.is_dir():
                    try:
                        d.rmdir()
                    except OSError:
                        pass

        self.state.setdefault("attempted_artifacts", []).append(plan.artifact)
        rec = {
            "artifact": plan.artifact,
            "plan": asdict(plan),
            "changed_files": changed,
            "backups": backups,
            "quarantined": quarantined,
        }
        self.state.setdefault("history", []).append(rec)
        self._save_state()
        (self.root / "last-plan.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
        if changed:
            self.log(
                f"Binary island: quarantined {len(changed)} decompiled source file(s) behind {plan.artifact}; "
                f"the already-resolved binary dependency now owns those classes"
            )
            if plan.skipped_alias_risk:
                self.log(
                    f"Binary island retained {len(plan.skipped_alias_risk)} APK-specific alias-risk source class(es) "
                    "instead of replacing them with an upstream binary"
                )
        return IslandApplyResult(changed, backups, quarantined, plan)

    def repair(self, gradle_output: str) -> IslandApplyResult:
        plan = self.choose_plan(gradle_output)
        if not plan:
            return IslandApplyResult()
        return self.apply(plan)
