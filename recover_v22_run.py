#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, shutil, sys, zipfile
from datetime import datetime, timezone
from pathlib import Path


def snapshot(project: Path) -> Path:
    java = project / 'app/src/main/java'
    outdir = project / 'analysis/source-repair/recovery-snapshots'
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    dst = outdir / f'before-v22-recovery-{stamp}.zip'
    with zipfile.ZipFile(dst, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        if java.is_dir():
            for p in sorted(java.rglob('*.java')):
                z.write(p, 'app/src/main/java/' + p.relative_to(java).as_posix())
        for rel in ('app/build.gradle','build.gradle','settings.gradle','gradle.properties','local.properties'):
            p = project / rel
            if p.is_file(): z.write(p, rel)
    return dst


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def semantic_restore_plan(project: Path):
    history_path = project / 'analysis/source-repair/history.json'
    history = load_json(history_path, [])
    if not isinstance(history, list): return [], history_path
    plan=[]
    # v22 overwrote history.json at process start; therefore this file normally
    # describes only the latest invocation. Reverse accepted/unvalidated source
    # mutations in reverse transaction order.
    for rec in reversed(history):
        if rec.get('outcome') not in ('kept','pending-at-exit'):
            continue
        for dst, backup in (rec.get('backups') or {}).items():
            bp=Path(backup); dp=Path(dst)
            if bp.is_file(): plan.append((dp,bp,rec.get('round'),rec.get('outcome')))
    return plan, history_path


def current_run_targeted_plan(project: Path):
    cls_path = project / 'analysis/compile-failure-classification.json'
    audit_path = project / 'analysis/jadx-targeted-repair.json'
    cls = load_json(cls_path, [])
    audit = load_json(audit_path, [])
    n=0
    if isinstance(cls,list):
        for rec in cls:
            if rec.get('targeted_jadx_candidates') is not None:
                n=max(n,int(rec.get('targeted_jadx_candidates') or 0))
    if not n or not isinstance(audit,list): return [], cls_path, audit_path
    tail=audit[-n:]
    plan=[]
    for rec in reversed(tail):
        if rec.get('status')!='replaced': continue
        src=Path(str(rec.get('source','')))
        bp=Path(str(rec.get('backup','')))
        if src and bp.is_file(): plan.append((src,bp,rec.get('class')))
    return plan, cls_path, audit_path


def main():
    ap=argparse.ArgumentParser(description='Safely undo source mutations made by the latest v22 invocation.')
    ap.add_argument('project', nargs='?', type=Path, default=Path.cwd())
    ap.add_argument('--apply', action='store_true', help='actually restore files; default is dry-run')
    ap.add_argument('--include-targeted-jadx', action='store_true', help='also restore current-run targeted JADX replacements; v22 backups may be older than this run')
    z=ap.parse_args(); project=z.project.expanduser().resolve()
    java=project/'app/src/main/java'
    if not java.is_dir(): raise SystemExit(f'No Java source tree: {java}')
    semantic, hist=semantic_restore_plan(project)
    targeted=[]
    if z.include_targeted_jadx:
        targeted, cls, audit=current_run_targeted_plan(project)
    print(f'project: {project}')
    print(f'semantic files to restore: {len(semantic)} from {hist}')
    for dst,bp,r,o in semantic:
        print(f'  semantic round={r} outcome={o}: {dst} <- {bp}')
    if z.include_targeted_jadx:
        print(f'targeted JADX files to restore: {len(targeted)}')
        for dst,bp,c in targeted:
            print(f'  targeted {c}: {dst} <- {bp}')
        print('WARNING: v22 only created a targeted-JADX backup if one did not already exist; it may predate the latest rerun.')
    if not z.apply:
        print('\nDRY RUN ONLY. Re-run with --apply to restore the semantic files.')
        if targeted:
            print('Targeted JADX restoration remains explicitly enabled because --include-targeted-jadx was supplied.')
        return
    snap=snapshot(project)
    print(f'safety snapshot: {snap}')
    restored=set()
    for dst,bp,*_ in semantic:
        dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(bp,dst); restored.add(str(dst))
    for dst,bp,*_ in targeted:
        dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(bp,dst); restored.add(str(dst))
    print(f'restored {len(restored)} unique source file(s)')
    print('Now compile once WITHOUT source repair to measure the recovered baseline before making more edits.')

if __name__=='__main__': main()
