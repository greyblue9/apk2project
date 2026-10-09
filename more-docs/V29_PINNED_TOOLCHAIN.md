# v29.0 — Pinned toolchain, source-first runtime rebuild, and class-tree export

v29 deliberately reduces the number of representations and runtime choices that apk2project has to guess about. The successful v28.8 hybrid architecture is preserved: DEX remains runtime truth; javac still sees a source-facing ABI facade; replacement classfiles are dealiased to the raw runtime namespace; D8 produces replacement DEX; original DEX definitions are filtered only for exact replacement owners; and the final DEX universe is subjected to structural, forward-linkage, reverse-linkage, and constructor-bridge gates.

## 1. Tool ownership

apk2project now owns the versions of the tools that materially determine decompilation and runtime DEX behavior:

| Tool | Pinned version | Selection rule |
|---|---:|---|
| Apktool | 3.0.3 | apk2project tool cache only |
| JADX | 1.5.6 | apk2project tool cache only |
| smali-dexlib2 | 3.0.10 | apk2project pinned runtime bundle only |

The user may choose `--tools-dir`, which is a cache root rather than a way to inject a replacement jar. There is no per-dexlib-jar option, `DEXLIB_JAR` override, Gradle/Maven cache discovery, Apktool-shaded dexlib fallback, or system Apktool/JADX preference.

`analysis/toolchain.json` records the selected versions and concrete Apktool/JADX paths for each reconstructed project.

This does **not** mean apk2project blindly bundles every platform executable. Java/JDK and Android SDK/build-tools are still host/platform prerequisites. The change is intentionally scoped to tools whose API/behavior apk2project itself consumes and whose accidental version drift previously created compatibility layers.

## 2. Reflection/probing removal

The runtime DEX path already moved to direct `com.android.tools.smali.dexlib2` imports in v28.5. v29 removes the compatibility residue around that decision:

- no dexlib namespace probing or `probe-dexlib` subcommand;
- no reflective dexlib adapter;
- no system/cached dexlib candidate search;
- no `DEXLIB_CP` build-script injection; the runtime helper is compiled on demand against apk2project's pinned bundle;
- no JADX `--help` capability probing — the code calls the known 1.5.6 CLI surface directly;
- no Java reflection for JSON array serialization in the javac helper; primitive/object arrays use typed paths.

The goal is not “zero reflection at any cost.” The rule is that apk2project should not use reflection to paper over an API version it controls. Where a dependency is pinned and public, use its direct API.

## 3. Source-first replacement compilation

The hybrid rebuilder no longer treats a pre-existing `.class` directory as a user prerequisite.

At rebuild time it:

1. computes the exact source-owned runtime replacement plan from validated ownership metadata and the original DEX inventory;
2. locates known javac output if it exists;
3. verifies that every planned top-level replacement class exists and is not older than its Java source;
4. if output is missing/stale, invokes the reconstructed project's JavaCompile task itself;
5. rechecks the exact planned class set before dealiasing/D8.

Existing fresh output is reused. This keeps the hybrid layer idempotent without making classfile preparation part of the external interface.

At the main CLI level, `--rebuild-apk` implies `--compile`, so the normal apk2project path always reaches the validated javac boundary before entering the runtime DEX leg.

## 4. Complete DEX class tree

`--dump-class-tree` writes:

- `analysis/dex-class-tree.txt`
- `analysis/dex-class-tree.json`

The dumper is dependency-free and uses apk2project's direct DEX reader against the original APK. The text view is a superclass forest. Interface edges are annotations rather than tree edges because Java/DEX classes may implement multiple interfaces. Each node also records its source DEX entry and member counts.

The JSON view contains the complete class set, superclass, interfaces, children, DEX entry, field count, and method count. Every original class definition is emitted exactly once; malformed/cyclic leftovers are retained in a defensive final section instead of silently disappearing.

DEX entries are traversed in Android multidex order (`classes.dex`, `classes2.dex`, …, `classes10.dex`) rather than lexicographic filename order, so the reader's first-definition behavior matches the runtime ordering model.

This is intentionally a **DEX tree**, not a JADX source tree. Source reconstruction can rename, omit, synthesize, or merge artifacts; the dump is meant to expose the runtime class universe that apk2project treats as authoritative.

## 5. Invariants preserved from v28.8

v29 does not weaken the successful runtime gates:

- source-facing and runtime-facing ABI views remain separate;
- exact owner/name/prototype member identity is preserved;
- compiled classfile aliases are lowered before D8;
- original-Dex-proven constructor bridge lowering still occurs after D8 where JVM semantics cannot express the original DEX operation;
- untouched original DEX entries are copied byte-for-byte;
- only exact replacement descriptors are removed;
- final class count/uniqueness is checked;
- structural ABI compatibility is checked;
- replacement → final-runtime linkage is checked;
- retained-original → replacement reverse linkage is checked;
- original binary resources/manifest/assets/native libraries remain authoritative.

The v29 changes are therefore boundary simplifications around a proven runtime architecture, not a redesign of it.
