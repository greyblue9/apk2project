# v25 Binary-Island Design

## Problem

An APK is a *deployment artifact*, not the author's source checkout. Decompiling every
DEX class into `app/src/main/java` collapses two originally separate namespaces into one:

1. source the author actually compiled; and
2. bytecode supplied by JAR/AAR dependencies.

`javac` then attempts to compile damaged JADX output for Guava/AndroidX/etc. even when an
authoritative binary already exists. Repairing those source copies is often wasted work.

The v25 strategy is therefore to reconstruct the **source/binary boundary**, not merely
repair syntax.

## Evidence hierarchy

Highest to lowest confidence:

1. exact source FQCN physically appears in a resolved Gradle JAR/AAR;
2. several currently failing source FQCNs physically appear in the same newly-discovered
   Maven/Google artifact;
3. package/group structural agreement;
4. package naming heuristics alone.

A binary island is never created from (4) alone.

## Complete runtime inventory

v24 asked Gradle only for AARs because the original purpose was resource reconciliation.
That omitted pure JAR dependencies from ownership/pruning. v25 adds a read-only task over
`debugRuntimeClasspath.incoming.artifactView` and emits both `.jar` and `.aar` artifacts.
Each artifact is indexed by the classes it physically contains.

This means a transitive Guava JAR can own `com.google.common.*` sources even if Guava was
never a direct coordinate selected by the Python resolver.

## Error-driven whole-artifact quarantine

Suppose javac reports failures in:

- `com.google.common.cache.RemovalCause`
- `com.google.common.collect.BoundType`

and the resolved Guava JAR contains both classes. Rather than move only those two files,
v25 computes:

`active Java source classes ∩ artifact classes`

and moves the whole overlap under `binary-island-sources/<artifact>/...` when at least two
classes (or enough diagnostics) implicate the artifact. This recreates the author's likely
boundary: Guava is a dependency, not part of application source.

The move is registered as an external `SourceRepairSession` transaction. Exact backups are
kept. The next complete javac frontier validates the move and can restore the sources if it
is a real regression.

## Emergency promotion

The normal dependency resolver already examines bundled classes outside the application
namespace, but huge APKs, query limits, version conflicts, or incomplete mappings can still
miss a family.

After javac fails, v25 takes only the failing third-party source FQCNs not already owned by
an artifact and performs a small exact lookup. Candidate artifacts are downloaded and
class-indexed. Selection strongly favors a single artifact containing several failing
classes. Package similarity is only secondary evidence.

If accepted, one `implementation "g:a:v"` line is inserted into the preserved Gradle file,
the artifact becomes a new ownership record, and its broken source cohort can immediately
be turned into a binary island.

## Why alias-heavy providers are different

R8 can transform a library class *inside the APK*. JADX with deobfuscation may expose
members like `m814I`, `f1103t0`, `m867y`. Callers reconstructed from the same DEX may refer
to those aliases even though the upstream Maven RecyclerView class does not expose them.

Therefore safe mode refuses to replace source classes containing multiple such aliases
with an upstream artifact. Those classes continue through the smali/DEX oracle and provider
reconstruction logic. This avoids confusing "same outer FQCN" with "same APK ABI".

## Why this differs from building a JAR from decompiled source

v25 never compiles broken JADX source merely to hide it in a JAR. That would preserve the
same reconstruction errors behind a different file extension.

The binary must already be authoritative:

- a resolved Maven/Google dependency, or
- eventually, a separately reconstructed APK-binary/ABI island sourced from DEX/smali.

The latter is a possible future extension for transformed library providers that cannot be
represented by the upstream artifact.

## Useful audit files

- `analysis/gradle-runtime-artifacts.json`
- `analysis/gradle-runtime-artifacts.log`
- `analysis/binary-islands/state.json`
- `analysis/binary-islands/last-plan.json`
- `analysis/binary-islands/emergency-discovery.jsonl`
- `binary-island-sources/`
