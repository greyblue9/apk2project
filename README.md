# Apk2Project

**Version 29.0 — pinned toolchain, source-first hybrid rebuild, and DEX class-tree export**

Apk2Project reconstructs editable app-owned Java from an APK while keeping binary-owned/library code behind DEX-derived ABI facades. Its hybrid rebuild path recompiles only the reconstructed source-owned classes, lowers them back to the original raw DEX namespace/semantics, preserves the original binary resources and retained DEX code, then repacks and signs the APK.

## Quick usage

```bash
python3 apk2project.py \
  --keep-work \
  --hybrid-shadow permissive \
  --hybrid-obfuscated-binary \
  --hybrid-binary-source-action move \
  --binary-islands off \
  --java-repair aggressive \
  --java-repair-rounds 64 \
  --rebuild-apk \
  --hybrid-apk-sign debug \
  app.apk
```

`--rebuild-apk` now implies `--compile`; callers no longer have to pre-create or point apk2project at replacement `.class` files. If the expected javac output is missing or older than its source, the hybrid rebuilder invokes the reconstructed project's JavaCompile task and reuses fresh output on subsequent runs.

To emit a complete original-DEX superclass forest (plus machine-readable JSON), add:

```bash
--dump-class-tree
```

The files are written to `analysis/dex-class-tree.txt` and `analysis/dex-class-tree.json`.

## v29.0 — one owned, pinned toolchain

The main decompiler/runtime tools are now selected by apk2project rather than injected piecemeal by callers:

- Apktool **3.0.3**
- JADX **1.5.6**
- `com.android.tools.smali:smali-dexlib2` **3.0.10** plus its pinned runtime bundle

They live under `--tools-dir` (a cache-root choice, not an individual-jar override). Apk2Project no longer selects system Apktool/JADX, searches Gradle/Maven caches for dexlib2, consumes `DEXLIB_JAR`, accepts a dexlib jar override, or probes multiple shaded dexlib namespaces. The resolved versions and paths are recorded in `analysis/toolchain.json`.

The runtime DEX helper continues to use the public `com.android.tools.smali.dexlib2` API directly. The remaining Java array serialization reflection was also removed from the javac helper, and JADX capability probing was replaced with the known surface of the pinned JADX release. See `more-docs/V29_PINNED_TOOLCHAIN.md`.

## v29.0 — source-first runtime boundary

The hybrid API treats Java source as the input. Existing current javac output is reused; otherwise apk2project compiles it on demand. This preserves the validated source/binary ownership boundary while removing `.class` preparation as a user-facing prerequisite.

The repository is source-only for the Java helpers: precompiled `java_engine/classes` and `javac_engine/build` artifacts are not shipped and are ignored by Git. Helper bytecode is compiled against the local JDK when the relevant path is first needed.

The class-tree dumper is dependency-free and reads `class_defs` directly from the APK DEX universe. The printable tree follows superclass edges; interface relationships and per-class DEX/member metadata are included on each node, and every class definition is emitted exactly once.

Historical v28 milestones follow.

# v28.8 — verbose merge diagnostics

v28.8 retains the v28.7 runtime semantics and adds a detailed phase-by-phase trace around `apk2project.hybrid.DexHybridRebuilder.merge()`. It reports original/replacement class universes, constructor-bridge discovery/lowering, exact removal ownership, touched/byte-copied DEX files, hashes, appended multidex placement, ABI/linkage gates, and expanded class-hierarchy context for missing methods/fields. Verbosity is on by default and can be disabled with `APK2PROJECT_DEX_MERGE_VERBOSE=0`. See `V28_8_VERBOSE_MERGE.md`.

# v28.7 — DEX constructor-bridge lowering

v28.7 handles a real JVM↔DEX semantic mismatch exposed by the strict runtime-linkage gate. Some optimized DEX classes have no declared constructor and are instantiated by invoking their direct superclass constructor on the newly allocated object. Java source/classfiles cannot express that directly, so apk2project's compile-time ABI must expose a temporary facade constructor. After D8, v28.7 lowers only constructor references whose alternate owner is proven by the original APK, then reruns the normal final runtime-linkage gates. See `V28_7_DEX_CONSTRUCTOR_BRIDGES.md`.

# v28.6 — Canonical runtime dexlib classpath

The first real v28.5 run exposed a narrow launcher bug after successful app javac: the standalone dexlib2 bundle was downloaded, compiled, and successfully probed, but the following `inventory` command launched `DexHybridRebuilder` with only the engine classes directory on `-cp`. That dropped `smali-dexlib2` at runtime and produced `NoClassDefFoundError: com/android/tools/smali/dexlib2/iface/DexFile`.

v28.6 centralizes every `DexHybridRebuilder` invocation through a single launcher that always includes the engine classes plus the complete resolved dexlib runtime bundle. This is a wiring fix, not a rollback of the v28.5 architecture; the source/binary ownership boundary remains isolated from runtime DEX tooling. See `V28_6_RUNTIME_CLASSPATH.md`.

# v28.5 — direct standalone dexlib2 runtime boundary

v28.5 removes the reflection/shaded-Apktool compatibility layer from the runtime DEX path.
`apk2project` now uses the public `com.android.tools.smali:smali-dexlib2` API directly.
The important part is *when* that dependency is introduced: the source/JADX ownership and
shadow engine is compiled without dexlib2, and `DexHybridRebuilder` is compiled lazily only
after the app-owned `javac` boundary has already succeeded. A missing or incompatible dexlib2
can therefore fail `--rebuild-apk`, but it cannot collapse the source/binary boundary or send
quarantined AndroidX/library decompiler output back through javac.

Changes from v28.4:

* removed `Class.forName`, `Proxy`, and the dual `org.jf`/`com.android.tools.smali` reflection adapter;
* stopped treating Apktool as a candidate dexlib library entirely;
* searches the apk2project tools cache, Gradle/Maven caches, or bootstraps pinned
  `smali-dexlib2` 3.0.10 plus runtime dependencies;
* splits Java-engine compilation into a dexlib-independent core and a late runtime-Dex helper;
* runtime linkage validation now directly walks dexlib2 instruction/reference interfaces;
* call-site extra arguments, annotations, field encoded initial values, method handles,
  method types, enum/field/method encoded values, and nested annotation/array values are
  included in the runtime-reference gate.


---

# v28.1 — Conservative Hybrid APK Rebuilder

v28.1 tightens the first runtime rebuild design before producing an installable APK.  The most important
change is that D8 replacement code is no longer interned back into an original DEX file.  On API 21+ the
original DEX entry is filtered only to remove superseded definitions, while D8's output is appended as a
new `classesN.dex` byte-for-byte.  This reduces mutation of the original APK, avoids pushing a near-65K
DEX back over its ID limits, and keeps D8's own output intact.

Additional v28.1 gates:

* `invokedynamic`/lambda SAM method names are dealiased using the functional-interface owner + bootstrap
  method descriptor, so D8 cannot synthesize an implementation of a JADX alias;
* compiled `R$*.class` integer constants are checked against the original apktool `public.xml` backup before D8, so inlined resource IDs cannot silently drift away from the preserved `resources.arsc`;
* every explicitly replaced original class is structurally compared to the final replacement: superclass,
  interfaces, class kind/access, and non-private declared members must remain compatible;
* missing private implementation members are warnings unless retained original DEX actually references
  them, in which case the reverse-linkage gate remains fatal;
* append-only replacement DEX currently requires `minSdk >= 21`.  Pre-L output is refused rather than
  guessing about main-dex/MultiDex installation;
* the actual TopActivity APK dry run still resolves exactly five runtime replacements, 1,554 class links,
  9,897 exact member links, and a 1,531-class raw D8 ABI.  See `TOPACTIVITY_V28_1_DRYRUN.md`.


v28 extends the validated v27.5 compiler boundary into a runtime-preserving APK rebuild.  The
compile-time shadow remains a **source/JADX-facing ABI facade**; it is never packaged.  After a
successful javac build, v28 rewrites the selected app-owned `.class` files back to the APK's raw
DEX/R8 namespace, compiles only those replacements with D8, filters their original definitions
from the original `classes*.dex` with dexlib2, and repackages the original binary resources and
manifest unchanged.

The two ABI views are deliberately separate:

```text
Java/JADX source
      |
      | javac
      v
source-visible shadow ABI       (aliases such as AbstractC0488w.m1561e)
      |
      v
.class files
      |
      | RuntimeDealiaser: JOBF + exact shadow provenance
      v
raw runtime .class ABI          (original DEX owners/members such as f.w.e)
      |
      | D8, classpath = raw APK ABI jar
      v
replacement DEX
      |
      | dexlib2/DexBackedDexFile
      v
original DEX minus replaced owners + appended replacement DEX
      |
      | preserve original AndroidManifest.xml/resources.arsc/res/assets/lib
      v
hybrid APK -> zipalign -> debug sign -> apksigner verify
```

### Runtime safety gates

Before an APK is emitted, v28 now requires all of the following:

* source ownership came from a successfully validated hybrid-shadow build;
* compile-only scaffolding such as `R.java`/`BuildConfig` is not automatically treated as runtime
  replacement code;
* the bytecode dealiaser leaves no known JADX/shadow class, field, or method alias behind;
* D8 sees a second **raw-name ABI jar**, not the source-facing shadow jar;
* compiled `R` integer constants match the original resource-ID table;
* every expected final DEX class has exactly one definition;
* every class/method/field reference made by replacement DEX resolves to final raw DEX or the
  Android/Java boot classpath;
* retained original DEX is also scanned in the reverse direction for method/field calls into the
  replacement classes, preventing a decompiler-omitted member from becoming a runtime linkage
  failure;
* untouched multidex entries are copied byte-for-byte; only DEX entries containing replacement
  definitions are rewritten;
* original APK resources/manifest/assets/native libraries are carried forward rather than rebuilt,
  preserving the resource-ID universe expected by retained DEX;
* old signatures are removed, zip alignment is reapplied (16-KiB native-page mode when supported),
  and the debug-signed result is verified by `apksigner`.

For the uploaded TopActivity APK, v28's replacement planner selects exactly five runtime classes:

```text
io.github.ratul.topactivity.App
io.github.ratul.topactivity.receivers.NotificationActionReceiver
io.github.ratul.topactivity.services.AccessibilityMonitoringService
io.github.ratul.topactivity.services.PackageMonitoringService
io.github.ratul.topactivity.services.QuickSettingsTileService
```

`io.github.ratul.topactivity.R` is compile-time scaffolding and is not present in the original APK
DEX, while the four `io.github.ratul.topactivity.ui.*` classes remain original binary-owned DEX.
The direct APK inventory contains 1,536 classes; the raw ABI emitter excludes the five replacement
owners and emits 1,531 raw-name ABI classes for D8.

### Run

```bash
python apk2project.py app.apk \
  --compile --keep-work \
  --hybrid-shadow permissive \
  --hybrid-obfuscated-binary \
  --hybrid-binary-source-action move \
  --binary-islands off \
  --java-repair aggressive \
  --java-repair-rounds 64 \
  --rebuild-apk \
  --hybrid-apk-sign debug
```


Runtime diagnostics are written under `analysis/hybrid-apk/`, including the replacement plan,
dealias map/report, raw ABI report, D8 log, dex merge/linkage report, zipalign command, signature
verification, and the final `hybrid-apk-report.json`.

**Alpha limitation:** the complete D8 + dexlib2 + signing leg needs Android build-tools and a
compatible standalone smali-dexlib2 distribution on the machine doing the rebuild.  The compiler/dealiaser/raw-ABI,
DEX inventory, replacement planning, APK repacking, and regression layers can be exercised without
those external runtime tools.

---

# v27.5 — source-visible APK shadow ABI

**TopActivity diag3 fix:** DEX/R8 compatibility shims are frequently marked `synthetic`. The old shadow faithfully copied `ACC_SYNTHETIC`, but `javac` deliberately hides synthetic methods and constructors from Java source lookup. This produced the final six `cannot find symbol` errors even though `javap` and the exact validator showed the members were present. v27.5 treats the compileOnly shadow as a source-facing ABI facade and clears `ACC_SYNTHETIC`/method `ACC_BRIDGE` while preserving descriptors and provenance. See `TOPACTIVITY_DIAG3_REPORT.md`.

# apk2project v27.4.1 — Gradle separator fix

## v27.4.1 hotfix

The generated hybrid Gradle block no longer embeds a backslash literal inside a Python-generated Groovy string. It now normalizes paths with `java.io.File.separator`, avoiding the invalid Groovy output `.replace('\', '/')`. Rerunning against a `--keep-work` project replaces the existing marked hybrid block.

# apk2project v27.4 — Real-APK boundary fix

## v27.4 additions — reproduced against the uploaded TopActivity APK

I ran the hybrid-shadow/promotion path against the actual `io.github.ratul.topactivity_25.apk`,
the preserved source checkpoint from the second diagnostic bundle, and its exact JADX JOBF map.
That uncovered two boundary bugs that synthetic tests had missed:

* **Observed top-level flattening of nested DEX classes.** JOBF correctly records some classes as
  nested (`Outer$...$1`) but JADX can still emit their alias as a real top-level `.java` file. v27.4
  preserves nested identity by default, but when the source index proves that JADX emitted the exact
  alias as a top-level type, that observed shape overrides the nested default. This fixes the real
  `androidx.lifecycle.C0174xfdb59cc4` and Material floating-action-button cases without restoring
  the old global flattening/collision bug.
* **Intentional source-only shells now have explicit provenance.** Auxiliary/non-DEX source such as
  `kotlin.coroutines.jvm.internal.DebugProbesKt` can legitimately appear in the compile-only shadow.
  Such classes are recorded with `S` provenance and no longer count as unexplained/unmapped DEX
  classes. Truly unanchored classes are still fatal.
* **Merged-manifest library components are not app source roots.** AndroidX Startup and
  ProfileInstaller add provider/receiver entries to the merged manifest. v27.4 only promotes
  manifest components to strong source roots when their FQCN lies under an explicit app source
  prefix.

Against the exact TopActivity checkpoint, v27.4 validation reports 0 unmapped classes, 0 missing
raw DEX members, 0 hierarchy/kind/signature/throws mismatches, and 0 alias failures. With
`--hybrid-binary-source-action move`, 1,521 Java files move out of `app/src/main/java`, leaving six
active application sources. The AndroidX/Material files from the prior javac frontier are all in the
binary evidence archive and cannot reach `JavaCompile`. See `TOPACTIVITY_REAL_RUN_REPORT.md`.


v27.2 keeps the exact validated DEX shadow linker from v27.1 and adds a Java/javac-internal decompiler-source normalization pass before the first real javac build.
The APK's DEX metadata is the authoritative ABI; smali is optional enrichment for generic
`Signature` and constant metadata. Decompiled library/obfuscated source can remain on disk
without being compiled.
## v27.3 additions — based on the second TopActivity diagnostic snapshot

The second real TopActivity run exposed a very specific failure that was masking the success of the shadow approach. The candidate ownership classifier correctly marked every one of the final eight javac-failing files as **binary-owned** (Android framework compatibility stubs, AndroidX AppCompat/RecyclerView, and Material Chip), but the candidate shadow was rejected by the all-or-nothing validation gate because two unrelated nested lifecycle classes were flattened by JOBF onto the same package-level alias. Once the candidate was rejected, Gradle fell back to compiling the decompiled provider sources, so javac quite reasonably reported JADX `?? rN` syntax and illegal interface initializer blocks inside libraries that should never have reached javac.

v27.3 fixes that root cause rather than repairing those library files:

* JOBF nested classes retain their mapped outer identity. `e0$a = a` under `e0 = FragmentC0184e0` now becomes `FragmentC0184e0$a`, never package-level `a`. Multi-level nested classes are handled recursively.
* Shadow validation now detects and rejects duplicate `shadow owner <- multiple raw DEX classes` mappings explicitly instead of silently overwriting one provenance row.
* The exact TopActivity APK + JOBF mapping now validates from direct DEX truth with 1536/1536 classes mapped, 0 collisions, 0 missing raw members, 0 hierarchy/kind/signature/throws mismatches, and 0 alias failures.
* Gradle ownership is enforced twice: once through `android.sourceSets.main.java.exclude`, and again on the final `JavaCompile.source` in `doFirst`. This prevents AGP/plugins from reintroducing binary-owned source after source-set configuration.
* Targeted single-class JADX repair now refuses hybrid-binary-owned source. Those files are alias evidence only and cannot be re-decompiled back into the active compile surface.

The intended result is that parser errors in `androidx.*`, `com.google.android.material.*`, and decompiled `android.*` compatibility classes disappear by **not compiling those files**, rather than by attempting to make their JADX source legal Java.


Recommended run for a badly damaged JADX tree:

```bash
python apk2project.py app.apk --compile --keep-work \
  --hybrid-shadow permissive \
  --hybrid-obfuscated-binary \
  --hybrid-binary-source-action move \
  --java-repair aggressive \
  --java-repair-rounds 64
```

The generated `app/libs/apk2project-apk-shadow-abi.jar` is **compileOnly** and intentionally
non-executable. Its method bodies are poison stubs; only the ABI is meaningful.


## v27.2 additions

### JADX SSA common-type recovery with javac `Types.lub`

JADX warnings such as:

```text
/* JADX WARN: Type inference failed for: r0v1, types: [java.util.ArrayList] */
/* JADX WARN: Type inference failed for: r0v2, types: [java.util.List] */
/* JADX WARN: Type inference failed for: r0v3, types: [java.util.List] */
/* JADX WARN: Type inference failed for: r0v4 */
```

are now grouped by **method + physical register** (`r0`). Known SSA versions are resolved through
javac's actual type universe and `com.sun.tools.javac.code.Types.lub`. Untyped versions are treated
as missing evidence, not contradictory evidence. For the example above the Java engine obtains raw
`java.util.List` and can repair either `?? r0` or an over-specific `ArrayList r0`.

The rewrite is constrained by source uses. If the source calls a member that the candidate common
type does not expose (for example `ArrayList.trimToSize()`), the LUB is rejected rather than applied.
Raw warning types intentionally produce an erased/raw declaration (`List`, not
`List<? extends Object>`) because JADX's warning did not provide generic arguments.

Every decision is written to:

```text
analysis/java-engine/source-normalize.jsonl
analysis/java-engine/source-normalize.log
analysis/java-engine/normalize-backups/
```

Disable this pre-javac pass with `--no-hybrid-source-normalize`.

### Legal interface `<clinit>` reconstruction

A JVM/DEX interface may contain `<clinit>`, while Java source has never permitted an interface
`static { ... }` initializer block. JADX can therefore emit behaviorally meaningful but illegal
source such as:

```java
interface I {
    Object A;
    int B;
    static {
        A = new Object();
        B = 3;
    }
}
```

v27.2 no longer deletes that block. When the block consists solely of one assignment per
uninitialized interface field, the Java engine moves the RHS expressions into legal field
initializers and removes only the now-redundant block:

```java
interface I {
    Object A = new Object();
    int B = 3;
}
```

If the `<clinit>` has control flow, local temporaries, repeated assignments, or other complex
behavior, the normalizer **preserves it** and reports `interface-clinit-unsupported`. Such a class
should normally become binary-owned and use the exact DEX-derived shadow ABI rather than having
its initialization silently discarded. The older Python fallback was also hardened: it only
removes a truly empty interface static block.

## v27.1 additions

### Exact ABI promotion gate

A candidate shadow is no longer accepted because its class/member counts merely look sane. The
validator checks every binary-owned DEX class against the emitted JVM classfile:

- every Java-addressable raw DEX field and method survives under the remapped descriptor;
- superclass and interface sets are identical after class-name remapping;
- interface/annotation/enum class kind is preserved;
- DEX `dalvik.annotation.Signature` generic metadata is present in the classfile;
- DEX `dalvik.annotation.Throws` checked exceptions are present in the classfile;
- every JADX alias is anchored to one exact raw owner/member/descriptor and is physically emitted.

The direct DEX reader now decodes `Signature` and `Throws` itself, so these no longer depend on
apktool/smali. Smali can still fill metadata missing from DEX parsing but never overwrites metadata
already decoded directly from the APK.

### Descriptor-scoped aliases and overload resolution

Field aliases are now scoped by **owner + raw name + descriptor**, not merely owner + name.
Method aliases that encounter same-name/same-arity overloads are not sprayed across all overloads.
The iterative javac linker uses the attributed types of actual call arguments and `javax.lang.model`
type relations to choose one compatible DEX descriptor. If the choice is still ambiguous, it refuses
to guess and leaves the alias unresolved for a later evidence source (usually JOBF).

This matters for R8 output where an owner can legally contain several raw `a(...)` methods after
obfuscation. A source call such as `x.m777a("hello")` can now link specifically to
`a(Ljava/lang/String;)I` without inventing `m777a(int)`.

### TopActivity exact validation

On the supplied TopActivity APK, a newly generated direct-DEX candidate currently validates as:

```text
mapped binary classes       1535
unmapped classes               0
empty shells                   0
severe alias fan-out           0
missing raw DEX members        0
hierarchy mismatches           0
class-kind mismatches          0
generic-signature mismatches   0   (88 DEX signatures checked)
throws mismatches              0   (4 DEX Throws entries checked)
bad alias anchors              0
missing emitted aliases        0
```

The old uploaded shadow predates provenance tables, so v27.1 deliberately refuses to promote a jar
like it. In best-effort forensic mode that old jar still shows 29 empty shells, 882 fan-out classes,
1,404 definitely missing raw members, 117 hierarchy mismatches, generic/throws mismatches, and no
verifiable provenance map.

## What changed in v27

### Direct DEX is the ABI authority

`java_engine/DexReader.java` reads `classes.dex`, `classes2.dex`, ... directly from the APK:
class ownership, superclass/interfaces, fields, method prototypes, access flags, and static
constant values. A missing or stale Apktool tree can no longer turn a real APK class into an
empty shadow shell.

### Exact JADX JOBF mappings when available

The main JADX decompile now asks JADX to persist its auto-generated `.jobf` mapping. v27 reads
that mapping as owner+descriptor scoped evidence for class, package, field, and method aliases.
This is stronger than reversing `C####x`, `m####a`, `mo####e`, and `f####b` heuristically.
Heuristic inversion remains only as a fallback.

### Owner-scoped aliases only

Older prototypes globally fanned a suffix such as raw field `b` across every observed `f####b`.
That is catastrophically wrong after R8 because hundreds of unrelated classes have raw members
named `a`, `b`, `c`, etc. v27 never performs global suffix fan-out. Aliases are anchored to an
exact DEX owner/member/descriptor using, in order:

1. exact JOBF mappings;
2. provider declarations;
3. caller syntax with a known receiver type;
4. javac attributed receiver types.

### Iterative javac semantic linker

The Java engine emits a temporary minimal shadow and asks javac to partially attribute the
app-owned source. New aliases are attached only to the DEX member on the attributed receiver
type, the shadow is regenerated, and attribution runs again until a fixed point. This allows
chains to unlock across rounds:

```text
x.f777n.m888a(...)
   |
   +-- round 1 links f777n and reveals its DEX type Y
                         |
                         +-- round 2 links m888a on Y
```

Provider Java source can be completely absent. Caller evidence plus DEX is enough.

### Transactional exact shadow validation

Every candidate JAR now embeds two provenance tables:

```text
META-INF/apk2project-shadow-classes.tsv
META-INF/apk2project-shadow-aliases.tsv
```

Before it can replace the live JAR, the validator compares the candidate directly with the APK:

- every mapped shadow class has an exact DEX owner;
- every Java-addressable raw DEX field/method is present with the remapped JVM descriptor;
- superclass and interface relationships match;
- every synthetic alias points to a real owner/member/descriptor;
- every declared alias is physically present in the classfile;
- empty shells and severe member fan-out are rejected.

The candidate lives under `analysis/java-engine/candidate/`. Only a fully valid candidate is
atomically promoted to `app/libs/apk2project-apk-shadow-abi.jar`. A bad experiment therefore
cannot overwrite the last known-good compiler checkpoint.

### TopActivity forensic result

The diagnostic package supplied during development exposed the old shadow problem clearly:

```text
                         old shadow      v27 direct-DEX shadow
mapped classes              1624               1535
unmapped classes               4                  0
empty-shell failures           29                  0
severe alias fan-out          882                  0
missing raw DEX members      3908                  0
hierarchy mismatches          636                  0
bad alias anchors               -                  0
missing emitted aliases         -                  0
```

The older shadow was therefore poisoning javac's symbol universe; thousands of downstream
`cannot find symbol` messages were not trustworthy evidence about the reconstructed source.

## Java engine

The engine deliberately uses javac internals and JDK-internal ASM via `--add-exports`:

- `JavacTool` / `JavacTaskImpl` for parse, enter and attribution;
- `JCTree.type` and `Symbol` for real receiver/member ownership;
- `Types` for castability/convertibility/subtyping/LUB;
- structured `JCDiagnostic` arguments instead of parsing English diagnostics;
- `jdk.internal.org.objectweb.asm` for compile-only classfile generation.

See `HYBRID_SHADOW_DESIGN.md` for the architecture.

## Important outputs

```text
app/libs/apk2project-apk-shadow-abi.jar
app/apk2project-binary-sources.txt
analysis/hybrid-source-ownership.json
analysis/jadx-renames.jobf
analysis/java-engine/shadow-validation.json
analysis/java-engine/shadow-validation.log
analysis/java-engine/attributed.jsonl
analysis/java-engine/source-normalize.jsonl
analysis/java-engine/normalize-backups/
analysis/hybrid-binary-source-archive/java/
```

## Focused tests

```bash
python tests/hybrid_shadow_cases.py
python tests/hybrid_transactional_shadow.py
python tests/hybrid_gradle_classpath_case.py
python tests/obfuscated_binary_ownership.py
python tests/v27_2_ssa_clinit.py
```

The hybrid suite includes compile-backed tests for caller-only aliases, `mo####` aliases,
generalized JADX class aliases, chained multi-round attribution, exact JOBF mappings, generic
signatures, constants, nested classes, javac diagnostics/types, and transactional promotion.

---

# apk2project v25 — reconstructed dependency boundaries / binary islands

v25 adds a new strategy for exactly the failure shown by damaged classes such as
`com.google.common.cache.RemovalCause`, `BoundType`, `BloomFilterStrategies`, and
`TypeToken`: **do not compile decompiled library source when an authoritative binary
dependency can provide the same classes.**

## Binary islands

A reconstructed APK source tree is fundamentally different from the author's source
checkout: JADX gives you application code *plus source-shaped copies of every bundled
library*. The original author normally compiled application source against JAR/AAR
dependencies instead. v25 tries to reconstruct that boundary.

The pipeline now inventories **every JAR and AAR on Gradle's resolved
`debugRuntimeClasspath`**, not only transitive AARs. This closes an important v24 gap:
pure JAR dependencies such as Guava, Gson, Okio, and many JVM helpers could already
exist on Gradle's classpath while their damaged JADX sources still reached javac.

When two or more javac-failing source classes are physically contained in one resolved
artifact, v25 can quarantine the entire source/artifact overlap at once:

```text
RemovalCause.java  --\
BoundType.java     ---->  com.google.guava:guava:...  => move all overlapping Guava Java source out
TypeToken.java     --/                                  and compile callers against the JAR
```

Quarantined source is moved under `binary-island-sources/`, never deleted. The change
is registered as an external semantic transaction, so the next full javac result can
roll it back from exact backups if the compiler state genuinely regresses.

### Javac-driven emergency dependency promotion

If a broken bundled library was *not* discovered during the initial dependency pass,
v25 performs a tightly scoped late lookup using only the third-party source classes
currently producing javac errors. Candidate Maven/Google artifacts must physically
contain the exact classes. A candidate covering multiple failing classes gets very
strong ownership evidence; only then is one `implementation` line inserted and the
matching source cohort quarantined.

This is intentionally different from guessing from a package name alone. Package
similarity is only a secondary score; exact class coverage in the downloaded artifact
is mandatory.

### Safety around APK-specific/R8 ABI

An upstream Maven class is **not automatically equivalent** to the APK's transformed
class. Safe mode therefore leaves source classes containing multiple JADX/R8 member
aliases such as `m814I`, `f1103t0`, `m867y`, etc. in place. Those classes continue
through the DEX/smali oracle path, because callers may depend on package-private or
R8-renamed members that the published artifact does not expose.

Use:

```text
--binary-islands off
--binary-islands safe        # default
--binary-islands aggressive
```

Resume mode also appends a **read-only** `apk2projectResolvedArtifacts` Gradle task to
older generated projects. It does not rewrite the existing dependency classpath; it
only inventories the classpath that already produced the user's current compiler
checkpoint.


v24 is aimed at the failure mode where a reconstructed project appears to be down to a few javac errors, fixing one blocker suddenly exposes hundreds or thousands of errors, and many of the new errors are really repeated symptoms of a few damaged provider classes.

## The key change: make the javac frontier stable

Gradle incremental compilation can make a "3 error" build misleading: only the changed dependency closure may have been compiled. v24 forces JavaCompile to be non-incremental while semantic repair is active and raises javac's error ceiling to 10,000:

```groovy
tasks.withType(org.gradle.api.tasks.compile.JavaCompile).configureEach {
  options.incremental = false
  options.warnings = false
  options.compilerArgs.addAll(["-Xlint:none", "-nowarn", "-Xmaxerrs", "10000"])
}
```

This makes repair rounds comparable. A small blocker fix can still legitimately reveal a new compiler frontier, so v24 distinguishes a true regression from a frontier expansion. A large increase can be committed only when nearly all old blocker diagnostics disappear, the new errors are spread into previously unseen files, and none of the new errors occur in the files just modified. Other error-count increases are rolled back.

Frontier transitions are persisted in `analysis/source-repair/state.json` and `history.json`.

## DEX/smali is now an exact symbol oracle

The reconstructed Java tree is not treated as the ultimate source of truth for obfuscated members. v24 indexes the original Apktool smali and reverses common JADX aliases:

- `p036i1.AbstractC0570m` -> raw DEX `i1.m`
- `androidx.emoji2.text.C0115w` -> raw DEX `androidx.emoji2.text.w`
- `m814I` -> raw method `I`
- `f1103t0` -> raw field `t0`

When javac reports a missing method or field, v24 can ask the APK bytecode whether that member actually existed and recover its JVM descriptor. This is especially useful for APK-private/R8 members on otherwise familiar AndroidX classes.

### Bulk provider-surface repair

Before ordinary caller-level inference, v24 groups exact smali-backed missing members by provider. If 80 different call sites all fail because `RecyclerView` is missing `m814I`, `m815a`, `m816b`, `m867y`, `f1103t0`, etc., the engine repairs the provider class once instead of modifying 80 callers.

The whole provider batch is one compiler-validated transaction and is rolled back if it makes the full javac frontier worse.

### Over-pruned provider resurrection

If an earlier library-pruning pass moved the APK's decompiled provider source aside in favor of a Maven class, but the APK bytecode proves that the caller needs private/R8-specific members absent from the stock library, v24 can restore the entire provider source from `removed-library-sources` / `removed-platform-sources`.

### Exact field-type correction

For poisoned declarations such as an obfuscated holder field reconstructed with the wrong Java type, v24 can replace the provider field's declared type using the exact DEX descriptor rather than adding casts at every use.

## New source repairs in v24

In addition to v23's type inference, rollback, persistent blacklists, lost-local recovery, constructor overload recovery, enum compatibility, enhanced-for casts and warning suppression, v24 adds handlers for:

- JVM binary nested-class spelling in Java source, e.g. `WindowInsetsAnimation$Callback` -> `WindowInsetsAnimation.Callback`
- missing source classes confirmed by DEX; restore pruned source first, otherwise create a minimal compatibility shell
- APK-private/R8 missing fields and methods using exact smali descriptors
- package-private/protected/private source members that javac shows must be externally accessible
- lost `implements`/supertype relationships by use-site bridge casts when a source declaration cannot safely be changed
- `List`/`Collection` -> `ArrayList` decompiler mismatches by materializing a real `ArrayList`
- generic `SparseArray` capture mismatches through an erased bridge
- DEX integer/boolean and integer/null sentinel reconstruction
- reference comparisons emitted as `obj == 0` / `obj != 0`
- malformed `Enum.valueOf(...)` arity
- constructor temporaries placed before `this(...)` / `super(...)`; values are inlined so the chain call is first
- missing explicit superclass constructor calls using the smallest reconstructed superclass constructor
- impossible `super` use in static methods
- distributed toxic-class error islands: in aggressive mode, when one source file has >=30 errors spread over >=6 methods, failing method bodies can be transactionally quarantined even when no single method crosses the old 8-error threshold

Surgical and bytecode-backed edits outrank destructive stubs. Quarantine edits are only a fallback and still go through the same compile/rollback/blacklist machinery.

## Live colored Java AST tracing

The JDK compiler-tree helper now emits human-readable progress to **stderr**, while stdout remains strict JSON consumed by Python. This means the tree walker can be verbose without corrupting the repair protocol.

Default tracing is `detail`:

```text
[JAVA-TREE][OPEN]   .../RecyclerView.java bytes=...
[JAVA-TREE][SCAN]   RecyclerView.java package=androidx.recyclerview.widget ...
[JAVA-TREE][TYPE]   androidx.recyclerview.widget.RecyclerView class line=...
[JAVA-TREE][METHOD] RecyclerView.m814I(View) -> AbstractC0391b1 line=...
[JAVA-TREE][DONE]   RecyclerView.java ... types=... methods=... vars=... calls=...
[JAVA-TREE][FACTS]  RecyclerView.java: ... AST facts ...
```

Additional repair-side tracing includes:

```text
[JAVA-GRAPH][FRONTIER] ... top provider clusters ...
[JAVA-GRAPH][FILES]    ... hottest source files ...
[SMALI-ORACLE][PROVIDER] ... exact members restored ...
[JAVA-REPAIR][CANDIDATES] ... candidate strategies ...
[JAVA-REPAIR][EDIT] ... selected edit, confidence and evidence ...
[JAVA-FRONTIER][EXPANDED] ... blocker fix exposed a legitimate new frontier ...
[JAVA-REPAIR][QUARANTINE] ... destructive error-island fallback proposed ...
```

Control verbosity with:

```text
--java-tree-trace off
--java-tree-trace summary
--java-tree-trace detail      # default; types + methods
--java-tree-trace verbose     # also variables + calls
```

ANSI color obeys `NO_COLOR` / `TERM=dumb` in the Java helper.

## Resume safety retained from v23

An existing `app/src/main/java` tree is authoritative by default. A rerun preserves manual/source repairs, freezes prior dependencies unless `--refresh-dependencies` is requested, avoids targeted JADX replacement unless explicitly refreshing sources, persists proven-bad repair blacklists, and creates resume safety snapshots.

Use these only deliberately:

```text
--refresh-sources
--refresh-dependencies
--refresh-resources
--refresh-manifest
```

## Recommended run for heavily damaged decompiled source

```sh
python apk2project.py app.apk \
  --compile \
  --java-repair aggressive \
  --java-repair-rounds 64 \
  --java-repair-min-confidence 0.65 \
  --java-tree-trace detail \
  --keep-work
```

For maximum AST chatter while diagnosing a particularly bad provider:

```sh
... --java-tree-trace verbose
```

## Audit files

Important outputs live under `analysis/source-repair/`:

```text
state.json
history.json
diagnostic-graph.json
round-NN.json
backups/
helper-build.log
helper-errors/
resume-baselines/
```

Every accepted semantic mutation is compiler-validated. Failed mutations are restored, exact edits are blacklisted, mixed failed batches can be bisected, and cross-process state is retained.

## Tests

The archive includes compile-backed and structural tests for the older repair families plus v24-specific cases:

- inverse JADX alias mapping
- exact smali method reconstruction
- bulk provider-surface repair
- over-pruned provider resurrection
- exact DEX field-type correction
- nested `$` class spelling repair
- constructor-chain normalization
- int/boolean lowering repair
- legitimate 3 -> many-errors compiler-frontier expansion
- distributed toxic-method quarantine
- persistent rollback/blacklist/resume behavior

Run:

```sh
python tests/smoke_source_repair.py
python tests/regression_cases.py
python tests/search_strategy.py
python tests/resume_safety.py
python tests/v24_frontier_oracle_cases.py
```

## v25: do not force JADX's Java-bytecode D8 converter for APK input

Earlier versions explicitly passed:

```text
-Pjava-convert.mode=d8
```

That has now been removed from both the main APK decompile and targeted single-class
JADX retries.  JADX's `java-convert` plugin is for converting `.class`, `.jar`, and
`.aar` Java-bytecode inputs into DEX.  APK/DEX input is loaded by the `dex-input`
plugin, so forcing D8 is unnecessary for this program's normal APK path and obscures
which component is actually responsible for a decompilation failure.

This change is primarily about correctness and diagnostic clarity; it is not expected
by itself to cure `lost code at ... offset` messages, because those arise during
DEX-to-source reconstruction after the APK's DEX has already been loaded.

### v25 binary-island tests

```sh
python tests/binary_island_cases.py
```

They cover:

- expanding two failing Guava classes into a whole artifact/source quarantine cohort
- retaining alias-heavy APK/R8 provider classes in safe mode
- complete runtime JAR + AAR inventory
- javac-driven emergency Maven promotion with exact class coverage
- resume-mode helper injection without rewriting the existing classpath

## v27.1: force JADX-obfuscated source to binary ownership

For heavily obfuscated trees, this preset makes characteristic JADX aliases binary-owned even when they live under the selected app package:

```bash
python apk2project.py app.apk --compile --keep-work \
  --hybrid-shadow permissive \
  --hybrid-obfuscated-binary \
  --hybrid-binary-source-action move
```

The preset recognizes package segments such as `p001a0`, `p036i1`, etc. and class names such as `C0014k`, `AbstractC0570m`, `InterfaceC0698a`, `EnumC0199m`, and related `C<digits>...` forms. The binary override is evaluated before app-package/manifest ownership.

`move` is recommended: the shadow ABI is generated first, then binary-owned `.java` files are relocated from `app/src/main/java` to `analysis/hybrid-binary-source-archive/java`. Later runs scan that archive only as JADX alias evidence. Use `--hybrid-binary-source-action delete` only if you truly do not want the archived source.

Custom overrides are repeatable:

```bash
--hybrid-force-binary-regex '(^|\\.)p[0-9]+' \
--hybrid-force-binary-regex '(^|[.$])C[0-9]+'
```

## v27.2 Gradle classpath hotfix

Fixed hybrid shadow classpath injection for AGP projects where `JavaCompile.classpath` is still null during task configuration. The shadow ABI is now prepended in a `doFirst` action using `project.files(...)`, avoiding Groovy coercion to `[File, null]`. Rerunning with `--keep-work` replaces the existing APK2PROJECT_V27_HYBRID block automatically.

## v28.4: standalone dexlib2 + fail-closed rebuild boundary

The clean-slate v28 logs exposed that Apktool 3's bundled/shaded dexlib classes
are not a supported library ABI: some public-looking classes are present while
other interfaces/methods used by standalone dexlib2 are absent or transformed.

v28.4 therefore uses Apktool only as Apktool. Runtime DEX filtering/writing uses
an official standalone `com.android.tools.smali:smali-dexlib2` bundle. If no
complete dexlib distribution is supplied/found, it is bootstrapped into the
apk2project tools cache.

`--rebuild-apk` also makes hybrid-boundary initialization fail closed. A Java
engine/shadow failure can no longer silently drop back to compiling all
AndroidX/Material JADX sources; that fallback obscured the real v28.3 defect.

See `RECENT_OUTPUTS_DIAGNOSIS.md` for the run-by-run forensic timeline.
