> **v28.5 note:** the reflection/dual-namespace dexlib adapter described in older sections below is superseded. `DexHybridRebuilder` now compiles lazily after app javac and imports the official `com.android.tools.smali:smali-dexlib2` API directly. See `V28_5_DIRECT_DEXLIB.md`.

# v28 Hybrid APK Runtime Design

## Goal

Turn the validated v27 source build into an installable APK **without recompiling or re-decompiling the binary-owned dependency universe**.  The original APK remains the runtime implementation for every class that was intentionally removed from javac.

## Two ABI worlds

The compile boundary and runtime boundary intentionally use different names:

```text
JADX/source namespace                  raw APK DEX namespace
---------------------                  ---------------------
p023f.AbstractC0488w.m1561e()   <->    f.w.e()
p023f.AbstractC0488w.m1558b()   <->    f.w.b()
...
```

The v27 shadow JAR exposes the left side to javac.  It is compile-only and contains poison/stub bodies.  v28 never packages it.

After javac succeeds, `RuntimeDealiaser` rewrites the resulting classfiles onto the right side before D8.  It uses:

1. `META-INF/apk2project-shadow-classes.tsv`
2. `META-INF/apk2project-shadow-aliases.tsv`
3. exact JADX JOBF member mappings
4. source ownership/raw-owner mappings

A post-transform ASM scan rejects any known source/JADX ABI aliases that remain in executable classfiles.

## Runtime D8 classpath

D8 receives a separately generated raw ABI JAR made directly from the APK DEX.  It contains raw DEX names and members only.  Replacement owners are omitted so a new class cannot accidentally link against the old definition during D8 conversion.

## Replacement planning

Only source-owned classes that already exist in the APK DEX are runtime replacements.  `R`, `R$*`, and `BuildConfig` are compile scaffolding unless runtime evidence proves otherwise.

Compiled `$...` companion classfiles are collected with their selected top-level owner.  The bytecode dealias pass applies exact mappings when available and enclosing-owner mapping otherwise.

## DEX rewrite

`DexHybridRebuilder` has no compile-time dexlib2 dependency.  At runtime it reflects over either:

* `com.android.tools.smali.dexlib2` (current smali/apktool ecosystem), or
* `org.jf.dexlib2` (legacy dexlib2 2.x).

The original `classes*.dex` are loaded through `DexBackedDexFile`.  DEX files with no replaced class are copied byte-for-byte.  A touched DEX is rebuilt from retained `ClassDef` objects only, using `DexPool` to omit the superseded definitions. On API 21+ D8 replacement DEX files are appended as new `classesN.dex` entries rather than interned into the filtered original DEX.

The dependency-free `DexReader` then reparses the emitted DEX independently and verifies the exact class universe.  A malformed dexlib2 output therefore cannot silently continue to packaging.

## Runtime linkage gates

Two directional gates run after DEX replacement:

```text
new replacement classes  ------>  retained original DEX
retained original DEX     ------>  new replacement classes
```

The first detects aliases or missing targets left by the source-to-raw transform.  The second detects original binary code that still expects a method/field which the decompiled replacement failed to reconstruct.

Only reverse references whose defining owner is actually a replacement class are made fatal; this avoids turning optional/unresolved references elsewhere in an otherwise-valid original APK into false positives.

## APK packaging

The first v28 milestone deliberately does **not** regenerate resources through aapt2/AGP.  It copies the original APK payload and changes only DEX/signing state:

```text
PRESERVE: AndroidManifest.xml
          resources.arsc
          res/**
          assets/**
          lib/**
          other ordinary ZIP entries

REPLACE:  affected classes*.dex
COPY:     unaffected classes*.dex byte-for-byte
REMOVE:   obsolete META-INF signing records
```

Rewriting the ZIP discards the old APK Signing Block.  The result is aligned before signing.  If the installed build-tools support `zipalign -P`, v28 requests 16-KiB native-library page alignment; older tools fall back to legacy page alignment.

## Signing

`--hybrid-apk-sign debug` creates/reuses `~/.android/debug.keystore`, signs with `apksigner`, and immediately runs `apksigner verify --verbose`.

The rebuilt APK cannot update an installed copy signed by the original developer unless the same signing key is supplied.  For ordinary testing the original app must therefore be uninstalled first.

## Failure philosophy

v28 is intentionally conservative.  It aborts rather than producing an APK when:

* the source/binary ownership checkpoint is absent;
* replacement classfiles cannot be located;
* a known alias survives dealiasing;
* D8 fails against the raw runtime ABI;
* the requested original class is absent;
* duplicate replacement classes occur;
* final DEX class identity differs from the expected universe;
* either runtime-link direction is unresolved;
* signing/alignment verification fails.

The goal is for a produced APK to mean substantially more than "the ZIP command succeeded."

## Structural replacement ABI gate

Instruction-reference validation is necessary but not sufficient: Android lifecycle callbacks, XML/reflection,
and framework entry points may never appear as retained DEX member references. v28.1 therefore compares each
explicit replacement owner against its original DEX declaration. Superclass/interfaces and essential class
flags must agree, and every original non-private field/method must remain present with compatible access/static
shape. Missing private members are reported as warnings; any retained bytecode that actually calls one is still
rejected by the reverse-linkage gate.

## Appended replacement DEX

For `minSdk >= 21`, touched original DEX entries are rewritten only to remove superseded class definitions.
Untouched original DEX entries are byte-copied. D8 output is then copied byte-for-byte to new `classesN.dex`
entries after the highest original multidex index. This avoids unnecessary reference-pool growth in original
DEX files. v28.1 refuses this mode below API 21 until an explicit main-dex/MultiDex proof is available.

## Resource-ID invariant

The final hybrid APK preserves the original `resources.arsc`, while javac can inline `R.type.name` integer
constants into replacement bytecode. Before D8, v28.1 reads the compiled `R$*.class` ConstantValue entries
and compares them with the original apktool `analysis/resource-backups/values/public.xml`. Any ID mismatch is
fatal. Non-constant holders such as `R.styleable` remain subject to the runtime-linkage gate; if replacement
bytecode still requires an `R$...` runtime class that the original APK does not contain, the rebuild is rejected.
