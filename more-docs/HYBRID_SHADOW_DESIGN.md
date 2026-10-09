# v26 Hybrid Compiler / APK ABI Shadow

## Why this exists

The v20-v25 repair engines still asked javac to parse and compile far too much decompiled code. A modern APK may contain application code plus AndroidX, Material, Guava, Kotlin helpers, generated adapters, shaded dependencies, R8-merged classes, and obfuscated support code. JADX can make any of those readable-ish, but that does **not** make them suitable Java source.

The key change in v26 is to stop treating all decompiled Java as source.

```text
APK DEX / apktool smali
          |
          | exact binary ABI facts
          v
  Java HybridCompiler
    - javac parser/symbol APIs
    - JDK internal ASM
          |
          +--> app/libs/apk2project-apk-shadow-abi.jar  (compileOnly)
          |
          +--> app/apk2project-binary-sources.txt
          |
          +--> analysis/hybrid-source-ownership.json

app/src/main/java remains intact:
    app package(s)          -> javac compiles as source
    everything else        -> visible for inspection, excluded from javac
```

This is intentionally closer to the original author's project boundary: application source on one side, already-compiled dependencies on the other.

## Why an ABI JAR instead of dex2jar

For **javac**, executable implementations are unnecessary. Javac needs class metadata: names, inheritance, interfaces, fields, methods, constructors, descriptors, access, generic signatures, inner-class relationships, and compile-time constants.

That means we can avoid the hardest DEX->JVM problem entirely. v26 emits JVM `.class` files whose methods have poison bodies (`aconst_null; athrow`). They are never intended to execute.

The JAR is added with Gradle `compileOnly`, so D8/R8 must not package it.

## Why use the APK instead of Maven binaries

The APK is the authoritative transformed ABI. R8 may have renamed/merged/optimized code, and JADX may expose aliases such as:

```text
RecyclerView.m814I(...)
RecyclerView.f1103t0
p036i1.AbstractC0570m
```

An upstream Maven RecyclerView or Guava JAR can have the right library version while still lacking the exact names seen by the decompiled APK. The shadow ABI comes from the APK's own smali and therefore knows what actually existed after shrinking/obfuscation.

## JADX alias reconstruction

The engine builds raw-Dex <-> source-name maps from:

1. parsed Java declarations;
2. imports, even if the provider Java file is missing;
3. observed method/field aliases throughout the source tree.

Examples:

```text
p036i1.AbstractC0570m  -> i1.m
C0115w                 -> w
m814I                  -> I
f1103t0                -> t0
```

For binary-owned classes, the ABI class can expose both the raw DEX member and observed JADX aliases. Extra aliases are acceptable because this JAR is a compile-time compatibility surface, not the runtime implementation.

## Smali metadata recovered into classfiles

v26 currently carries across:

- class/super/interface descriptors;
- field descriptors and static/final constant values;
- method/constructor descriptors;
- `dalvik.annotation.Signature` generic signatures;
- nested-class relationships via JVM `InnerClasses` metadata;
- static/abstract/native/interface/enum/synthetic/bridge/varargs flags where useful;
- optional permissive access widening for damaged decompiles.

Generic signatures are especially important. Without them, a DEX `Ljava/util/List;` looks raw to javac and can recreate errors such as `Object cannot be converted to Foo` in enhanced-for loops. The preserved Signature attribute can make javac see `List<Foo>` again.

Compile-time constants matter for `switch` labels and other constant expressions, so static final primitive/String values are emitted as `ConstantValue` attributes.

## Why `--add-exports`

The Java helper is compiled on the user's installed JDK and currently uses:

```text
jdk.compiler/com.sun.tools.javac.api
jdk.compiler/com.sun.tools.javac.code
jdk.compiler/com.sun.tools.javac.file
jdk.compiler/com.sun.tools.javac.tree
jdk.compiler/com.sun.tools.javac.util
java.base/jdk.internal.org.objectweb.asm
```

The syntax/index pass uses javac itself rather than a third-party parser. The attributed analysis pass runs `parse -> enter -> analyze` and can inspect `JCTree.type`, `Symbol`, `TreeInfo.symbol`, and `Types`.

It also unwraps javac's internal `JCDiagnostic` objects. For an incompatible-types error, the engine gets the actual `Type` objects rather than parsing English text and can ask:

```text
Types.isConvertible(found, required)
Types.isCastable(found, required)
Types.isSubtype(found, required)
Types.isSameType(found, required)
Types.lub(found, required)
```

These facts are written to `analysis/java-engine/attributed.jsonl` and are intended to become the primary semantic-repair input instead of Python regexes.

## Source ownership

By default v26 keeps the APK manifest package as editable source. Additional roots can be supplied with repeated `--app-source-prefix`.

For example:

```bash
python apk2project.py app.apk --compile --keep-work \
  --hybrid-shadow permissive \
  --app-source-prefix com.henrythompson.quoda
```

Everything outside the selected app package(s) remains in `app/src/main/java` for inspection but is listed in `app/apk2project-binary-sources.txt` and excluded from the Android Java source set.

This intentionally makes an obfuscated helper such as `p001a0.C0014k` binary-owned unless the user explicitly elects to compile that namespace as source.

## Classpath precedence

The shadow ABI is prepended to each JavaCompile classpath. This is deliberate. If Maven also supplies `androidx.recyclerview.widget.RecyclerView`, javac must see the APK-shadow version first because it may expose transformed aliases that the upstream binary does not.

## Important limitation: compile-time, not runtime

The ABI JAR has poison method bodies and is `compileOnly`. It solves source compilation; it is not yet a runnable replacement for the binary-owned portion of the APK.

A logical next architecture for a runnable rebuild is a **DEX overlay**:

1. keep the original APK's binary-owned DEX classes unchanged;
2. remove only app-owned classes from that DEX/smali set;
3. compile editable app Java to replacement DEX;
4. merge/repackage the untouched binary-owned DEX with the replacement app DEX.

That would preserve real library/obfuscated implementations rather than trying to recompile them from JADX at all.

## v27.1 exact linker hardening

The shadow candidate is now treated like a linker's output rather than a heuristic cache. Promotion requires exact DEX coverage for every binary-owned class: raw member descriptors, hierarchy, class kind, generic Signature attributes and Throws metadata must survive remapping. This catches jars that have plausible member counts but the wrong symbols.

Alias keys are descriptor-scoped. Fields use `(owner, rawName, rawDesc)`; methods use `(owner, rawName, rawMethodDesc)`. Syntax-only evidence is accepted only when it identifies a unique member. For same-name/same-arity method overloads, a javac attribution round compares the actual argument TypeMirrors with candidate parameter descriptors. A unique compatible overload receives the alias; ties are intentionally left unresolved.

Direct DEX annotations are now authoritative for `dalvik.annotation.Signature` and `dalvik.annotation.Throws`. Apktool/smali metadata only fills gaps and never overwrites metadata already decoded from the APK.
