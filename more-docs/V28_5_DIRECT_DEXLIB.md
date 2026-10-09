# v28.5 direct dexlib runtime boundary

## Why this version exists

The v28.1–v28.4 failures were not a reason to abandon the validated apk2project architecture.
They exposed a bad dependency boundary: runtime DEX rewriting was trying to adapt Apktool's
private/shaded dexlib copy and then accumulated reflection compatibility code around it.

v28.5 removes that workaround layer.

## Boundary

```text
APK/JADX source analysis
        |
        | dexlib-independent HybridCompiler + DexReader
        v
validated source/binary ownership
        |
        v
app-owned javac succeeds
        |
        +---- only now resolve official standalone smali-dexlib2
                         |
                         | compile DexHybridRebuilder directly against public API
                         v
                 dealias -> D8 -> filter original DEX -> append replacement DEX
```

`DexHybridRebuilder.java` directly imports `com.android.tools.smali.dexlib2.*`; it no longer
uses `Class.forName`, `Method.invoke`, dynamic proxies, or the legacy `org.jf` compatibility
path. Apktool itself is not used as a dexlib provider.

## Runtime-reference validation added

The DEX linkage gate now walks reference-bearing instructions directly and also validates
references embedded in call-site extra arguments, method handles, method types, annotations,
static encoded field values, arrays, nested annotations, enum values, and method/field values.

## Failure rule

A dexlib resolution/compile/probe failure is fatal only to `--rebuild-apk`. It occurs after
validated app javac and must never trigger ordinary-source fallback.
