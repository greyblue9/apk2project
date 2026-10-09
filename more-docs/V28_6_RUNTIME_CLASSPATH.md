# v28.6 — Runtime dexlib classpath fix

The first real v28.5 Termux run reached the intended boundary:

- Gradle/app javac succeeded.
- apk2project downloaded the standalone `smali-dexlib2` bundle and dependencies.
- `DexHybridRebuilder` compiled successfully against that bundle.
- the `probe-dexlib` subcommand succeeded.

The next `inventory` launch failed with `NoClassDefFoundError: com/android/tools/smali/dexlib2/iface/DexFile`.

This was not a dexlib API incompatibility. `inventory_apk()` invoked Java with only the compiled engine directory:

```text
java -cp <analysis/java-engine/classes> apk2project.hybrid.DexHybridRebuilder inventory ...
```

while `probe-dexlib` and `merge` used the complete runtime classpath.

v28.6 removes that footgun rather than patching only the inventory line. Every runtime invocation now goes through one `run_dex_helper()` launcher, which always builds:

```text
engine classes
+ smali-dexlib2
+ guava
+ the remaining standalone runtime dependencies
```

into the Java `-cp`. `probe-dexlib`, `inventory`, and `merge` all use this one path.

A regression test (`tests/v28_6_runtime_classpath.py`) asserts both the exact classpath and that there is only one direct `DexHybridRebuilder` Java launch site in `hybrid_apk.py`.
