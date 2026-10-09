# v28.8 — verbose hybrid DEX merge diagnostics

v28.8 keeps the v28.7 constructor-bridge lowering and makes the runtime DEX merge deliberately verbose so failures can be localized without reverse-engineering a single final exception.

`apk2project.hybrid.DexHybridRebuilder.merge()` now emits timestamped, numbered phases and the important state transition at each phase:

1. startup paths / API levels / requested replacement descriptors
2. dexlib2 initialization
3. original APK DEX entries, byte sizes, class counts, and DEX API
4. constructor-bridge discovery, including proven and ambiguous rules
5. D8 replacement DEX inputs, class counts, and constructor rewrites
6. exact removal set and original DEX ownership
7. touched vs byte-copied original DEX entries
8. per-DEX rewrite/copy counts, sizes, SHA-256 values, and removed descriptors
9. appended replacement DEX mapping and final multidex order
10. exact final class-universe comparison
11. structural replacement ABI validation, including warnings/errors
12. replacement -> final-runtime linkage validation
13. retained-original -> replacement reverse-linkage validation
14. report emission and final summary

On a failure the helper also prints the phase number/name before rethrowing. Missing method/field linkage errors are expanded with the referenced owner's final DEX declaration, superclass chain, interfaces, and same-name methods/constructors/fields where available. This is particularly useful for DEX/JVM representation-boundary failures such as the v28.7 constructor-owner case.

The verbosity is enabled by default. To suppress it:

```bash
APK2PROJECT_DEX_MERGE_VERBOSE=0 python apk2project.py ...
```

The normal merge JSON report and `analysis/hybrid-apk/dex-merge.log` remain authoritative machine-readable/persistent artifacts; the new trace is diagnostic output around those same gates, not a relaxation of validation.
