# v28.7 — DEX constructor-bridge lowering

v28.7 fixes a JVM↔DEX constructor semantic mismatch exposed only after the
replacement DEX reached the runtime-linkage gate.

The original APK contains legal DEX patterns such as:

```smali
new-instance v0, Lv2/a;
invoke-direct {v0}, Landroid/os/Binder;-><init>()V
```

`Lv2/a;` extends `Landroid/os/Binder;` but declares **no `<init>()V` method**.
That is representable in DEX/R8 output, but Java source/classfiles cannot express
`new v2.a()` without a constructor on `v2.a`.  apk2project's compile-time ABI
therefore exposes a temporary facade constructor.  javac emits
`v2.a.<init>()V`, and D8 quite reasonably carries that symbolic reference into
replacement DEX.  The strict runtime gate then correctly rejects it because the
real APK has no such method.

v28.7 treats this as a representation-boundary lowering, not as a missing-method
repair:

1. Scan original executable DEX for `new-instance T` followed by constructor
   initialization of the same allocation register.
2. Record a bridge only when the constructor owner is **T's direct superclass**
   and T does **not** declare that constructor descriptor.
3. Ambiguous observations are not used.
4. After D8, rewrite only matching `invoke-direct`/`invoke-direct-range`
   constructor references from `T.<init>` back to the exact superclass owner
   observed in the original APK.
5. Run the existing final-universe and runtime-linkage validators on the lowered
   DEX.  No unresolved facade constructor is allowed to survive packaging.

This preserves the original DEX as runtime truth.  The constructor added to the
JVM-facing ABI is only a bridge needed to cross Java's stricter constructor
model; it is never accepted as a real runtime member.

The merge report now includes:

- `constructor_bridge_rules_discovered`
- `constructor_bridge_rewrites`
- `constructor_bridge_rules_used`

Replacement DEX remains byte-identical to D8 output unless one of these
original-DEX-proven constructor bridges must be lowered.
