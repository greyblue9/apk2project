#!/usr/bin/env python3
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
src=(ROOT/'java_engine/DexHybridRebuilder.java').read_text()
hybrid=(ROOT/'hybrid_apk.py').read_text()

# Regression for a real R8/DEX impedance mismatch observed in TopActivity:
# new-instance Lv2/a; invoke-direct Landroid/os/Binder;-><init>()V while Lv2/a;
# declares no constructor. javac must temporarily see a facade constructor, but
# the D8 result must be lowered back to the constructor owner proven by original DEX.
assert 'discoverConstructorBridges' in src
assert 'lowerConstructorBridges' in src
assert 'Opcode.NEW_INSTANCE' in src
assert 'Opcode.INVOKE_DIRECT' in src and 'Opcode.INVOKE_DIRECT_RANGE' in src
assert 'Objects.equals(allocatedClass.getSuperclass(),target)' in src
assert '!declaresConstructor(allocatedClass,d)' in src
assert 'ImmutableInstruction35c' in src and 'ImmutableInstruction3rc' in src
assert 'new ImmutableMethodReference(target,"<init>"' in src
assert 'constructor_bridge_rewrites' in src
assert "'v29.0'" in hybrid

print('PASS original DEX constructor-bypass patterns are discovered from executable code')
print('PASS bridge rules require direct-super ownership and absent allocated-class ctor')
print('PASS D8 invoke-direct and invoke-direct/range references are lowered before linkage validation')
print('PASS v29 retains constructor bridge rewrites')
