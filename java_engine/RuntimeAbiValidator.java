package apk2project.hybrid;

import java.util.*;

/** Dependency-free structural ABI gate for source-owned runtime replacements. */
final class RuntimeAbiValidator {
    private RuntimeAbiValidator() {}

    static final class AbiCompat {
        final List<String> errors=new ArrayList<>(), warnings=new ArrayList<>();
    }
    static AbiCompat validateReplacementAbi(Map<String,DexReader.Clazz> original,
                                                     Map<String,DexReader.Clazz> rebuilt,
                                                     Collection<String> requestedDescriptors) {
        AbiCompat out=new AbiCompat();
        for(String d:requestedDescriptors){
            String f=descriptorFq(d); if(f==null)continue;
            DexReader.Clazz old=original.get(f), now=rebuilt.get(f);
            if(old==null){out.errors.add(d+": original ABI class missing");continue;}
            if(now==null){out.errors.add(d+": replacement ABI class missing");continue;}
            if(!Objects.equals(old.superDesc,now.superDesc))
                out.errors.add(d+": superclass changed "+old.superDesc+" -> "+now.superDesc);
            if(!new LinkedHashSet<>(old.interfaces).equals(new LinkedHashSet<>(now.interfaces)))
                out.errors.add(d+": interfaces changed "+old.interfaces+" -> "+now.interfaces);
            int classMask=0x0001|0x0010|0x0200|0x0400|0x2000|0x4000; // public/final/interface/abstract/annotation/enum
            if((old.access&classMask)!=(now.access&classMask))
                out.errors.add(d+": essential class access changed 0x"+Integer.toHexString(old.access&classMask)+
                        " -> 0x"+Integer.toHexString(now.access&classMask));

            Map<String,DexReader.Field> nf=new HashMap<>();
            for(DexReader.Field x:now.fields)nf.put(x.name+":"+x.desc,x);
            for(DexReader.Field x:old.fields){
                String k=x.name+":"+x.desc; DexReader.Field y=nf.get(k);
                if(y==null){
                    if((x.access&0x0002)==0) out.errors.add(d+": missing non-private field "+k);
                    else out.warnings.add(d+": missing private field "+k);
                    continue;
                }
                int fieldMask=0x0001|0x0002|0x0004|0x0008|0x0010|0x0040|0x0080; // visibility/static/final/volatile/transient
                if((x.access&fieldMask)!=(y.access&fieldMask))
                    out.errors.add(d+": field access changed "+k+" 0x"+Integer.toHexString(x.access&fieldMask)+
                            " -> 0x"+Integer.toHexString(y.access&fieldMask));
            }

            Map<String,DexReader.Method> nm=new HashMap<>();
            for(DexReader.Method x:now.methods)nm.put(x.name+x.desc,x);
            for(DexReader.Method x:old.methods){
                String k=x.name+x.desc; DexReader.Method y=nm.get(k);
                if(y==null){
                    // Private implementation details can legitimately disappear when the
                    // reconstructed method body no longer needs them. Reverse linkage still
                    // catches retained DEX that actually calls one. Keep them visible as warnings.
                    if((x.access&0x0002)==0) out.errors.add(d+": missing non-private method "+k);
                    else out.warnings.add(d+": missing private method "+k);
                    continue;
                }
                int methodMask=0x0001|0x0002|0x0004|0x0008|0x0010|0x0100|0x0400; // visibility/static/final/native/abstract
                if((x.access&methodMask)!=(y.access&methodMask))
                    out.errors.add(d+": method access changed "+k+" 0x"+Integer.toHexString(x.access&methodMask)+
                            " -> 0x"+Integer.toHexString(y.access&methodMask));
                if(x.signature!=null && y.signature!=null && !x.signature.equals(y.signature))
                    out.warnings.add(d+": generic method signature changed "+k);
            }
            if(old.signature!=null && now.signature!=null && !old.signature.equals(now.signature))
                out.warnings.add(d+": generic class signature changed");
        }
        return out;
    }

    private static String descriptorFq(String d){
        if(d==null)return null; while(d.startsWith("["))d=d.substring(1);
        return d.startsWith("L")&&d.endsWith(";") ? d.substring(1,d.length()-1).replace('/','.') : null;
    }

}
