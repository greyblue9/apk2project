package apk2project.hybrid;

import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/**
 * Small dependency-free DEX ABI reader.
 *
 * It intentionally reads only metadata needed by javac's compile-time shadow:
 * classes, inheritance, interfaces, declared fields, declared methods, access
 * flags, descriptors, constants, generic Signature metadata and declared Throws.
 * It does not translate method bytecode.
 *
 * DEX itself is therefore the authoritative ABI source.  Apktool/smali is only
 * optional enrichment/fallback; missing or malformed smali can no longer make a
 * real APK class or generic/checked-exception ABI disappear from the shadow jar.
 */
final class DexReader {
    static final class Field {
        String name, desc, signature;
        int access, dexIndex;
        Object constantValue;
    }
    static final class Method {
        String name, desc, signature;
        int access, dexIndex;
        final List<String> exceptions = new ArrayList<>(); // DEX descriptors
    }
    static final class Clazz {
        String fqcn, internal, superDesc, signature;
        int access;
        final List<String> interfaces = new ArrayList<>();
        final List<Field> fields = new ArrayList<>();
        final List<Method> methods = new ArrayList<>();
        String dexEntry;
    }

    private DexReader() {}

    static Map<String, Clazz> readApk(Path apk) throws IOException {
        Map<String, Clazz> out = new LinkedHashMap<>();
        try (ZipFile zf = new ZipFile(apk.toFile())) {
            List<? extends ZipEntry> dexEntries = Collections.list(zf.entries()).stream()
                    .filter(e -> e.getName().matches("classes(?:\\d+)?\\.dex"))
                    .sorted(Comparator.comparing(ZipEntry::getName)).toList();
            for (ZipEntry ze : dexEntries) {
                byte[] data;
                try (InputStream in = zf.getInputStream(ze)) { data = in.readAllBytes(); }
                readDex(data, ze.getName(), out);
            }
        }
        return out;
    }

    private static void readDex(byte[] b, String entry, Map<String, Clazz> out) throws IOException {
        if (b.length < 0x70 || b[0] != 'd' || b[1] != 'e' || b[2] != 'x' || b[3] != '\n')
            throw new IOException("not a DEX file: " + entry);
        LE d = new LE(b);
        int stringSize=d.u32(0x38), stringOff=d.u32(0x3c);
        int typeSize=d.u32(0x40), typeOff=d.u32(0x44);
        int protoSize=d.u32(0x48), protoOff=d.u32(0x4c);
        int fieldSize=d.u32(0x50), fieldOff=d.u32(0x54);
        int methodSize=d.u32(0x58), methodOff=d.u32(0x5c);
        int classSize=d.u32(0x60), classOff=d.u32(0x64);

        String[] strings = new String[stringSize];
        for (int i=0;i<stringSize;i++) strings[i]=d.stringData(d.u32(stringOff + 4*i));
        String[] types = new String[typeSize];
        for (int i=0;i<typeSize;i++) types[i]=strings[d.u32(typeOff + 4*i)];

        Proto[] protos = new Proto[protoSize];
        for (int i=0;i<protoSize;i++) {
            int o=protoOff+12*i;
            Proto p=new Proto(); p.ret=types[d.u32(o+4)];
            int poff=d.u32(o+8);
            if (poff!=0) {
                int n=d.u32(poff); p.params=new String[n];
                for (int j=0;j<n;j++) p.params[j]=types[d.u16(poff+4+2*j)];
            } else p.params=new String[0];
            protos[i]=p;
        }
        FieldId[] fieldIds=new FieldId[fieldSize];
        for (int i=0;i<fieldSize;i++) {
            int o=fieldOff+8*i; FieldId f=new FieldId();
            f.owner=types[d.u16(o)]; f.type=types[d.u16(o+2)]; f.name=strings[d.u32(o+4)]; fieldIds[i]=f;
        }
        MethodId[] methodIds=new MethodId[methodSize];
        for (int i=0;i<methodSize;i++) {
            int o=methodOff+8*i; MethodId m=new MethodId();
            m.owner=types[d.u16(o)]; m.proto=protos[d.u16(o+2)]; m.name=strings[d.u32(o+4)]; methodIds[i]=m;
        }

        // Decode class definitions and their class_data_item so only members actually
        // declared by the APK class are emitted (not merely referenced field/method IDs).
        for (int i=0;i<classSize;i++) {
            int o=classOff+32*i;
            int classIdx=d.u32(o), access=d.u32(o+4), superIdx=d.u32(o+8), interfacesOff=d.u32(o+12);
            int annotationsOff=d.u32(o+20), classDataOff=d.u32(o+24), staticValuesOff=d.u32(o+28);
            Clazz c=new Clazz(); c.internal=objectInternal(types[classIdx]); c.fqcn=c.internal.replace('/','.');
            c.access=access; c.superDesc=superIdx==0xffffffff ? "Ljava/lang/Object;" : types[superIdx]; c.dexEntry=entry;
            if (interfacesOff!=0) {
                int n=d.u32(interfacesOff);
                for (int j=0;j<n;j++) c.interfaces.add(types[d.u16(interfacesOff+4+2*j)]);
            }
            if (classDataOff!=0) {
                Cursor cur=new Cursor(classDataOff);
                int sf=d.uleb(cur), inf=d.uleb(cur), dm=d.uleb(cur), vm=d.uleb(cur);
                List<Field> staticFields=new ArrayList<>();
                decodeFields(d,cur,sf,fieldIds,c,staticFields);
                decodeFields(d,cur,inf,fieldIds,c,null);
                decodeMethods(d,cur,dm,methodIds,c);
                decodeMethods(d,cur,vm,methodIds,c);
                if (staticValuesOff!=0 && !staticFields.isEmpty()) decodeStaticValues(d,staticValuesOff,staticFields,strings,types);
            }
            if (annotationsOff!=0) decodeAnnotationDirectory(d,annotationsOff,c,strings,types);
            out.putIfAbsent(c.fqcn,c);
        }
    }

    private static void decodeFields(LE d, Cursor cur, int count, FieldId[] ids, Clazz c, List<Field> capture) throws IOException {
        int idx=0;
        for (int i=0;i<count;i++) {
            idx += d.uleb(cur); int access=d.uleb(cur);
            if (idx<0 || idx>=ids.length) throw new IOException("bad DEX field index " + idx);
            FieldId id=ids[idx]; Field f=new Field(); f.name=id.name; f.desc=id.type; f.access=access; f.dexIndex=idx;
            c.fields.add(f); if (capture!=null) capture.add(f);
        }
    }
    private static void decodeMethods(LE d, Cursor cur, int count, MethodId[] ids, Clazz c) throws IOException {
        int idx=0;
        for (int i=0;i<count;i++) {
            idx += d.uleb(cur); int access=d.uleb(cur); d.uleb(cur); // code_off
            if (idx<0 || idx>=ids.length) throw new IOException("bad DEX method index " + idx);
            MethodId id=ids[idx]; Method m=new Method(); m.name=id.name; m.desc=id.proto.desc(); m.access=access; m.dexIndex=idx; c.methods.add(m);
        }
    }

    // ------------------------------------------------------------- DEX annotations

    static final class AnnotationMeta {
        String signature;
        final List<String> exceptions = new ArrayList<>();
    }

    /**
     * Decode annotations_directory_item metadata that changes Java compilation.
     * In particular, dalvik.annotation.Signature restores generic class/member
     * signatures and dalvik.annotation.Throws restores checked exceptions.
     */
    private static void decodeAnnotationDirectory(LE d, int off, Clazz c, String[] strings, String[] types) {
        try {
            int classAnnotationsOff=d.u32(off), fieldsSize=d.u32(off+4), methodsSize=d.u32(off+8), paramsSize=d.u32(off+12);
            if(classAnnotationsOff!=0){AnnotationMeta a=decodeAnnotationSet(d,classAnnotationsOff,strings,types); if(a.signature!=null)c.signature=a.signature;}
            int p=off+16;
            Map<Integer,Field> fields=new HashMap<>(); for(Field f:c.fields)fields.put(f.dexIndex,f);
            for(int i=0;i<fieldsSize;i++,p+=8){
                int idx=d.u32(p), setOff=d.u32(p+4); Field f=fields.get(idx); if(f==null||setOff==0)continue;
                AnnotationMeta a=decodeAnnotationSet(d,setOff,strings,types); if(a.signature!=null)f.signature=a.signature;
            }
            Map<Integer,Method> methods=new HashMap<>(); for(Method m:c.methods)methods.put(m.dexIndex,m);
            for(int i=0;i<methodsSize;i++,p+=8){
                int idx=d.u32(p), setOff=d.u32(p+4); Method m=methods.get(idx); if(m==null||setOff==0)continue;
                AnnotationMeta a=decodeAnnotationSet(d,setOff,strings,types); if(a.signature!=null)m.signature=a.signature; m.exceptions.addAll(a.exceptions);
            }
            // parameter_annotations are irrelevant to javac ABI linkage for now.
            p += paramsSize * 8;
        } catch(Throwable ignored) { /* annotations are enrichment; core ABI remains usable */ }
    }

    private static AnnotationMeta decodeAnnotationSet(LE d, int setOff, String[] strings, String[] types) {
        AnnotationMeta out=new AnnotationMeta();
        int n=d.u32(setOff);
        for(int i=0;i<n;i++){
            int annOff=d.u32(setOff+4+4*i); if(annOff==0)continue;
            Cursor cur=new Cursor(annOff); cur.p++; // visibility
            int typeIdx=d.uleb(cur), elems=d.uleb(cur);
            String annType=(typeIdx>=0&&typeIdx<types.length)?types[typeIdx]:"";
            for(int e=0;e<elems;e++){
                int nameIdx=d.uleb(cur); String name=(nameIdx>=0&&nameIdx<strings.length)?strings[nameIdx]:"";
                if(annType.equals("Ldalvik/annotation/Signature;") && name.equals("value")) {
                    List<String> parts=readEncodedIndexArray(d,cur,0x17,strings,types);
                    if(parts!=null) out.signature=String.join("",parts);
                } else if(annType.equals("Ldalvik/annotation/Throws;") && name.equals("value")) {
                    List<String> ex=readEncodedIndexArray(d,cur,0x18,strings,types);
                    if(ex!=null) out.exceptions.addAll(ex);
                } else {
                    skipEncodedValue(d,cur);
                }
            }
        }
        return out;
    }

    /** Read VALUE_ARRAY containing VALUE_STRING or VALUE_TYPE entries. */
    private static List<String> readEncodedIndexArray(LE d, Cursor cur, int expectedType, String[] strings, String[] types) {
        int head=d.u8(cur.p++), type=head&0x1f, arg=(head>>>5)&7;
        if(type!=0x1c){ skipEncodedValueAfterHead(d,cur,type,arg); return null; }
        int n=d.uleb(cur); List<String> out=new ArrayList<>();
        for(int i=0;i<n;i++){
            int h=d.u8(cur.p++), t=h&0x1f, a=(h>>>5)&7;
            if(t==expectedType){
                long idx=readUnsignedLE(d,cur,a+1);
                String[] table=expectedType==0x17?strings:types;
                if(idx>=0&&idx<table.length)out.add(table[(int)idx]);
            } else skipEncodedValueAfterHead(d,cur,t,a);
        }
        return out;
    }

    private static long readUnsignedLE(LE d, Cursor cur, int width) {
        long v=0; for(int i=0;i<width;i++)v|=((long)d.u8(cur.p++))<<(8*i); return v;
    }

    private static void skipEncodedValue(LE d, Cursor cur) {
        int h=d.u8(cur.p++); skipEncodedValueAfterHead(d,cur,h&0x1f,(h>>>5)&7);
    }

    private static void skipEncodedValueAfterHead(LE d, Cursor cur, int type, int arg) {
        if(type==0x1c){int n=d.uleb(cur);for(int i=0;i<n;i++)skipEncodedValue(d,cur);return;}
        if(type==0x1d){d.uleb(cur);int n=d.uleb(cur);for(int i=0;i<n;i++){d.uleb(cur);skipEncodedValue(d,cur);}return;}
        if(type==0x1e||type==0x1f)return; // null/boolean payload lives in header
        cur.p += arg+1;
    }

    /** Decode enough encoded_value forms to preserve javac compile-time constants. */
    private static void decodeStaticValues(LE d, int off, List<Field> staticFields, String[] strings, String[] types) {
        try {
            Cursor cur=new Cursor(off); int n=d.uleb(cur);
            for (int i=0;i<n && i<staticFields.size();i++) staticFields.get(i).constantValue=decodeValue(d,cur,strings,types);
        } catch (Throwable ignored) { /* metadata enrichment must never abort ABI recovery */ }
    }
    private static Object decodeValue(LE d, Cursor cur, String[] strings, String[] types) {
        int head=d.u8(cur.p++), type=head & 0x1f, arg=(head>>>5)&7, width=arg+1;
        long v=0;
        switch(type) {
            case 0x00,0x02,0x03,0x04,0x06,0x10,0x11,0x17,0x18 -> {
                for(int i=0;i<width;i++) v |= ((long)d.u8(cur.p++)) << (8*i);
                switch(type) {
                    case 0x00: return (byte)v;
                    case 0x02: return (short)signExtend(v,width);
                    case 0x03: return (char)v;
                    case 0x04: return (int)signExtend(v,width);
                    case 0x06: return signExtend(v,width);
                    case 0x10: return Float.intBitsToFloat((int)(v << (8*(4-width))));
                    case 0x11: return Double.longBitsToDouble(v << (8*(8-width)));
                    case 0x17: return (v>=0 && v<strings.length) ? strings[(int)v] : null;
                    default: return null; // TYPE value is metadata, not ConstantValue
                }
            }
            case 0x1e -> { return null; } // VALUE_NULL
            case 0x1f -> { return arg != 0; } // VALUE_BOOLEAN encodes value in arg
            default -> { skipEncodedValuePayload(d,cur,type,arg,strings,types); return null; }
        }
    }
    private static long signExtend(long v,int width) { int bits=width*8; return (v << (64-bits)) >> (64-bits); }
    private static void skipEncodedValuePayload(LE d, Cursor cur, int type, int arg, String[] strings, String[] types) {
        // For the uncommon compound forms in static_values, recursively skip safely.
        if (type==0x1c) { int n=d.uleb(cur); for(int i=0;i<n;i++) decodeValue(d,cur,strings,types); }
        else if (type==0x1d) {
            d.uleb(cur); int n=d.uleb(cur);
            for(int i=0;i<n;i++){ d.uleb(cur); decodeValue(d,cur,strings,types); }
        } else cur.p += arg+1;
    }

    static String objectInternal(String desc) {
        return desc!=null && desc.length()>=2 && desc.charAt(0)=='L' && desc.endsWith(";") ? desc.substring(1,desc.length()-1) : desc;
    }

    private static final class Proto {
        String ret; String[] params;
        String desc(){ StringBuilder b=new StringBuilder("("); for(String p:params)b.append(p); return b.append(')').append(ret).toString(); }
    }
    private static final class FieldId { String owner,name,type; }
    private static final class MethodId { String owner,name; Proto proto; }
    private static final class Cursor { int p; Cursor(int p){this.p=p;} }

    private static final class LE {
        final byte[] b; LE(byte[] b){this.b=b;}
        int u8(int o){return b[o]&0xff;}
        int u16(int o){return u8(o)|(u8(o+1)<<8);}
        int u32(int o){return u8(o)|(u8(o+1)<<8)|(u8(o+2)<<16)|(u8(o+3)<<24);}
        int uleb(Cursor c){ int v=0,s=0,x; do{x=u8(c.p++);v|=(x&0x7f)<<s;s+=7;}while((x&0x80)!=0 && s<35);return v; }
        String stringData(int off){ Cursor c=new Cursor(off); uleb(c); int start=c.p,end=start; while(end<b.length && b[end]!=0)end++; return new String(b,start,end-start,StandardCharsets.UTF_8); }
    }
}
