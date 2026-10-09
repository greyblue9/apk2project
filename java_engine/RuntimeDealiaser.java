package apk2project.hybrid;

import jdk.internal.org.objectweb.asm.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * v28 classfile boundary transformer.
 *
 * javac compiles against human/JADX-facing shadow aliases. Android runtime DEX
 * still contains raw R8/obfuscated names. Before D8, rewrite compiled classfiles
 * back onto the raw DEX ABI using a provenance TSV generated from JOBF + shadow
 * alias manifests. This handles definitions and references, not source text.
 */
public final class RuntimeDealiaser {
    static final class Maps {
        final Map<String,String> classes=new LinkedHashMap<>(); // source internal -> raw internal
        final Map<String,String> fields=new HashMap<>();        // owner#alias:srcDesc -> rawName
        final Map<String,String> methods=new HashMap<>();       // owner#alias(srcDesc) -> rawName
        final Set<String> forbiddenClasses=new LinkedHashSet<>();
        final Set<String> forbiddenFields=new LinkedHashSet<>();
        final Set<String> forbiddenMethods=new LinkedHashSet<>();
    }

    public static void main(String[] args) throws Exception {
        Path in=null,out=null,map=null,report=null;
        for(int i=0;i<args.length;i++) switch(args[i]){
            case "--in" -> in=Path.of(args[++i]);
            case "--out" -> out=Path.of(args[++i]);
            case "--map" -> map=Path.of(args[++i]);
            case "--report" -> report=Path.of(args[++i]);
            default -> throw new IllegalArgumentException("unknown option "+args[i]);
        }
        if(in==null||out==null||map==null)throw new IllegalArgumentException("requires --in --out --map");
        Maps m=load(map); Files.createDirectories(out);
        int files=0,changed=0;
        List<String> rows=new ArrayList<>(), outputClasses=new ArrayList<>();
        try(var st=Files.walk(in)){
            for(Path p:st.filter(Files::isRegularFile).toList()){
                Path rel=in.relativize(p), dst=out.resolve(rel); Files.createDirectories(dst.getParent());
                if(!p.getFileName().toString().endsWith(".class")){Files.copy(p,dst,StandardCopyOption.REPLACE_EXISTING);continue;}
                byte[] before=Files.readAllBytes(p), after=transform(before,m);
                List<String> unresolved=verifyNoAliases(after,m);
                if(!unresolved.isEmpty()) throw new IllegalStateException("unresolved runtime alias(es) after dealias: "+String.join(" | ",unresolved));
                String finalInternal=new ClassReader(after).getClassName();
                dst=out.resolve(finalInternal+".class");
                Files.createDirectories(dst.getParent());
                if(Files.exists(dst)) throw new IllegalStateException("dealias class collision: "+finalInternal);
                Files.write(dst,after); files++;
                outputClasses.add("L"+finalInternal+";");
                if(!Arrays.equals(before,after)){changed++;rows.add(rel.toString().replace(File.separatorChar,'/'));}
            }
        }
        Collections.sort(outputClasses);
        String json="{\n  \"class_files\": "+files+",\n  \"changed_class_files\": "+changed+",\n  \"changed\": "+jsonArray(rows)+",\n  \"output_classes\": "+jsonArray(outputClasses)+"\n}\n";
        if(report!=null){Files.createDirectories(report.toAbsolutePath().getParent());Files.writeString(report,json);}
        System.out.print(json);
    }

    static Maps load(Path p)throws IOException{
        Maps m=new Maps();
        for(String line:Files.readAllLines(p,StandardCharsets.UTF_8)){
            if(line.isBlank()||line.startsWith("#"))continue;
            String[] q=line.split("\t",-1);
            if(q[0].equals("C")&&q.length>=3)m.classes.put(q[1],q[2]);
            else if(q[0].equals("F")&&q.length>=6)m.fields.put(fkey(q[1],q[2],q[3]),q[4]);
            else if(q[0].equals("M")&&q.length>=6)m.methods.put(mkey(q[1],q[2],q[3]),q[4]);
        }
        // Build a raw-namespace denylist. If any of these source/JADX aliases survive
        // transformation, D8 would happily encode a runtime reference that the APK does
        // not actually provide.
        for(var e:m.classes.entrySet()) if(!e.getKey().equals(e.getValue())) m.forbiddenClasses.add(e.getKey());
        for(var e:m.fields.entrySet()){
            String k=e.getKey(); int h=k.indexOf('#'), c=k.indexOf(':',h+1); if(h<0||c<0)continue;
            String so=k.substring(0,h), alias=k.substring(h+1,c), sd=k.substring(c+1), raw=e.getValue();
            if(!alias.equals(raw))m.forbiddenFields.add(fkey(mapI(so,m),alias,mapDesc(sd,m)));
        }
        for(var e:m.methods.entrySet()){
            String k=e.getKey(); int h=k.indexOf('#'), par=k.indexOf('(',h+1); if(h<0||par<0)continue;
            String so=k.substring(0,h), alias=k.substring(h+1,par), sd=k.substring(par), raw=e.getValue();
            if(!alias.equals(raw))m.forbiddenMethods.add(mkey(mapI(so,m),alias,mapDesc(sd,m)));
        }
        return m;
    }
    static String fkey(String o,String n,String d){return o+"#"+n+":"+d;}
    static String mkey(String o,String n,String d){return o+"#"+n+d;}

    static byte[] transform(byte[] in,Maps maps){
        ClassReader cr=new ClassReader(in); ClassWriter cw=new ClassWriter(0);
        cr.accept(new DealiasClass(cw,maps),0); return cw.toByteArray();
    }

    static final class DealiasClass extends ClassVisitor {
        final Maps m; String sourceOwner;
        DealiasClass(ClassVisitor cv,Maps m){super(Opcodes.ASM8,cv);this.m=m;}
        @Override public void visit(int version,int access,String name,String sig,String superName,String[] ifaces){
            sourceOwner=name;
            super.visit(version,access,mapI(name,m),mapSig(sig,m),mapI(superName,m),mapIs(ifaces,m));
        }
        @Override public FieldVisitor visitField(int access,String name,String desc,String sig,Object value){
            String rawName=m.fields.getOrDefault(fkey(sourceOwner,name,desc),name);
            FieldVisitor fv=super.visitField(access,rawName,mapDesc(desc,m),mapSig(sig,m),mapConst(value,m));
            return fv==null?null:new DealiasField(fv,m);
        }
        @Override public MethodVisitor visitMethod(int access,String name,String desc,String sig,String[] exceptions){
            String rawName=(name.equals("<init>")||name.equals("<clinit>"))?name:m.methods.getOrDefault(mkey(sourceOwner,name,desc),name);
            MethodVisitor mv=super.visitMethod(access,rawName,mapDesc(desc,m),mapSig(sig,m),mapIs(exceptions,m));
            return mv==null?null:new DealiasMethod(mv,m);
        }
        @Override public AnnotationVisitor visitAnnotation(String desc,boolean visible){return wrap(super.visitAnnotation(mapDesc(desc,m),visible),m);}
        @Override public AnnotationVisitor visitTypeAnnotation(int typeRef,TypePath typePath,String desc,boolean visible){return wrap(super.visitTypeAnnotation(typeRef,typePath,mapDesc(desc,m),visible),m);}
        @Override public void visitNestHost(String nestHost){super.visitNestHost(mapI(nestHost,m));}
        @Override public void visitNestMember(String nestMember){super.visitNestMember(mapI(nestMember,m));}
        @Override public void visitPermittedSubclass(String permittedSubclass){super.visitPermittedSubclass(mapI(permittedSubclass,m));}
        @Override public void visitOuterClass(String owner,String name,String desc){
            String rn=name;
            if(name!=null&&desc!=null&&!name.equals("<init>")&&!name.equals("<clinit>"))rn=m.methods.getOrDefault(mkey(owner,name,desc),name);
            super.visitOuterClass(mapI(owner,m),rn,mapDesc(desc,m));
        }
        @Override public void visitInnerClass(String name,String outerName,String innerName,int access){
            String mn=mapI(name,m), mo=mapI(outerName,m), mi=innerName;
            if(mn!=null && mo!=null && mn.startsWith(mo+"$")) mi=mn.substring(mo.length()+1);
            super.visitInnerClass(mn,mo,mi,access);
        }
        @Override public RecordComponentVisitor visitRecordComponent(String name,String desc,String sig){
            RecordComponentVisitor rv=super.visitRecordComponent(name,mapDesc(desc,m),mapSig(sig,m));
            return rv==null?null:new RecordComponentVisitor(Opcodes.ASM8,rv){
                @Override public AnnotationVisitor visitAnnotation(String d,boolean v){return wrap(super.visitAnnotation(mapDesc(d,m),v),m);}
            };
        }
    }

    static final class DealiasField extends FieldVisitor{
        final Maps m; DealiasField(FieldVisitor fv,Maps m){super(Opcodes.ASM8,fv);this.m=m;}
        @Override public AnnotationVisitor visitAnnotation(String d,boolean v){return wrap(super.visitAnnotation(mapDesc(d,m),v),m);}
        @Override public AnnotationVisitor visitTypeAnnotation(int tr,TypePath tp,String d,boolean v){return wrap(super.visitTypeAnnotation(tr,tp,mapDesc(d,m),v),m);}
    }

    static final class DealiasMethod extends MethodVisitor{
        final Maps m; DealiasMethod(MethodVisitor mv,Maps m){super(Opcodes.ASM8,mv);this.m=m;}
        @Override public void visitTypeInsn(int opcode,String type){super.visitTypeInsn(opcode,mapI(type,m));}
        @Override public void visitFieldInsn(int opcode,String owner,String name,String desc){
            String rn=m.fields.getOrDefault(fkey(owner,name,desc),name);
            super.visitFieldInsn(opcode,mapI(owner,m),rn,mapDesc(desc,m));
        }
        @Override public void visitMethodInsn(int opcode,String owner,String name,String desc,boolean itf){
            String rn=(name.equals("<init>")||name.equals("<clinit>"))?name:m.methods.getOrDefault(mkey(owner,name,desc),name);
            super.visitMethodInsn(opcode,mapI(owner,m),rn,mapDesc(desc,m),itf);
        }
        @Override public void visitInvokeDynamicInsn(String name,String desc,Handle bsm,Object... args){
            // LambdaMetafactory encodes the functional-interface/SAM method name in
            // invokedynamic.name.  If that interface was JADX-renamed, mapping only
            // the descriptor would make D8 synthesize an implementation of the alias
            // rather than the real raw DEX method.  Bootstrap arg #0 is normally the
            // erased SAM MethodType, which gives us the exact alias descriptor.
            String rawIndyName=mapInvokeDynamicName(name,desc,args,m);
            Object[] na=new Object[args.length];for(int i=0;i<args.length;i++)na[i]=mapConst(args[i],m);
            super.visitInvokeDynamicInsn(rawIndyName,mapDesc(desc,m),mapHandle(bsm,m),na);
        }
        @Override public void visitLdcInsn(Object value){super.visitLdcInsn(mapConst(value,m));}
        @Override public void visitMultiANewArrayInsn(String desc,int dims){super.visitMultiANewArrayInsn(mapDesc(desc,m),dims);}
        @Override public void visitTryCatchBlock(Label s,Label e,Label h,String type){super.visitTryCatchBlock(s,e,h,mapI(type,m));}
        @Override public void visitLocalVariable(String name,String desc,String sig,Label s,Label e,int idx){super.visitLocalVariable(name,mapDesc(desc,m),mapSig(sig,m),s,e,idx);}
        @Override public AnnotationVisitor visitAnnotation(String d,boolean v){return wrap(super.visitAnnotation(mapDesc(d,m),v),m);}
        @Override public AnnotationVisitor visitTypeAnnotation(int tr,TypePath tp,String d,boolean v){return wrap(super.visitTypeAnnotation(tr,tp,mapDesc(d,m),v),m);}
        @Override public AnnotationVisitor visitParameterAnnotation(int p,String d,boolean v){return wrap(super.visitParameterAnnotation(p,mapDesc(d,m),v),m);}
        @Override public AnnotationVisitor visitAnnotationDefault(){return wrap(super.visitAnnotationDefault(),m);}
        @Override public AnnotationVisitor visitInsnAnnotation(int tr,TypePath tp,String d,boolean v){return wrap(super.visitInsnAnnotation(tr,tp,mapDesc(d,m),v),m);}
        @Override public AnnotationVisitor visitTryCatchAnnotation(int tr,TypePath tp,String d,boolean v){return wrap(super.visitTryCatchAnnotation(tr,tp,mapDesc(d,m),v),m);}
        @Override public AnnotationVisitor visitLocalVariableAnnotation(int tr,TypePath tp,Label[] start,Label[] end,int[] idx,String d,boolean v){return wrap(super.visitLocalVariableAnnotation(tr,tp,start,end,idx,mapDesc(d,m),v),m);}
        @Override public void visitFrame(int type,int nLocal,Object[] local,int nStack,Object[] stack){
            super.visitFrame(type,nLocal,mapFrame(local,nLocal,m),nStack,mapFrame(stack,nStack,m));
        }
    }

    static AnnotationVisitor wrap(AnnotationVisitor av,Maps m){
        if(av==null)return null;
        return new AnnotationVisitor(Opcodes.ASM8,av){
            @Override public void visit(String n,Object v){super.visit(n,mapConst(v,m));}
            @Override public void visitEnum(String n,String d,String v){
                String owner=null;
                if(d!=null && d.startsWith("L") && d.endsWith(";")) owner=d.substring(1,d.length()-1);
                String rawValue=v;
                if(owner!=null) rawValue=m.fields.getOrDefault(fkey(owner,v,d),v);
                super.visitEnum(n,mapDesc(d,m),rawValue);
            }
            @Override public AnnotationVisitor visitAnnotation(String n,String d){return wrap(super.visitAnnotation(n,mapDesc(d,m)),m);}
            @Override public AnnotationVisitor visitArray(String n){return wrap(super.visitArray(n),m);}
        };
    }

    static Object[] mapFrame(Object[] x,int n,Maps m){if(x==null)return null;Object[] y=x.clone();for(int i=0;i<n&&i<y.length;i++)if(y[i] instanceof String s)y[i]=mapI(s,m);return y;}
    static String[] mapIs(String[] a,Maps m){if(a==null)return null;String[] b=a.clone();for(int i=0;i<b.length;i++)b[i]=mapI(b[i],m);return b;}
    static String mapI(String s,Maps m){
        if(s==null)return null; String x=m.classes.get(s); if(x!=null)return x;
        // javac-created nested classes may not appear in the source index. Map them
        // by the longest known enclosing source owner.
        int d=s.lastIndexOf('$');
        while(d>0){String base=s.substring(0,d),raw=m.classes.get(base);if(raw!=null)return raw+s.substring(d);d=s.lastIndexOf('$',d-1);}return s;
    }
    static String mapDesc(String d,Maps m){
        if(d==null)return null;StringBuilder o=new StringBuilder();
        for(int i=0;i<d.length();){char c=d.charAt(i);if(c=='L'){int e=d.indexOf(';',i);if(e<0){o.append(d.substring(i));break;}o.append('L').append(mapI(d.substring(i+1,e),m)).append(';');i=e+1;}else{o.append(c);i++;}}return o.toString();
    }
    // Generic signatures contain internal names after L. Exact class replacement is
    // sufficient for our alias map; descriptors and executable references are the
    // runtime-critical surface.
    static String mapSig(String s,Maps m){
        if(s==null)return null;String out=s;
        List<Map.Entry<String,String>> es=new ArrayList<>(m.classes.entrySet());es.sort((a,b)->Integer.compare(b.getKey().length(),a.getKey().length()));
        for(var e:es)out=out.replace("L"+e.getKey(),"L"+e.getValue());return out;
    }
    static String mapInvokeDynamicName(String name,String indyDesc,Object[] args,Maps m){
        try{
            Type ret=Type.getMethodType(indyDesc).getReturnType();
            if(ret.getSort()!=Type.OBJECT)return name;
            String owner=ret.getInternalName(), samDesc=null;
            if(args!=null)for(Object a:args)if(a instanceof Type t && t.getSort()==Type.METHOD){samDesc=t.getDescriptor();break;}
            if(samDesc==null)return name;
            return m.methods.getOrDefault(mkey(owner,name,samDesc),name);
        }catch(Throwable ignored){return name;}
    }

    static Handle mapHandle(Handle h,Maps m){
        if(h==null)return null;String owner=h.getOwner(),name=h.getName(),desc=h.getDesc(),rn=name;
        int tag=h.getTag();
        if(tag>=Opcodes.H_GETFIELD&&tag<=Opcodes.H_PUTSTATIC)rn=m.fields.getOrDefault(fkey(owner,name,desc),name);
        else if(!name.equals("<init>"))rn=m.methods.getOrDefault(mkey(owner,name,desc),name);
        return new Handle(tag,mapI(owner,m),rn,mapDesc(desc,m),h.isInterface());
    }
    static Object mapConst(Object v,Maps m){
        if(v instanceof Type t){String d=t.getDescriptor();return Type.getType(mapDesc(d,m));}
        if(v instanceof Handle h)return mapHandle(h,m);
        if(v instanceof ConstantDynamic c){
            Object[] args=new Object[c.getBootstrapMethodArgumentCount()];for(int i=0;i<args.length;i++)args[i]=mapConst(c.getBootstrapMethodArgument(i),m);
            return new ConstantDynamic(c.getName(),mapDesc(c.getDescriptor(),m),mapHandle(c.getBootstrapMethod(),m),args);
        }
        return v;
    }
    static List<String> verifyNoAliases(byte[] bytes,Maps m){
        LinkedHashSet<String> bad=new LinkedHashSet<>();
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM8){
            String owner;
            void ci(String x,String where){if(x!=null&&m.forbiddenClasses.contains(x))bad.add(where+": class alias "+x);}
            void desc(String d,String where){if(d==null)return;for(int i=0;i<d.length();){if(d.charAt(i)!='L'){i++;continue;}int e=d.indexOf(';',i);if(e<0)break;ci(d.substring(i+1,e),where);i=e+1;}}
            void handle(Handle h,String where){if(h==null)return;ci(h.getOwner(),where);desc(h.getDesc(),where);if(h.getTag()>=Opcodes.H_GETFIELD&&h.getTag()<=Opcodes.H_PUTSTATIC){if(m.forbiddenFields.contains(fkey(h.getOwner(),h.getName(),h.getDesc())))bad.add(where+": field alias "+h.getOwner()+"."+h.getName());}else if(m.forbiddenMethods.contains(mkey(h.getOwner(),h.getName(),h.getDesc())))bad.add(where+": method alias "+h.getOwner()+"."+h.getName());}
            void constant(Object v,String where){if(v instanceof Type t)desc(t.getDescriptor(),where);else if(v instanceof Handle h)handle(h,where);else if(v instanceof ConstantDynamic c){desc(c.getDescriptor(),where);handle(c.getBootstrapMethod(),where);for(int i=0;i<c.getBootstrapMethodArgumentCount();i++)constant(c.getBootstrapMethodArgument(i),where);}}
            @Override public void visit(int v,int a,String n,String sig,String sup,String[] ints){owner=n;ci(n,"class");ci(sup,"super");if(ints!=null)for(String x:ints)ci(x,"interface");}
            @Override public FieldVisitor visitField(int a,String n,String d,String sig,Object value){desc(d,"field "+n);if(m.forbiddenFields.contains(fkey(owner,n,d)))bad.add("field definition alias "+owner+"."+n+":"+d);constant(value,"field "+n);return null;}
            @Override public MethodVisitor visitMethod(int a,String n,String d,String sig,String[] ex){desc(d,"method "+n);if(ex!=null)for(String x:ex)ci(x,"throws");if(m.forbiddenMethods.contains(mkey(owner,n,d)))bad.add("method definition alias "+owner+"."+n+d);return new MethodVisitor(Opcodes.ASM8){
                @Override public void visitTypeInsn(int op,String t){ci(t,"type insn");}
                @Override public void visitFieldInsn(int op,String o,String n,String d){ci(o,"field owner");desc(d,"field desc");if(m.forbiddenFields.contains(fkey(o,n,d)))bad.add("field instruction alias "+o+"."+n+":"+d);}
                @Override public void visitMethodInsn(int op,String o,String n,String d,boolean itf){ci(o,"method owner");desc(d,"method desc");if(m.forbiddenMethods.contains(mkey(o,n,d)))bad.add("method instruction alias "+o+"."+n+d);}
                @Override public void visitInvokeDynamicInsn(String n,String d,Handle b,Object... args){desc(d,"indy desc");handle(b,"indy bsm");for(Object x:args)constant(x,"indy arg");}
                @Override public void visitLdcInsn(Object v){constant(v,"ldc");}
                @Override public void visitMultiANewArrayInsn(String d,int dims){desc(d,"multianewarray");}
                @Override public void visitTryCatchBlock(Label s,Label e,Label h,String t){ci(t,"catch");}
                @Override public void visitLocalVariable(String n,String d,String sig,Label s,Label e,int i){desc(d,"local "+n);}
            };}
        },ClassReader.SKIP_DEBUG);
        return new ArrayList<>(bad);
    }

    static String jsonArray(List<String> a){StringBuilder b=new StringBuilder("[");boolean f=true;for(String s:a){if(!f)b.append(',');f=false;b.append('"').append(s.replace("\\","\\\\").replace("\"","\\\"")).append('"');}return b.append(']').toString();}
}
