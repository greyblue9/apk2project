package apk2project.hybrid;

import jdk.internal.org.objectweb.asm.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

/**
 * v28 runtime-facing compile classpath.
 *
 * javac sees a source/JADX-facing shadow with aliases.  After RuntimeDealiaser
 * rewrites the compiled program classes back to their raw APK names, D8 must see
 * the opposite view: raw class/member names exactly as they exist in DEX.  This
 * emitter creates that compile-only facade directly from the APK ABI and excludes
 * classes that are about to be supplied as D8 program inputs.
 */
public final class RawAbiEmitter {
    public static void main(String[] args) throws Exception {
        Path apk=null,out=null,exclude=null,report=null;
        int api=35;
        for(int i=0;i<args.length;i++) switch(args[i]) {
            case "--apk" -> apk=Path.of(args[++i]);
            case "--out" -> out=Path.of(args[++i]);
            case "--exclude-list" -> exclude=Path.of(args[++i]);
            case "--report" -> report=Path.of(args[++i]);
            case "--api" -> api=Integer.parseInt(args[++i]);
            default -> throw new IllegalArgumentException("unknown option "+args[i]);
        }
        if(apk==null||out==null) throw new IllegalArgumentException("requires --apk --out");
        LinkedHashSet<String> excluded=new LinkedHashSet<>();
        if(exclude!=null&&Files.isRegularFile(exclude)) for(String s:Files.readAllLines(exclude,StandardCharsets.UTF_8)) {
            s=s.trim(); if(!s.isEmpty()&&!s.startsWith("#")) excluded.add(toFqcn(s));
        }

        HybridCompiler.Opts o=new HybridCompiler.Opts();
        o.apk=apk.toAbsolutePath().normalize(); o.permissive=true;
        Map<String,HybridCompiler.SmaliClass> dex=HybridCompiler.scanDexApk(o.apk);
        HybridCompiler.SourceIndex identity=new HybridCompiler.SourceIndex();

        Map<String,List<String>> children=new LinkedHashMap<>();
        for(HybridCompiler.SmaliClass c:dex.values()) {
            if(excluded.contains(c.rawFqcn)) continue;
            int d=c.rawInternal.lastIndexOf('$');
            if(d>0) children.computeIfAbsent(c.rawInternal.substring(0,d),k->new ArrayList<>()).add(c.rawInternal);
        }

        Files.createDirectories(out.toAbsolutePath().getParent());
        int emitted=0;
        try(JarOutputStream jar=new JarOutputStream(Files.newOutputStream(out))) {
            JarEntry meta=new JarEntry("META-INF/apk2project-raw-abi.tsv");
            jar.putNextEntry(meta);
            StringBuilder mb=new StringBuilder("#raw_owner\n");
            for(HybridCompiler.SmaliClass c:dex.values()) if(!excluded.contains(c.rawFqcn)) mb.append(c.rawFqcn).append('\n');
            jar.write(mb.toString().getBytes(StandardCharsets.UTF_8)); jar.closeEntry();
            for(HybridCompiler.SmaliClass c:dex.values()) {
                if(excluded.contains(c.rawFqcn)) continue;
                byte[] b=HybridCompiler.emitStubClass(c,c.rawInternal,null,identity,o,children.getOrDefault(c.rawInternal,List.of()));
                JarEntry je=new JarEntry(c.rawInternal+".class"); jar.putNextEntry(je); jar.write(b); jar.closeEntry(); emitted++;
            }
        }
        String json="{\n  \"apk_classes\": "+dex.size()+",\n  \"excluded_classes\": "+excluded.size()+",\n  \"emitted_classes\": "+emitted+",\n  \"output\": "+q(out.toString())+"\n}\n";
        if(report!=null){Files.createDirectories(report.toAbsolutePath().getParent());Files.writeString(report,json);}
        System.out.print(json);
    }

    static String toFqcn(String s){
        if(s.startsWith("L")&&s.endsWith(";"))s=s.substring(1,s.length()-1);
        return s.replace('/','.');
    }
    static String q(String s){return "\""+s.replace("\\","\\\\").replace("\"","\\\"")+"\"";}
}
