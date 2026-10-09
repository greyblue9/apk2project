package apk2project.hybrid;

import java.nio.file.*;
import java.util.*;

/**
 * Dependency-free class hierarchy dump built directly from the APK DEX class_defs.
 *
 * The superclass relation defines the printable tree. Interfaces are attached as
 * annotations on each node because a class may implement multiple interfaces and
 * therefore cannot appear in a single inheritance tree through interface edges.
 */
public final class DexTreeDumper {
    private DexTreeDumper() {}

    public static void main(String[] args) throws Exception {
        Path apk=null, text=null, json=null;
        for(int i=0;i<args.length;i++) {
            switch(args[i]) {
                case "--apk" -> apk=Path.of(require(args,++i,"--apk"));
                case "--text" -> text=Path.of(require(args,++i,"--text"));
                case "--json" -> json=Path.of(require(args,++i,"--json"));
                default -> throw new IllegalArgumentException("unknown option: "+args[i]);
            }
        }
        if(apk==null) throw new IllegalArgumentException("--apk is required");
        Map<String,DexReader.Clazz> classes=DexReader.readApk(apk);
        String txt=renderText(classes);
        String js=renderJson(classes);
        if(text!=null) { mkdirParent(text); Files.writeString(text,txt); }
        if(json!=null) { mkdirParent(json); Files.writeString(json,js); }
        if(text==null && json==null) System.out.print(txt);
        System.err.printf(Locale.ROOT,"[*] DEX class tree: classes=%d roots=%d%n",classes.size(),rootNames(classes).size());
    }

    private static String require(String[] args,int i,String opt) {
        if(i>=args.length) throw new IllegalArgumentException(opt+" requires a value");
        return args[i];
    }

    private static void mkdirParent(Path p) throws Exception {
        Path parent=p.toAbsolutePath().getParent();
        if(parent!=null) Files.createDirectories(parent);
    }

    static String renderText(Map<String,DexReader.Clazz> classes) {
        Map<String,List<String>> children=children(classes);
        List<String> roots=rootNames(classes);
        StringBuilder out=new StringBuilder();
        out.append("# apk2project DEX class hierarchy\n");
        out.append("# classes=").append(classes.size()).append(" roots=").append(roots.size()).append("\n\n");
        Set<String> emitted=new HashSet<>();
        for(int r=0;r<roots.size();r++) {
            String name=roots.get(r);
            appendNode(out,classes,children,name,"",r==roots.size()-1,emitted);
        }
        // Defensive: malformed/cyclic input should still be a complete dump.
        List<String> leftover=new ArrayList<>();
        for(String n:classes.keySet()) if(!emitted.contains(n)) leftover.add(n);
        Collections.sort(leftover);
        if(!leftover.isEmpty()) {
            out.append("\n# Unreachable/cyclic class_defs\n");
            for(String n:leftover) appendNode(out,classes,children,n,"",true,emitted);
        }
        return out.toString();
    }

    private static void appendNode(StringBuilder out,Map<String,DexReader.Clazz> classes,
                                   Map<String,List<String>> children,String name,String prefix,
                                   boolean last,Set<String> emitted) {
        if(!emitted.add(name)) {
            out.append(prefix).append(last?"└── ":"├── ").append(name).append(" [cycle]\n");
            return;
        }
        DexReader.Clazz c=classes.get(name);
        out.append(prefix).append(last?"└── ":"├── ").append(name);
        if(c!=null) {
            out.append("  [").append(c.dexEntry).append(']');
            String superName=fqcn(c.superDesc);
            if(superName!=null && !classes.containsKey(superName) && !"java.lang.Object".equals(superName))
                out.append(" extends ").append(superName);
            if(!c.interfaces.isEmpty()) {
                out.append(" implements ");
                for(int i=0;i<c.interfaces.size();i++) {
                    if(i>0) out.append(", ");
                    String x=fqcn(c.interfaces.get(i));
                    out.append(x==null?c.interfaces.get(i):x);
                }
            }
            out.append("  {fields=").append(c.fields.size()).append(", methods=").append(c.methods.size()).append('}');
        }
        out.append('\n');
        List<String> kids=children.getOrDefault(name,List.of());
        String nextPrefix=prefix+(last?"    ":"│   ");
        for(int i=0;i<kids.size();i++) appendNode(out,classes,children,kids.get(i),nextPrefix,i==kids.size()-1,emitted);
    }

    static String renderJson(Map<String,DexReader.Clazz> classes) {
        Map<String,List<String>> kids=children(classes);
        List<String> names=new ArrayList<>(classes.keySet()); Collections.sort(names);
        List<String> roots=rootNames(classes);
        StringBuilder out=new StringBuilder();
        out.append("{\n  \"class_count\": ").append(classes.size()).append(",\n");
        out.append("  \"roots\": ").append(jsonArray(roots)).append(",\n  \"classes\": [\n");
        for(int ni=0;ni<names.size();ni++) {
            String n=names.get(ni); DexReader.Clazz c=classes.get(n);
            out.append("    {\"name\":").append(q(n));
            out.append(",\"descriptor\":").append(q("L"+c.internal+";"));
            out.append(",\"dex\":").append(q(c.dexEntry));
            out.append(",\"super\":").append(qNullable(fqcn(c.superDesc)));
            List<String> ifaces=new ArrayList<>(); for(String d:c.interfaces){String x=fqcn(d);ifaces.add(x==null?d:x);}
            out.append(",\"interfaces\":").append(jsonArray(ifaces));
            out.append(",\"children\":").append(jsonArray(kids.getOrDefault(n,List.of())));
            out.append(",\"field_count\":").append(c.fields.size());
            out.append(",\"method_count\":").append(c.methods.size()).append('}');
            if(ni+1<names.size()) out.append(',');
            out.append('\n');
        }
        out.append("  ]\n}\n");
        return out.toString();
    }

    private static Map<String,List<String>> children(Map<String,DexReader.Clazz> classes) {
        Map<String,List<String>> out=new HashMap<>();
        for(var e:classes.entrySet()) {
            String parent=fqcn(e.getValue().superDesc);
            if(parent!=null && classes.containsKey(parent)) out.computeIfAbsent(parent,x->new ArrayList<>()).add(e.getKey());
        }
        for(List<String> v:out.values()) Collections.sort(v);
        return out;
    }

    private static List<String> rootNames(Map<String,DexReader.Clazz> classes) {
        List<String> roots=new ArrayList<>();
        for(var e:classes.entrySet()) {
            String parent=fqcn(e.getValue().superDesc);
            if(parent==null || !classes.containsKey(parent)) roots.add(e.getKey());
        }
        Collections.sort(roots);
        return roots;
    }

    private static String fqcn(String desc) {
        if(desc==null || desc.isEmpty()) return null;
        while(desc.startsWith("[")) desc=desc.substring(1);
        if(desc.startsWith("L") && desc.endsWith(";")) return desc.substring(1,desc.length()-1).replace('/','.');
        return null;
    }

    private static String jsonArray(Collection<String> values) {
        StringBuilder b=new StringBuilder("["); boolean first=true;
        for(String v:values){if(!first)b.append(',');first=false;b.append(q(v));}
        return b.append(']').toString();
    }
    private static String qNullable(String s){return s==null?"null":q(s);}
    private static String q(String s) {
        StringBuilder b=new StringBuilder("\"");
        for(int i=0;i<s.length();i++) {
            char c=s.charAt(i);
            switch(c) {
                case '\\' -> b.append("\\\\");
                case '"' -> b.append("\\\"");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> { if(c<0x20)b.append(String.format(Locale.ROOT,"\\u%04x",(int)c)); else b.append(c); }
            }
        }
        return b.append('"').toString();
    }
}
