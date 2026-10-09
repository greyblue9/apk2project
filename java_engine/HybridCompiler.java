package apk2project.hybrid;

import com.sun.source.tree.*;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import com.sun.source.util.SourcePositions;
import com.sun.tools.javac.api.JavacTaskImpl;
import com.sun.tools.javac.api.ClientCodeWrapper.DiagnosticSourceUnwrapper;
import com.sun.tools.javac.api.JavacTool;
import com.sun.tools.javac.code.Symbol;
import com.sun.tools.javac.code.Type;
import com.sun.tools.javac.code.Types;
import com.sun.tools.javac.file.JavacFileManager;
import com.sun.tools.javac.tree.JCTree;
import com.sun.tools.javac.tree.TreeInfo;
import com.sun.tools.javac.util.Context;
import com.sun.tools.javac.util.JCDiagnostic;

import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassVisitor;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.FieldVisitor;
import jdk.internal.org.objectweb.asm.MethodVisitor;
import jdk.internal.org.objectweb.asm.Opcodes;

import javax.lang.model.element.Element;
import javax.tools.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * apk2project v27.2 hybrid compiler/linker + decompiler-normalization engine.
 *
 * Deliberately uses javac internals (enabled with --add-exports) for two jobs:
 *   1) parse/attribute source using javac's own symbols/types instead of regex inference;
 *   2) build a compile-only ABI shadow JAR from the APK's smali/DEX surface so javac
 *      never has to compile most decompiled library/obfuscated/shaded source.
 *
 * The shadow JAR is NOT executable application code. Method bodies are poison stubs.
 * It exists solely to give javac class/member/type symbols matching the APK's transformed
 * ABI while app-owned Java remains editable source.
 */
public final class HybridCompiler {
    static final Pattern JADX_CLASS_ALIAS = Pattern.compile("^(?:[A-Za-z_$][\\w$]*?)?C\\d+([A-Za-z_$][\\w$]*)$");
    static final Pattern JADX_PKG_ALIAS = Pattern.compile("^p\\d+(.+)$");
    static final Pattern JADX_METHOD_ALIAS = Pattern.compile("^m(?:o)?\\d+(.+)$");
    static final Pattern JADX_FIELD_ALIAS = Pattern.compile("^f\\d+(.+)$");
    static final Pattern METHOD_ALIAS_TOKEN = Pattern.compile("\\bm\\d+[A-Za-z_$][\\w$]*\\b");
    static final Pattern FIELD_ALIAS_TOKEN = Pattern.compile("\\bf\\d+[A-Za-z_$][\\w$]*\\b");

    static final class Opts {
        String command = "shadow";
        Path javaRoot;
        Path original;
        Path apk;
        Path outJar;
        Path ownership;
        Path sourceList;
        Path classpathFile;
        Path jadxMap;
        Path shadowJar;
        Path report;
        List<String> appPrefixes = new ArrayList<>();
        List<String> rootClasses = new ArrayList<>();
        List<String> forceBinaryRegexes = new ArrayList<>();
        List<Pattern> forceBinaryPatterns = new ArrayList<>();
        List<Path> extraSourceRoots = new ArrayList<>();
        boolean permissive = true;
        boolean includeUnmappedDex = true;
        int aliasFanoutCap = 32;
    }

    static final class SourceType {
        String fqcn;
        String rawFqcn;
        Path file;
        boolean appOwned;
        boolean topLevel;
        final Map<String, Set<String>> methodAliasesByRaw = new LinkedHashMap<>();
        final Map<String, Map<Integer, Set<String>>> methodAliasesByRawArity = new LinkedHashMap<>();
        final Map<String, Set<String>> fieldAliasesByRaw = new LinkedHashMap<>();
        final Set<String> imports = new LinkedHashSet<>();
        String packageName = "";
    }

    static final class MemberUse {
        String ownerTypeText;
        String alias;
        boolean method;
        int arity = -1;
        String packageName;
        String enclosingType;
        final Set<String> imports = new LinkedHashSet<>();
    }

    static final class JadxMap {
        final Map<String, String> packages = new LinkedHashMap<>();
        final Map<String, String> classes = new LinkedHashMap<>();
        final Map<String, String> fields = new LinkedHashMap<>();
        final Map<String, String> methods = new LinkedHashMap<>();
        int ignored;

        boolean isEmpty() { return packages.isEmpty() && classes.isEmpty() && fields.isEmpty() && methods.isEmpty(); }

        String aliasPackage(String rawPkg) {
            if (rawPkg == null || rawPkg.isEmpty()) return rawPkg == null ? "" : rawPkg;
            String direct = packages.get(rawPkg);
            if (direct != null) {
                // JADX stores a full alias when a parent package is also aliased, but
                // stores only the renamed leaf when there is no aliased parent.
                if (direct.indexOf('.') >= 0) return direct;
                int dot = rawPkg.lastIndexOf('.');
                if (dot < 0) return direct;
                String parent = aliasPackage(rawPkg.substring(0, dot));
                return parent.isEmpty() ? direct : parent + "." + direct;
            }
            int dot = rawPkg.lastIndexOf('.');
            if (dot < 0) return rawPkg;
            String parentRaw = rawPkg.substring(0, dot);
            String parentAlias = aliasPackage(parentRaw);
            return (parentAlias.isEmpty() ? "" : parentAlias + ".") + rawPkg.substring(dot + 1);
        }

        String sourceClassName(String rawFqcn) {
            int dot = rawFqcn.lastIndexOf('.');
            String rawPkg = dot < 0 ? "" : rawFqcn.substring(0, dot);
            String rawSimple = dot < 0 ? rawFqcn : rawFqcn.substring(dot + 1);

            /*
             * JADX JOBF writes nested-class aliases as the renamed *inner leaf*.
             * For example:
             *
             *   c androidx.lifecycle.e0   = FragmentC0184e0
             *   c androidx.lifecycle.e0$a = a
             *
             * The second record does NOT mean the binary class should become the
             * package-level type androidx.lifecycle.a.  Earlier v27 builds did exactly
             * that, allowing unrelated nested classes such as a0$a and e0$a to collide
             * on one shadow owner and poison the entire validation gate.
             *
             * Preserve binary nesting: recursively map the outer class, then append
             * the JOBF leaf after '$'.  This is also correct for multi-level nested
             * names because the recursion peels one '$' segment at a time.
             */
            int dollar = rawFqcn.lastIndexOf('$');
            if (dollar > dot) {
                String rawOuter = rawFqcn.substring(0, dollar);
                String rawInnerLeaf = rawFqcn.substring(dollar + 1);
                String mappedOuter = sourceClassName(rawOuter);
                String alias = classes.getOrDefault(rawFqcn, rawInnerLeaf);
                // Be defensive if a future JOBF version emits a qualified/nested alias.
                int aliasDollar = alias.lastIndexOf('$');
                int aliasDot = alias.lastIndexOf('.');
                int cut = Math.max(aliasDollar, aliasDot);
                String aliasLeaf = cut >= 0 ? alias.substring(cut + 1) : alias;
                return mappedOuter + "$" + aliasLeaf;
            }

            String aliasSimple = classes.getOrDefault(rawFqcn, rawSimple);
            String aliasPkg = aliasPackage(rawPkg);
            return aliasPkg.isEmpty() ? aliasSimple : aliasPkg + "." + aliasSimple;
        }
    }

    static final class SourceIndex {
        final Map<String, SourceType> bySource = new LinkedHashMap<>();
        final Map<String, String> rawToSource = new LinkedHashMap<>();
        final Map<Path, List<SourceType>> byFile = new LinkedHashMap<>();
        final Map<String, LinkedHashSet<String>> globalMethodAliases = new LinkedHashMap<>();
        final Map<String, LinkedHashSet<String>> globalFieldAliases = new LinkedHashMap<>();
        final LinkedHashSet<String> observedTypeNames = new LinkedHashSet<>();
        final List<MemberUse> memberUses = new ArrayList<>();
        final Map<String, Set<String>> useFieldAliasesByRawOwner = new LinkedHashMap<>();
        final Map<String, Set<String>> useMethodAliasesByRawMember = new LinkedHashMap<>();
        final List<String> parseDiagnostics = new ArrayList<>();
    }

    static final class SmaliField {
        String name;
        String desc;
        String signature;
        Object constantValue;
        Set<String> flags = new LinkedHashSet<>();
    }

    static final class SmaliMethod {
        String name;
        String desc;
        String signature;
        List<String> exceptionDescs = new ArrayList<>();
        Set<String> flags = new LinkedHashSet<>();
    }

    static final class SmaliClass {
        String rawFqcn;
        String rawInternal;
        String superDesc = "Ljava/lang/Object;";
        String signature;
        List<String> interfaceDescs = new ArrayList<>();
        Set<String> flags = new LinkedHashSet<>();
        List<SmaliField> fields = new ArrayList<>();
        List<SmaliMethod> methods = new ArrayList<>();
        Path path;
    }

    static final class EngineDiagnostic implements DiagnosticListener<JavaFileObject> {
        final List<Diagnostic<? extends JavaFileObject>> all = new ArrayList<>();
        @Override public void report(Diagnostic<? extends JavaFileObject> d) { all.add(d); }
    }

    public static void main(String[] args) throws Exception {
        Opts o = parseArgs(args);
        if ((o.command.equals("shadow") || o.command.equals("analyze") || o.command.equals("normalize")) && o.javaRoot == null) die("--java-root is required");
        switch (o.command) {
            case "shadow" -> runShadow(o);
            case "analyze" -> runAnalyze(o);
            case "normalize" -> runNormalize(o);
            case "validate" -> runValidate(o);
            default -> die("unknown command: " + o.command);
        }
    }

    static Opts parseArgs(String[] args) {
        Opts o = new Opts();
        int i = 0;
        if (args.length > 0 && !args[0].startsWith("--")) { o.command = args[0]; i = 1; }
        for (; i < args.length; i++) {
            String a = args[i];
            String v = (i + 1 < args.length) ? args[i + 1] : null;
            switch (a) {
                case "--java-root" -> { o.javaRoot = Path.of(require(a, v)); i++; }
                case "--original" -> { o.original = Path.of(require(a, v)); i++; }
                case "--apk" -> { o.apk = Path.of(require(a, v)); i++; }
                case "--out" -> { o.outJar = Path.of(require(a, v)); i++; }
                case "--ownership" -> { o.ownership = Path.of(require(a, v)); i++; }
                case "--source-list" -> { o.sourceList = Path.of(require(a, v)); i++; }
                case "--classpath-file" -> { o.classpathFile = Path.of(require(a, v)); i++; }
                case "--jadx-map" -> { o.jadxMap = Path.of(require(a, v)); i++; }
                case "--shadow-jar" -> { o.shadowJar = Path.of(require(a, v)); i++; }
                case "--report" -> { o.report = Path.of(require(a, v)); i++; }
                case "--app-prefix" -> { o.appPrefixes.add(require(a, v)); i++; }
                case "--root-class" -> { o.rootClasses.add(require(a, v)); i++; }
                case "--force-binary-regex" -> { o.forceBinaryRegexes.add(require(a, v)); i++; }
                case "--extra-source-root" -> { o.extraSourceRoots.add(Path.of(require(a, v))); i++; }
                case "--strict-abi" -> o.permissive = false;
                case "--no-unmapped-dex" -> o.includeUnmappedDex = false;
                case "--alias-fanout-cap" -> { o.aliasFanoutCap = Integer.parseInt(require(a, v)); i++; }
                default -> die("unknown argument: " + a);
            }
        }
        o.javaRoot = o.javaRoot == null ? null : o.javaRoot.toAbsolutePath().normalize();
        if (o.original != null) o.original = o.original.toAbsolutePath().normalize();
        if (o.apk != null) o.apk = o.apk.toAbsolutePath().normalize();
        if (o.outJar != null) o.outJar = o.outJar.toAbsolutePath().normalize();
        if (o.shadowJar != null) o.shadowJar = o.shadowJar.toAbsolutePath().normalize();
        if (o.jadxMap != null) o.jadxMap = o.jadxMap.toAbsolutePath().normalize();
        if (o.report != null) o.report = o.report.toAbsolutePath().normalize();
        if (o.ownership != null) o.ownership = o.ownership.toAbsolutePath().normalize();
        if (o.sourceList != null) o.sourceList = o.sourceList.toAbsolutePath().normalize();
        for (int j = 0; j < o.extraSourceRoots.size(); j++)
            o.extraSourceRoots.set(j, o.extraSourceRoots.get(j).toAbsolutePath().normalize());
        for (String rx : o.forceBinaryRegexes) o.forceBinaryPatterns.add(Pattern.compile(rx));
        return o;
    }

    static String require(String arg, String v) { if (v == null) die(arg + " requires a value"); return v; }
    static void die(String s) { throw new IllegalArgumentException(s); }
    static void log(String s) { System.err.println("[JAVA-HYBRID] " + s); }

    // ---------------------------------------------------------------- exact JADX auto-deobfuscation mapping (JOBF)

    /**
     * Read JADX's own auto-generated rename map.  This is stronger evidence than
     * reverse-engineering names such as C0123x/m456a/f789b because field/method
     * keys include the exact declaring class and JVM descriptor.
     *
     * JOBF records are intentionally simple (JADX DeobfPresets):
     *   p raw.package = alias.package-or-leaf
     *   c raw.package.a = C0123a
     *   f raw.package.a.b:I = f0001b
     *   m raw.package.a.c(Ljava/lang/String;)V = m0002c
     */
    static JadxMap loadJadxMap(Path path) {
        JadxMap out = new JadxMap();
        if (path == null || !Files.isRegularFile(path)) return out;
        try {
            for (String rawLine : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                String line = rawLine.trim();
                if (line.isEmpty() || line.startsWith("#") || line.length() < 4) continue;
                char kind = line.charAt(0);
                if (line.charAt(1) != ' ') { out.ignored++; continue; }
                int eq = line.indexOf('=', 2);
                if (eq < 0) { out.ignored++; continue; }
                String key = line.substring(2, eq).trim();
                String alias = line.substring(eq + 1).trim();
                if (key.isEmpty() || alias.isEmpty()) { out.ignored++; continue; }
                switch (kind) {
                    case 'p' -> out.packages.put(key, alias);
                    case 'c' -> out.classes.put(key, alias);
                    case 'f' -> out.fields.put(key, alias);
                    case 'm' -> out.methods.put(key, alias);
                    default -> out.ignored++;
                }
            }
            log("JADX JOBF exact map: packages=" + out.packages.size() + ", classes=" + out.classes.size()
                    + ", fields=" + out.fields.size() + ", methods=" + out.methods.size()
                    + (out.ignored == 0 ? "" : ", ignored=" + out.ignored));
        } catch (Exception e) {
            log("JADX JOBF map ignored: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return new JadxMap();
        }
        return out;
    }

    // ---------------------------------------------------------------- source indexing with javac parser

    static SourceIndex scanSources(Opts o) throws IOException {
        SourceIndex index = new SourceIndex();
        List<Path> files = new ArrayList<>();
        List<Path> scanRoots = new ArrayList<>();
        scanRoots.add(o.javaRoot);
        scanRoots.addAll(o.extraSourceRoots);
        LinkedHashSet<Path> unique = new LinkedHashSet<>();
        for (Path root : scanRoots) {
            if (root == null || !Files.isDirectory(root)) continue;
            try (var st = Files.walk(root)) {
                st.filter(p -> p.toString().endsWith(".java"))
                  .map(p -> p.toAbsolutePath().normalize()).sorted().forEach(unique::add);
            }
        }
        files.addAll(unique);
        if (files.isEmpty()) return index;

        final int batchSize = 500;
        for (int from = 0; from < files.size(); from += batchSize) {
            List<Path> batch = files.subList(from, Math.min(files.size(), from + batchSize));
            JavacTool tool = JavacTool.create();
            Context context = new Context();
            EngineDiagnostic dl = new EngineDiagnostic();
            JavacFileManager fm = tool.getStandardFileManager(dl, Locale.ROOT, StandardCharsets.UTF_8);
            Iterable<? extends JavaFileObject> fos = fm.getJavaFileObjectsFromPaths(batch);
            List<String> opts = List.of("-proc:none", "-Xlint:none", "-XDshould-stop.at=FLOW");
            JavacTaskImpl task = (JavacTaskImpl) tool.getTask(null, fm, dl, opts, null, fos, context);
            Iterable<? extends CompilationUnitTree> units;
            try { units = task.parse(); }
            catch (Throwable t) { fm.close(); throw new IOException("javac parser failed: " + t, t); }
            for (CompilationUnitTree unit : units) indexCompilationUnit(unit, index, o);
            for (Diagnostic<? extends JavaFileObject> d : dl.all) {
                index.parseDiagnostics.add(d.getKind() + " " + d.getCode() + " " + d.getMessage(Locale.ROOT));
            }
            fm.close();
            if (files.size() > batchSize) log("source-index batch " + Math.min(files.size(), from + batch.size()) + "/" + files.size());
        }

        // v27 deliberately does NOT fan aliases out globally by raw suffix.  In a
        // heavily obfuscated APK, hundreds of unrelated classes have raw members named
        // a/b/c/A/B/t0/etc.  Treating every observed `f123B` as an alias for every raw
        // field `B` inflated individual shadow classes from tens of members to thousands.
        // Owner-local declaration aliases remain authoritative; missing aliases are handled
        // by the targeted shadow linker rather than global suffix guessing.

        return index;
    }

    static void indexCompilationUnit(CompilationUnitTree unit, SourceIndex index, Opts o) {
        Path path = Path.of(unit.getSourceFile().toUri()).toAbsolutePath().normalize();
        String pkg = unit.getPackageName() == null ? "" : unit.getPackageName().toString();
        Set<String> imports = unit.getImports().stream().map(x -> x.getQualifiedIdentifier().toString()).collect(Collectors.toCollection(LinkedHashSet::new));
        for (ImportTree it : unit.getImports()) {
            if (it.isStatic()) continue;
            String q = it.getQualifiedIdentifier().toString();
            if (q.endsWith(".*")) continue;
            index.observedTypeNames.add(q);
            index.rawToSource.putIfAbsent(sourceToRawFqcn(q), q);
        }
        Deque<String> owners = new ArrayDeque<>();
        Deque<Map<String,String>> vars = new ArrayDeque<>();
        vars.push(new LinkedHashMap<>());
        new TreePathScanner<Void, Void>() {
            String lookupVar(String n) { for (Map<String,String> m : vars) if (m.containsKey(n)) return m.get(n); return null; }
            String expressionTypeHint(ExpressionTree e) {
                if (e instanceof ParenthesizedTree pt) return expressionTypeHint(pt.getExpression());
                if (e instanceof TypeCastTree ct) return ct.getType().toString();
                if (e instanceof NewClassTree nc) return nc.getIdentifier().toString();
                if (e instanceof IdentifierTree id) {
                    String n=id.getName().toString();
                    if (n.equals("this") || n.equals("super")) return owners.peek();
                    String v=lookupVar(n); return v!=null ? v : n; // static Type.member is the common fallback
                }
                return null;
            }
            void recordUse(MemberSelectTree node, boolean method, int arity) {
                String alias=node.getIdentifier().toString();
                if (method ? !JADX_METHOD_ALIAS.matcher(alias).matches() : !JADX_FIELD_ALIAS.matcher(alias).matches()) return;
                String hint=expressionTypeHint(node.getExpression()); if (hint==null) return;
                MemberUse u=new MemberUse(); u.ownerTypeText=hint; u.alias=alias; u.method=method; u.arity=arity;
                u.packageName=pkg; u.enclosingType=owners.peek(); u.imports.addAll(imports); index.memberUses.add(u);
            }
            @Override public Void visitClass(ClassTree node, Void p) {
                String simple = node.getSimpleName().toString();
                if (simple.isEmpty()) return super.visitClass(node, p);
                boolean top = owners.isEmpty();
                String fq = top ? (pkg.isEmpty() ? simple : pkg + "." + simple) : owners.peek() + "$" + simple;
                SourceType st = new SourceType(); st.fqcn=fq; st.rawFqcn=sourceToRawFqcn(fq); st.file=path;
                st.appOwned=isAppOwned(fq,o); st.topLevel=top; st.packageName=pkg; st.imports.addAll(imports);
                index.bySource.put(fq,st); index.observedTypeNames.add(fq); index.rawToSource.putIfAbsent(st.rawFqcn,fq); index.byFile.computeIfAbsent(path,k->new ArrayList<>()).add(st);
                owners.push(fq); Void r=super.visitClass(node,p); owners.pop(); return r;
            }
            @Override public Void visitVariable(VariableTree node, Void p) {
                if (!vars.isEmpty() && node.getType()!=null) vars.peek().put(node.getName().toString(), node.getType().toString());
                if (!owners.isEmpty()) {
                    Tree parent = getCurrentPath()!=null && getCurrentPath().getParentPath()!=null ? getCurrentPath().getParentPath().getLeaf() : null;
                    if (parent instanceof ClassTree) {
                        SourceType st=index.bySource.get(owners.peek()); String alias=node.getName().toString(); String raw=memberToRaw(alias,false);
                        st.fieldAliasesByRaw.computeIfAbsent(raw,k->new LinkedHashSet<>()).add(alias);
                    }
                }
                return super.visitVariable(node,p);
            }
            @Override public Void visitMethod(MethodTree node, Void p) {
                if (!owners.isEmpty()) {
                    SourceType st=index.bySource.get(owners.peek()); String alias=node.getName().toString();
                    if (!alias.equals("<init>")) {
                        String raw=memberToRaw(alias,true); int arity=node.getParameters().size();
                        st.methodAliasesByRaw.computeIfAbsent(raw,k->new LinkedHashSet<>()).add(alias);
                        st.methodAliasesByRawArity.computeIfAbsent(raw,k->new LinkedHashMap<>()).computeIfAbsent(arity,k->new LinkedHashSet<>()).add(alias);
                    }
                }
                vars.push(new LinkedHashMap<>());
                for (VariableTree v : node.getParameters()) if (v.getType()!=null) vars.peek().put(v.getName().toString(),v.getType().toString());
                Void r=super.visitMethod(node,p); vars.pop(); return r;
            }
            @Override public Void visitBlock(BlockTree node, Void p) {
                vars.push(new LinkedHashMap<>()); Void r=super.visitBlock(node,p); vars.pop(); return r;
            }
            @Override public Void visitMemberSelect(MemberSelectTree node, Void p) {
                Tree parent=getCurrentPath()!=null&&getCurrentPath().getParentPath()!=null?getCurrentPath().getParentPath().getLeaf():null;
                boolean method=parent instanceof MethodInvocationTree mi && mi.getMethodSelect()==node;
                recordUse(node,method,method?((MethodInvocationTree)parent).getArguments().size():-1);
                return super.visitMemberSelect(node,p);
            }
        }.scan(unit,null);
    }

    static boolean isAppOwned(String fq, Opts o) {
        // Explicit binary rules deliberately outrank manifest roots/app prefixes.
        // This is for heavily obfuscated JADX trees where C####-style / p####-style classes are
        // much more useful as APK-derived ABI than as source.
        for (Pattern rx : o.forceBinaryPatterns) {
            if (rx.matcher(fq).find()) return false;
        }
        for (String root : o.rootClasses) if (fq.equals(root) || fq.startsWith(root + "$")) return true;
        for (String p : o.appPrefixes) {
            if (fq.equals(p) || fq.startsWith(p + ".") || fq.startsWith(p + "$")) return true;
        }
        return false;
    }

    static String sourceToRawFqcn(String fq) {
        String[] parts = fq.split("\\.");
        for (int i = 0; i < parts.length; i++) {
            if (i < parts.length - 1) {
                Matcher m = JADX_PKG_ALIAS.matcher(parts[i]);
                if (m.matches() && !m.group(1).isEmpty()) parts[i] = m.group(1);
            } else {
                String[] inners = parts[i].split("\\$", -1);
                for (int j = 0; j < inners.length; j++) {
                    Matcher m = JADX_CLASS_ALIAS.matcher(inners[j]);
                    if (m.matches() && !m.group(1).isEmpty()) inners[j] = m.group(1);
                }
                parts[i] = String.join("$", inners);
            }
        }
        return String.join(".", parts);
    }

    static String memberToRaw(String name, boolean method) {
        Matcher m = (method ? JADX_METHOD_ALIAS : JADX_FIELD_ALIAS).matcher(name == null ? "" : name);
        return m.matches() && !m.group(1).isEmpty() ? m.group(1) : name;
    }

    /** Reconcile guessed JADX aliases against classes that actually exist in the APK.
     *  Exact names win.  This prevents a legitimate class containing C#### from being
     *  "deobfuscated" into a class that does not exist, while still recovering broad
     *  JADX names such as AbstractComponentCallbacksC0168x -> x. */
    static void reconcileSourceMappings(SourceIndex src, Map<String, SmaliClass> dex, JadxMap jobf) {
        src.rawToSource.clear();

        // 1) Exact unrenamed source names always win.
        for (SourceType st : src.bySource.values()) {
            if (dex.containsKey(st.fqcn)) {
                st.rawFqcn = st.fqcn;
                src.rawToSource.put(st.rawFqcn, st.fqcn);
            }
        }

        // 2) JADX's own JOBF is authoritative for auto-generated package/class names.
        // It also works when the provider Java source was never emitted at all.
        if (jobf != null && !jobf.isEmpty()) {
            for (String raw : dex.keySet()) {
                String alias = jobf.sourceClassName(raw);
                if (!alias.equals(raw)) {
                    src.rawToSource.putIfAbsent(raw, alias);
                    SourceType st = src.bySource.get(alias);
                    if (st != null) st.rawFqcn = raw;
                }
            }

            /*
             * v27.4: JADX sometimes FLATTENS a real DEX nested class into a top-level
             * decompiled source file even though JOBF records only the inner alias leaf.
             * Example from the real TopActivity APK:
             *
             *   raw DEX: androidx.lifecycle.WithLifecycleStateKt$...$observer$1
             *   JOBF:    c raw$1 = C0174xfdb59cc4
             *   source:  androidx.lifecycle.C0174xfdb59cc4   (top-level file)
             *
             * The normal collision-safe JOBF rule deliberately preserves '$' nesting,
             * which is correct for ordinary inner classes (and fixed the v27.2 a0$a/e0$a
             * collision).  But when the source index proves that JADX emitted the alias
             * as a real top-level type, that observed source shape is stronger evidence.
             * Override ONLY in that case; never flatten a nested alias merely because its
             * leaf happens to resemble another class name.
             */
            for (String raw : dex.keySet()) {
                if (raw.indexOf('$') < 0) continue;
                String leafAlias = jobf.classes.get(raw);
                if (leafAlias == null || leafAlias.isEmpty()) continue;
                int cut = Math.max(leafAlias.lastIndexOf('$'), leafAlias.lastIndexOf('.'));
                if (cut >= 0) leafAlias = leafAlias.substring(cut + 1);
                int dot = raw.indexOf('$');
                String rawOuter = raw.substring(0, dot);
                int pkgDot = rawOuter.lastIndexOf('.');
                String rawPkg = pkgDot < 0 ? "" : rawOuter.substring(0, pkgDot);
                String aliasPkg = jobf.aliasPackage(rawPkg);
                String flat = aliasPkg == null || aliasPkg.isEmpty() ? leafAlias : aliasPkg + "." + leafAlias;
                SourceType observed = src.bySource.get(flat);
                if (observed != null && observed.topLevel) {
                    String previous = src.rawToSource.put(raw, flat);
                    observed.rawFqcn = raw;
                    if (previous != null && !previous.equals(flat))
                        log("observed top-level JADX flattening overrides nested JOBF alias: " + raw + " -> " + flat + " (was " + previous + ")");
                }
            }
        }

        // 3) Structural C####/p#### inversion is only a fallback for names not covered
        // by exact APK/JOBF evidence.
        for (SourceType st : src.bySource.values()) {
            if (!dex.containsKey(st.fqcn) && (st.rawFqcn == null || !dex.containsKey(st.rawFqcn)))
                st.rawFqcn = sourceToRawFqcn(st.fqcn);
            if (st.rawFqcn != null && dex.containsKey(st.rawFqcn))
                src.rawToSource.putIfAbsent(st.rawFqcn, st.fqcn);
        }
        for (String sourceName : src.observedTypeNames) {
            if (dex.containsKey(sourceName)) src.rawToSource.put(sourceName, sourceName);
        }
        for (String sourceName : src.observedTypeNames) {
            if (dex.containsKey(sourceName)) continue;
            String raw = sourceToRawFqcn(sourceName);
            if (dex.containsKey(raw)) src.rawToSource.putIfAbsent(raw, sourceName);
        }
    }

    /** Add exact JOBF member aliases to the owner+descriptor scoped linker maps. */
    static void linkJadxMapAliases(SourceIndex src, Map<String, SmaliClass> dex, JadxMap jobf) {
        if (jobf == null || jobf.isEmpty()) return;
        int fields = 0, methods = 0, missing = 0;
        for (SmaliClass c : dex.values()) {
            for (SmaliField f : c.fields) {
                String id = c.rawFqcn + "." + f.name + ":" + f.desc;
                String alias = jobf.fields.get(id);
                if (alias == null || alias.equals(f.name) || !javaIdentifier(alias)) continue;
                String key = c.rawFqcn + "#" + f.name + ":" + f.desc;
                if (src.useFieldAliasesByRawOwner.computeIfAbsent(key, k -> new LinkedHashSet<>()).add(alias)) fields++;
            }
            for (SmaliMethod m : c.methods) {
                String id = c.rawFqcn + "." + m.name + m.desc;
                String alias = jobf.methods.get(id);
                if (alias == null || alias.equals(m.name) || !javaIdentifier(alias)) continue;
                String key = c.rawFqcn + "#" + m.name + m.desc;
                if (src.useMethodAliasesByRawMember.computeIfAbsent(key, k -> new LinkedHashSet<>()).add(alias)) methods++;
            }
        }
        // Count stale entries rather than silently trusting a mapping from another APK.
        for (String id : jobf.fields.keySet()) {
            int colon = id.lastIndexOf(':'); int dot = colon < 0 ? -1 : id.lastIndexOf('.', colon);
            if (dot > 0) { String owner=id.substring(0,dot), name=id.substring(dot+1,colon), desc=id.substring(colon+1);
                SmaliClass c=dex.get(owner); if(c==null || c.fields.stream().noneMatch(f->f.name.equals(name)&&f.desc.equals(desc))) missing++; }
        }
        for (String id : jobf.methods.keySet()) {
            int par=id.indexOf('('); int dot=par<0?-1:id.lastIndexOf('.',par);
            if(dot>0){String owner=id.substring(0,dot), rest=id.substring(dot+1), name=rest.substring(0,rest.indexOf('(')), desc=rest.substring(rest.indexOf('('));
                SmaliClass c=dex.get(owner); if(c==null || c.methods.stream().noneMatch(m->m.name.equals(name)&&m.desc.equals(desc))) missing++;}
        }
        log("JADX JOBF exact linker: +" + fields + " field alias(es), +" + methods + " method alias(es)"
                + (missing == 0 ? "" : "; stale/unmatched entries=" + missing));
    }



    static void linkUseSiteAliases(SourceIndex src, Map<String, SmaliClass> dex) {
        int fields=0, methods=0, skipped=0;
        for (MemberUse u : src.memberUses) {
            String sourceOwner=resolveSourceType(u.ownerTypeText,u.packageName,u.imports,u.enclosingType,src);
            if (sourceOwner==null) { skipped++; continue; }
            SourceType st=src.bySource.get(sourceOwner);
            String rawOwner;
            if (st!=null) rawOwner=st.rawFqcn;
            else rawOwner=dex.containsKey(sourceOwner)?sourceOwner:sourceToRawFqcn(sourceOwner);
            SmaliClass c=dex.get(rawOwner); if(c==null){skipped++;continue;}
            String raw=memberToRaw(u.alias,u.method);
            if (!u.method) {
                List<SmaliField> candidates=c.fields.stream().filter(f->f.name.equals(raw)).toList();
                if(candidates.size()!=1){skipped++;continue;} // descriptor ambiguity: wait for stronger evidence
                SmaliField f=candidates.get(0); String key=rawOwner+"#"+f.name+":"+f.desc;
                if(src.useFieldAliasesByRawOwner.computeIfAbsent(key,k->new LinkedHashSet<>()).add(u.alias))fields++;
            } else {
                List<SmaliMethod> candidates=c.methods.stream().filter(m->m.name.equals(raw) && (u.arity<0 || methodArity(m.desc)==u.arity)).toList();
                if(candidates.size()!=1){skipped++;continue;} // semantic linker can disambiguate overloads later
                SmaliMethod m=candidates.get(0); String key=rawOwner+"#"+m.name+m.desc;
                if(src.useMethodAliasesByRawMember.computeIfAbsent(key,k->new LinkedHashSet<>()).add(u.alias))methods++;
            }
        }
        log("owner-scoped use-site linker: field aliases="+fields+", method aliases="+methods+", unresolved hints="+skipped);
    }

    static int methodArity(String desc) {
        int n=0,i=desc.indexOf('(')+1; if(i<=0)return -1;
        while(i<desc.length()&&desc.charAt(i)!=')'){
            while(desc.charAt(i)=='[')i++;
            char ch=desc.charAt(i++); if(ch=='L'){int semi=desc.indexOf(';',i);if(semi<0)return n;i=semi+1;} n++;
        }
        return n;
    }

    static String resolveSourceType(String rawText,String pkg,Set<String> imports,String enclosing,SourceIndex src) {
        if(rawText==null)return null; String t=rawText.trim();
        t=t.replaceAll("@[A-Za-z_$][\\w$.]*(?:\\([^)]*\\))?\\s*","");
        int gen=t.indexOf('<'); if(gen>=0)t=t.substring(0,gen); while(t.endsWith("[]"))t=t.substring(0,t.length()-2); t=t.trim();
        if(t.equals("this")||t.equals("super"))return enclosing;
        if(src.bySource.containsKey(t)||src.observedTypeNames.contains(t))return t;
        String simple=t.contains(".")?t.substring(t.lastIndexOf('.')+1):t;
        for(String imp:imports) if(!imp.endsWith(".*") && imp.substring(imp.lastIndexOf('.')+1).equals(simple))return imp;
        String same=pkg==null||pkg.isEmpty()?simple:pkg+"."+simple;
        if(src.bySource.containsKey(same)||src.observedTypeNames.contains(same))return same;
        String found=null; for(String n:src.observedTypeNames) if(n.endsWith("."+simple)||n.equals(simple)){if(found!=null&&!found.equals(n))return null;found=n;}
        return found!=null?found:same;
    }

    // ---------------------------------------------------------------- direct APK/DEX ABI reading

    static Map<String, SmaliClass> scanDexApk(Path apk) throws IOException {
        Map<String, SmaliClass> out = new LinkedHashMap<>();
        if (apk == null || !Files.isRegularFile(apk)) return out;
        for (DexReader.Clazz dc : DexReader.readApk(apk).values()) {
            SmaliClass c = new SmaliClass();
            c.rawFqcn = dc.fqcn; c.rawInternal = dc.internal; c.superDesc = dc.superDesc; c.signature = dc.signature;
            c.flags.addAll(accessFlagNames(dc.access, true, false));
            c.interfaceDescs.addAll(dc.interfaces);
            for (DexReader.Field df : dc.fields) {
                SmaliField f = new SmaliField(); f.name=df.name; f.desc=df.desc; f.signature=df.signature;
                f.flags.addAll(accessFlagNames(df.access, false, false)); f.constantValue=df.constantValue;
                c.fields.add(f);
            }
            for (DexReader.Method dm : dc.methods) {
                SmaliMethod m = new SmaliMethod(); m.name=dm.name; m.desc=dm.desc; m.signature=dm.signature;
                m.exceptionDescs.addAll(dm.exceptions);
                m.flags.addAll(accessFlagNames(dm.access, false, true)); c.methods.add(m);
            }
            out.put(c.rawFqcn,c);
        }
        return out;
    }

    static Set<String> accessFlagNames(int a, boolean clazz, boolean method) {
        LinkedHashSet<String> f = new LinkedHashSet<>();
        if ((a&0x1)!=0) f.add("public"); if ((a&0x2)!=0) f.add("private"); if ((a&0x4)!=0) f.add("protected");
        if ((a&0x8)!=0) f.add("static"); if ((a&0x10)!=0) f.add("final");
        if (method && (a&0x20)!=0) f.add("synchronized");
        if (!clazz && !method && (a&0x40)!=0) f.add("volatile");
        if (method && (a&0x40)!=0) f.add("bridge");
        if (!clazz && !method && (a&0x80)!=0) f.add("transient");
        if (method && (a&0x80)!=0) f.add("varargs");
        if (method && (a&0x100)!=0) f.add("native");
        if (clazz && (a&0x200)!=0) f.add("interface");
        if ((a&0x400)!=0) f.add("abstract");
        if ((a&0x1000)!=0) f.add("synthetic");
        if (clazz && (a&0x2000)!=0) f.add("annotation");
        if ((a&0x4000)!=0) f.add("enum");
        return f;
    }

    /** DEX defines existence/descriptors/access. Smali is optional metadata enrichment. */
    static Map<String, SmaliClass> loadApkAbi(Opts o) throws IOException {
        Map<String, SmaliClass> direct = scanDexApk(o.apk);
        Map<String, SmaliClass> smali = scanSmali(o.original);
        if (direct.isEmpty()) return smali;
        int enriched=0;
        for (SmaliClass c : direct.values()) {
            SmaliClass sc=smali.get(c.rawFqcn); if (sc==null) continue;
            // DEX annotations/static_values are authoritative. Smali is now only a
            // fallback for metadata the direct reader could not decode.
            if (c.signature==null && sc.signature!=null) c.signature=sc.signature;
            Map<String,SmaliField> sf=new HashMap<>(); for(SmaliField f:sc.fields)sf.put(f.name+":"+f.desc,f);
            for(SmaliField f:c.fields){
                SmaliField x=sf.get(f.name+":"+f.desc); if(x==null) continue;
                if(f.signature==null && x.signature!=null)f.signature=x.signature;
                if(f.constantValue==null && x.constantValue!=null)f.constantValue=x.constantValue;
            }
            Map<String,SmaliMethod> sm=new HashMap<>(); for(SmaliMethod m:sc.methods)sm.put(m.name+m.desc,m);
            for(SmaliMethod m:c.methods){
                SmaliMethod x=sm.get(m.name+m.desc); if(x==null) continue;
                if(m.signature==null && x.signature!=null)m.signature=x.signature;
                if(m.exceptionDescs.isEmpty() && !x.exceptionDescs.isEmpty())m.exceptionDescs.addAll(x.exceptionDescs);
            }
            enriched++;
        }
        log("direct DEX ABI: " + direct.size() + " class(es); smali metadata enriched " + enriched);
        return direct;
    }

    // ---------------------------------------------------------------- smali parsing

    static Map<String, SmaliClass> scanSmali(Path original) throws IOException {
        Map<String, SmaliClass> out = new LinkedHashMap<>();
        if (original == null || !Files.isDirectory(original)) return out;
        List<Path> roots;
        try (var st = Files.list(original)) {
            roots = st.filter(Files::isDirectory)
                    .filter(p -> p.getFileName().toString().equals("smali") || p.getFileName().toString().startsWith("smali_classes"))
                    .sorted().toList();
        }
        for (Path root : roots) {
            try (var st = Files.walk(root)) {
                for (Path p : st.filter(x -> x.toString().endsWith(".smali")).sorted().toList()) {
                    SmaliClass c = parseSmali(p);
                    if (c != null) out.put(c.rawFqcn, c);
                }
            }
        }
        return out;
    }

    static SmaliClass parseSmali(Path p) throws IOException {
        SmaliClass c = new SmaliClass(); c.path = p;
        List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
        SmaliField currentField = null;
        SmaliMethod currentMethod = null;
        for (int li = 0; li < lines.size(); li++) {
            String s = lines.get(li).trim();
            if (s.startsWith(".class ")) {
                currentField = null; currentMethod = null;
                String[] bits = s.split("\\s+");
                String desc = bits[bits.length - 1];
                c.rawInternal = objectDescriptorInternal(desc);
                c.rawFqcn = c.rawInternal == null ? null : c.rawInternal.replace('/', '.');
                for (int i = 1; i < bits.length - 1; i++) c.flags.add(bits[i]);
            } else if (s.startsWith(".super ")) {
                currentField = null;
                c.superDesc = s.substring(7).trim();
            } else if (s.startsWith(".implements ")) {
                currentField = null;
                c.interfaceDescs.add(s.substring(12).trim());
            } else if (s.startsWith(".field ")) {
                currentMethod = null;
                int colon = s.indexOf(':', 7);
                if (colon > 0) {
                    String left = s.substring(7, colon).trim();
                    String rhs = s.substring(colon + 1).trim();
                    String desc = rhs;
                    String constText = null;
                    int eq = rhs.indexOf(" = ");
                    if (eq >= 0) { desc = rhs.substring(0, eq).trim(); constText = rhs.substring(eq + 3).trim(); }
                    String[] bits = left.split("\\s+");
                    if (bits.length >= 1) {
                        SmaliField f = new SmaliField();
                        f.name = bits[bits.length - 1]; f.desc = desc;
                        for (int i = 0; i < bits.length - 1; i++) f.flags.add(bits[i]);
                        f.constantValue = parseSmaliConstant(desc, constText);
                        c.fields.add(f); currentField = f;
                    }
                }
            } else if (s.startsWith(".method ")) {
                currentField = null;
                String x = s.substring(8).trim();
                int lp = x.indexOf('('), rp = x.indexOf(')', lp + 1);
                if (lp > 0 && rp > lp) {
                    String head = x.substring(0, lp).trim();
                    String[] bits = head.split("\\s+");
                    SmaliMethod m = new SmaliMethod();
                    m.name = bits[bits.length - 1];
                    m.desc = x.substring(lp, rp + 1) + x.substring(rp + 1).trim().split("\\s+")[0];
                    for (int i = 0; i < bits.length - 1; i++) m.flags.add(bits[i]);
                    c.methods.add(m); currentMethod = m;
                }
            } else if (s.equals(".end method")) {
                currentMethod = null;
            } else if (s.equals(".end field")) {
                currentField = null;
            } else if (s.startsWith(".annotation ") && s.contains("Ldalvik/annotation/Signature;")) {
                StringBuilder sig = new StringBuilder();
                for (li = li + 1; li < lines.size(); li++) {
                    String a = lines.get(li).trim();
                    if (a.equals(".end annotation")) break;
                    Matcher qm = Pattern.compile("\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"").matcher(a);
                    while (qm.find()) sig.append(unescapeSmaliString(qm.group(1)));
                }
                String signature = sig.toString();
                if (!signature.isEmpty()) {
                    if (currentMethod != null) currentMethod.signature = signature;
                    else if (currentField != null) currentField.signature = signature;
                    else c.signature = signature;
                }
            }
        }
        return c.rawFqcn == null ? null : c;
    }

    static String unescapeSmaliString(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch != '\\' || i + 1 >= s.length()) { out.append(ch); continue; }
            char n = s.charAt(++i);
            switch (n) {
                case 'n' -> out.append('\n'); case 'r' -> out.append('\r'); case 't' -> out.append('\t');
                case '\\' -> out.append('\\'); case '"' -> out.append('"');
                case 'u' -> {
                    if (i + 4 < s.length()) {
                        try { out.append((char)Integer.parseInt(s.substring(i + 1, i + 5), 16)); i += 4; }
                        catch (NumberFormatException e) { out.append('u'); }
                    } else out.append('u');
                }
                default -> out.append(n);
            }
        }
        return out.toString();
    }

    static Object parseSmaliConstant(String desc, String raw) {
        if (raw == null || desc == null || desc.isEmpty()) return null;
        raw = raw.trim();
        try {
            char t = desc.charAt(0);
            if (t == 'L' && desc.equals("Ljava/lang/String;") && raw.startsWith("\"") && raw.endsWith("\""))
                return unescapeSmaliString(raw.substring(1, raw.length() - 1));
            if (t == 'Z') return parseIntegral(raw).intValue() == 0 ? 0 : 1;
            if (t == 'B' || t == 'S' || t == 'C' || t == 'I') return parseIntegral(raw).intValue();
            if (t == 'J') return parseIntegral(raw.replaceAll("[lL]$", "")).longValue();
            if (t == 'F') return Float.valueOf(raw.replaceAll("[fF]$", ""));
            if (t == 'D') return Double.valueOf(raw.replaceAll("[dD]$", ""));
        } catch (Exception ignored) { }
        return null;
    }

    static Long parseIntegral(String raw) {
        raw = raw.trim().replaceAll("[sStTlL]$", "");
        boolean neg = raw.startsWith("-");
        String x = neg ? raw.substring(1) : raw;
        long v;
        if (x.startsWith("0x") || x.startsWith("0X")) v = Long.parseUnsignedLong(x.substring(2), 16);
        else v = Long.parseLong(x);
        return neg ? -v : v;
    }

    static String objectDescriptorInternal(String desc) {
        if (desc != null && desc.startsWith("L") && desc.endsWith(";")) return desc.substring(1, desc.length() - 1);
        return null;
    }

    // ---------------------------------------------------------------- ABI shadow JAR

    static void runShadow(Opts o) throws Exception {
        if (o.original == null) die("shadow requires --original");
        if (o.outJar == null) die("shadow requires --out");
        if (o.ownership == null) die("shadow requires --ownership");
        SourceIndex src = scanSources(o);
        Map<String, SmaliClass> dex = loadApkAbi(o);
        JadxMap jobf = loadJadxMap(o.jadxMap);
        reconcileSourceMappings(src, dex, jobf);
        linkJadxMapAliases(src, dex, jobf);
        linkUseSiteAliases(src, dex);
        log("javac indexed " + src.bySource.size() + " source type(s); APK ABI indexed " + dex.size() + " DEX class(es)");

        // Mark one source file app-owned if any top-level type is app-owned.
        Map<Path, Boolean> fileApp = new LinkedHashMap<>();
        for (var e : src.byFile.entrySet()) {
            Path f = e.getKey().toAbsolutePath().normalize();
            if (!f.startsWith(o.javaRoot)) continue; // archive roots are evidence only
            boolean app = e.getValue().stream().anyMatch(t -> t.topLevel && t.appOwned);
            fileApp.put(f, app);
        }

        // v27 semantic linker: syntax gives us the first round of owner-local aliases,
        // then javac's attributed receiver types can unlock deeper/chained selections.
        // This is intentionally a fixed-point process: each newly linked field can expose
        // the receiver type needed to link the next field/method in a chain.
        semanticLinkAliases(o, src, dex, fileApp);

        Files.createDirectories(o.outJar.getParent());
        EmitStats stats = emitShadowJar(o.outJar, src, dex, o);

        writeOwnership(o, src, fileApp, stats.emitted, dex.size(), stats.shells);
        if (o.sourceList != null) {
            Files.createDirectories(o.sourceList.getParent());
            List<String> rels = new ArrayList<>();
            for (var e : fileApp.entrySet()) if (!e.getValue()) rels.add(o.javaRoot.relativize(e.getKey()).toString().replace(File.separatorChar, '/'));
            Collections.sort(rels);
            Files.write(o.sourceList, rels, StandardCharsets.UTF_8);
        }
        log("wrote " + stats.emitted + " compile-only ABI class(es) -> " + o.outJar + "; app source files remain authoritative");
    }

    static final class EmitStats {
        int emitted, skippedApp, shells;
    }

    /** Emit one complete shadow JAR from the current source<->DEX mapping and alias graph. */
    static EmitStats emitShadowJar(Path outJar, SourceIndex src, Map<String, SmaliClass> dex, Opts o) throws IOException {
        Files.createDirectories(outJar.getParent());
        Map<String, List<String>> childrenByOuter = new LinkedHashMap<>();
        for (SmaliClass c : dex.values()) {
            String target = mapRawInternal(c.rawInternal, src);
            int dollar = target.lastIndexOf('$');
            if (dollar > 0) childrenByOuter.computeIfAbsent(target.substring(0, dollar), k -> new ArrayList<>()).add(target);
        }
        EmitStats stats = new EmitStats();
        Set<String> emittedInternal = new HashSet<>();
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(outJar))) {
            byte[] classManifest = buildClassManifest(src, dex).getBytes(StandardCharsets.UTF_8);
            JarEntry cme = new JarEntry("META-INF/apk2project-shadow-classes.tsv");
            jar.putNextEntry(cme); jar.write(classManifest); jar.closeEntry();
            byte[] aliasManifest = buildAliasManifest(src, dex).getBytes(StandardCharsets.UTF_8);
            JarEntry ame = new JarEntry("META-INF/apk2project-shadow-aliases.tsv");
            jar.putNextEntry(ame); jar.write(aliasManifest); jar.closeEntry();
            for (SmaliClass c : dex.values()) {
                String sourceName = src.rawToSource.get(c.rawFqcn);
                SourceType st = sourceName == null ? null : src.bySource.get(sourceName);
                boolean appOwned = st != null && st.appOwned;
                if (appOwned) { stats.skippedApp++; continue; }
                if (!o.includeUnmappedDex && st == null) continue;
                String targetInternal = mapRawInternal(c.rawInternal, src);
                if (!emittedInternal.add(targetInternal)) continue;
                byte[] bytes = emitStubClass(c, targetInternal, st, src, o, childrenByOuter.getOrDefault(targetInternal, List.of()));
                JarEntry je = new JarEntry(targetInternal + ".class");
                jar.putNextEntry(je); jar.write(bytes); jar.closeEntry(); stats.emitted++;
            }

            // A source alias with no DEX class is kept only as a last-resort shell. The
            // validator treats large real DEX classes becoming shells as fatal, so this
            // path cannot silently replace a class that actually exists in the APK.
            for (SourceType st : src.bySource.values()) {
                if (st.appOwned) continue;
                if (dex.containsKey(st.rawFqcn)) continue;
                String targetInternal = st.fqcn.replace('.', '/');
                if (!emittedInternal.add(targetInternal)) continue;
                byte[] bytes = emitShellClass(targetInternal, st, o);
                JarEntry je = new JarEntry(targetInternal + ".class");
                jar.putNextEntry(je); jar.write(bytes); jar.closeEntry();
                stats.emitted++; stats.shells++;
            }
        }
        return stats;
    }

    /**
     * Use javac attribution as an owner oracle for member aliases.
     *
     * A first shadow is emitted from DEX + declaration/syntax evidence. App source is
     * then attributed against it. Even when `x.f123a` itself is unresolved, javac often
     * knows the type of `x`; after f123a is linked, the next round can know the type of
     * `x.f123a` and therefore link a following `.m456b(...)`. This converges quickly and
     * avoids the catastrophic global suffix fan-out used by earlier prototypes.
     */
    static void semanticLinkAliases(Opts o, SourceIndex src, Map<String, SmaliClass> dex, Map<Path, Boolean> fileApp) {
        List<Path> appFiles = fileApp.entrySet().stream().filter(Map.Entry::getValue).map(Map.Entry::getKey).sorted().toList();
        if (appFiles.isEmpty()) return;
        Path parent = o.outJar.getParent();
        if (parent == null) return;
        Path probe = parent.resolve(".apk2project-shadow-link.jar");
        int totalFields = 0, totalMethods = 0;
        try {
            for (int round = 1; round <= 5; round++) {
                emitShadowJar(probe, src, dex, o);
                int[] added = semanticLinkRound(o, src, dex, appFiles, probe);
                totalFields += added[0]; totalMethods += added[1];
                log("semantic alias linker round " + round + ": +" + added[0] + " field alias(es), +" + added[1] + " method alias(es)");
                if (added[0] + added[1] == 0) break;
            }
        } catch (Throwable t) {
            log("semantic alias linker degraded to syntax-only evidence: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        } finally {
            try { Files.deleteIfExists(probe); } catch (IOException ignored) { }
        }
        if (totalFields + totalMethods > 0)
            log("semantic alias linker fixed-point: +" + totalFields + " field alias(es), +" + totalMethods + " method alias(es)");
    }

    static int[] semanticLinkRound(Opts o, SourceIndex src, Map<String, SmaliClass> dex, List<Path> appFiles, Path probeJar) throws Exception {
        JavacTool tool = JavacTool.create(); Context context = new Context(); EngineDiagnostic dl = new EngineDiagnostic();
        JavacFileManager fm = tool.getStandardFileManager(dl, Locale.ROOT, StandardCharsets.UTF_8);
        List<String> opts = new ArrayList<>(List.of("-proc:none", "-Xlint:none", "-Xmaxerrs", "10000"));
        LinkedHashSet<String> cp = new LinkedHashSet<>(); cp.add(probeJar.toString());
        if (o.classpathFile != null && Files.isRegularFile(o.classpathFile)) {
            for (String line : Files.readAllLines(o.classpathFile)) {
                String x = line.trim(); if (!x.isEmpty() && !Path.of(x).toAbsolutePath().normalize().equals(o.outJar)) cp.add(x);
            }
        }
        opts.add("-classpath"); opts.add(String.join(File.pathSeparator, cp));
        Iterable<? extends JavaFileObject> fos = fm.getJavaFileObjectsFromPaths(appFiles);
        JavacTaskImpl task = (JavacTaskImpl) tool.getTask(null, fm, dl, opts, null, fos, context);
        Iterable<? extends CompilationUnitTree> parsed = task.parse();
        try { task.enter(parsed); task.analyze(); } catch (Throwable ignored) { /* partial attribution is useful */ }
        int[] added = {0,0};
        for (CompilationUnitTree unit : parsed) {
            new TreePathScanner<Void, Void>() {
                @Override public Void visitMemberSelect(MemberSelectTree node, Void p) {
                    String alias = node.getIdentifier().toString();
                    Tree parent = getCurrentPath()!=null && getCurrentPath().getParentPath()!=null ? getCurrentPath().getParentPath().getLeaf() : null;
                    boolean method = parent instanceof MethodInvocationTree mi && mi.getMethodSelect()==node;
                    if (method ? !JADX_METHOD_ALIAS.matcher(alias).matches() : !JADX_FIELD_ALIAS.matcher(alias).matches())
                        return super.visitMemberSelect(node,p);
                    JCTree selected = node.getExpression() instanceof JCTree jt ? jt : null;
                    String sourceOwner = attributedQualifiedType(selected == null ? null : selected.type);
                    if (sourceOwner == null || sourceOwner.isEmpty()) return super.visitMemberSelect(node,p);
                    String rawOwner = rawOwnerForSource(sourceOwner, src, dex);
                    SmaliClass c = rawOwner == null ? null : dex.get(rawOwner);
                    if (c == null) return super.visitMemberSelect(node,p);
                    String raw = memberToRaw(alias, method);
                    if (!method) {
                        List<SmaliField> candidates=c.fields.stream().filter(f -> f.name.equals(raw)).toList();
                        if(candidates.size()==1) {
                            SmaliField f=candidates.get(0); String key = rawOwner + "#" + f.name + ":" + f.desc;
                            if (src.useFieldAliasesByRawOwner.computeIfAbsent(key,k->new LinkedHashSet<>()).add(alias)) added[0]++;
                        }
                    } else {
                        MethodInvocationTree call=(MethodInvocationTree)parent;
                        int arity = call.getArguments().size();
                        List<SmaliMethod> candidates=c.methods.stream().filter(m->m.name.equals(raw) && methodArity(m.desc)==arity).toList();
                        SmaliMethod chosen=chooseMethodByAttributedArguments(candidates,call,task,src);
                        if(chosen!=null){
                            String key = rawOwner + "#" + chosen.name + chosen.desc;
                            if (src.useMethodAliasesByRawMember.computeIfAbsent(key,k->new LinkedHashSet<>()).add(alias)) added[1]++;
                        }
                    }
                    return super.visitMemberSelect(node,p);
                }
            }.scan(unit,null);
        }
        fm.close(); return added;
    }

    /**
     * Disambiguate overloaded raw DEX methods using javac-attributed argument types.
     * A unique arity is enough; otherwise a candidate must be uniquely compatible.
     * Ambiguity is deliberately left unresolved rather than spraying one JADX alias
     * across multiple overloads and poisoning later javac attribution.
     */
    static SmaliMethod chooseMethodByAttributedArguments(List<SmaliMethod> candidates, MethodInvocationTree call,
                                                          JavacTaskImpl task, SourceIndex src) {
        if(candidates.isEmpty()) return null;
        if(candidates.size()==1) return candidates.get(0);
        javax.lang.model.util.Types modelTypes=task.getTypes();
        javax.lang.model.util.Elements elements=task.getElements();
        int best=Integer.MIN_VALUE; SmaliMethod winner=null; boolean tie=false; boolean sawTyped=false;
        for(SmaliMethod m:candidates){
            List<String> params=methodParamDescriptors(remapMethodDescriptor(m.desc,src));
            if(params.size()!=call.getArguments().size()) continue;
            int score=0; boolean impossible=false;
            for(int i=0;i<params.size();i++){
                JCTree arg=call.getArguments().get(i) instanceof JCTree jt ? jt : null;
                javax.lang.model.type.TypeMirror at=arg==null?null:arg.type;
                if(at==null || at.getKind()==javax.lang.model.type.TypeKind.ERROR || at.getKind()==javax.lang.model.type.TypeKind.NONE){continue;}
                javax.lang.model.type.TypeMirror pt=descriptorTypeMirror(params.get(i),elements,modelTypes);
                if(pt==null) continue;
                sawTyped=true;
                try{
                    if(modelTypes.isSameType(at,pt)) score+=8;
                    else if(modelTypes.isAssignable(at,pt)) score+=5;
                    else { impossible=true; break; }
                }catch(Throwable ignored){ }
            }
            if(impossible) continue;
            if(score>best){best=score;winner=m;tie=false;}
            else if(score==best){tie=true;}
        }
        if(winner==null || tie || (!sawTyped && candidates.size()>1)) return null;
        return winner;
    }

    static List<String> methodParamDescriptors(String desc){
        List<String> out=new ArrayList<>(); int i=desc.indexOf('(')+1,end=desc.indexOf(')',i); if(i<=0||end<0)return out;
        while(i<end){int start=i;while(i<end&&desc.charAt(i)=='[')i++;if(i>=end)break;char ch=desc.charAt(i++);if(ch=='L'){int semi=desc.indexOf(';',i);if(semi<0||semi>end)break;i=semi+1;}out.add(desc.substring(start,i));}
        return out;
    }

    static javax.lang.model.type.TypeMirror descriptorTypeMirror(String desc, javax.lang.model.util.Elements elements,
                                                                  javax.lang.model.util.Types types){
        if(desc==null||desc.isEmpty())return null;
        if(desc.charAt(0)=='['){javax.lang.model.type.TypeMirror e=descriptorTypeMirror(desc.substring(1),elements,types);return e==null?null:types.getArrayType(e);}
        return switch(desc.charAt(0)){
            case 'Z' -> types.getPrimitiveType(javax.lang.model.type.TypeKind.BOOLEAN);
            case 'B' -> types.getPrimitiveType(javax.lang.model.type.TypeKind.BYTE);
            case 'S' -> types.getPrimitiveType(javax.lang.model.type.TypeKind.SHORT);
            case 'C' -> types.getPrimitiveType(javax.lang.model.type.TypeKind.CHAR);
            case 'I' -> types.getPrimitiveType(javax.lang.model.type.TypeKind.INT);
            case 'J' -> types.getPrimitiveType(javax.lang.model.type.TypeKind.LONG);
            case 'F' -> types.getPrimitiveType(javax.lang.model.type.TypeKind.FLOAT);
            case 'D' -> types.getPrimitiveType(javax.lang.model.type.TypeKind.DOUBLE);
            case 'L' -> {
                if(!desc.endsWith(";"))yield null; String fq=desc.substring(1,desc.length()-1).replace('/','.');
                javax.lang.model.element.TypeElement el=elements.getTypeElement(fq); yield el==null?null:el.asType();
            }
            default -> null;
        };
    }

    static String attributedQualifiedType(Type t) {
        if (t == null || t.isErroneous()) return null;
        try {
            Type x = t;
            while (x != null && x.hasTag(com.sun.tools.javac.code.TypeTag.ARRAY)) x = ((Type.ArrayType)x).elemtype;
            Symbol s = x == null ? null : x.tsym;
            if (s != null) {
                String q = s.getQualifiedName().toString();
                if (!q.isEmpty()) return q;
            }
        } catch (Throwable ignored) { }
        return null;
    }

    static String rawOwnerForSource(String sourceOwner, SourceIndex src, Map<String, SmaliClass> dex) {
        SourceType st = src.bySource.get(sourceOwner);
        if (st != null && dex.containsKey(st.rawFqcn)) return st.rawFqcn;
        if (dex.containsKey(sourceOwner)) return sourceOwner;
        String guessed = sourceToRawFqcn(sourceOwner);
        if (dex.containsKey(guessed)) return guessed;
        // rawToSource is raw -> source; use it only when exact source equality proves
        // the reverse mapping, never by member suffix or simple-name coincidence.
        for (var e : src.rawToSource.entrySet()) if (e.getValue().equals(sourceOwner) && dex.containsKey(e.getKey())) return e.getKey();
        return null;
    }

    static String buildClassManifest(SourceIndex src, Map<String, SmaliClass> dex) {
        StringBuilder b = new StringBuilder("#raw_owner\tshadow_owner\n");
        for (SmaliClass c : dex.values()) {
            String shadowOwner = mapRawInternal(c.rawInternal, src).replace('/', '.');
            b.append(c.rawFqcn).append('\t').append(shadowOwner).append('\n');
        }
        return b.toString();
    }

    static String buildAliasManifest(SourceIndex src, Map<String, SmaliClass> dex) {
        StringBuilder b = new StringBuilder("#kind\tshadow_owner\traw_owner\traw_name\traw_desc\talias\tshadow_desc\n");
        for (SmaliClass c : dex.values()) {
            String sourceName = src.rawToSource.get(c.rawFqcn);
            SourceType st = sourceName == null ? null : src.bySource.get(sourceName);
            if (st != null && st.appOwned) continue; // source wins; there is no shadow class to validate
            String shadowOwner = mapRawInternal(c.rawInternal, src).replace('/', '.');
            // C records make validation independent of any C####/p#### reverse-name heuristic.
            b.append("C\t").append(shadowOwner).append('\t').append(c.rawFqcn)
             .append("\t-\t-\t-\t-\n");
            for (SmaliField f : c.fields) {
                LinkedHashSet<String> names = new LinkedHashSet<>();
                if (st != null && c.fields.stream().filter(x -> x.name.equals(f.name)).count()==1)
                    names.addAll(st.fieldAliasesByRaw.getOrDefault(f.name, Set.of()));
                names.addAll(src.useFieldAliasesByRawOwner.getOrDefault(c.rawFqcn+"#"+f.name+":"+f.desc, Set.of()));
                String sd = remapDescriptor(f.desc, src);
                for (String alias : names) if (!alias.equals(f.name) && javaIdentifier(alias))
                    b.append("F\t").append(shadowOwner).append('\t').append(c.rawFqcn).append('\t').append(f.name)
                     .append('\t').append(f.desc).append('\t').append(alias).append('\t').append(sd).append('\n');
            }
            for (SmaliMethod m : c.methods) {
                if (m.name.equals("<init>") || m.name.equals("<clinit>")) continue;
                LinkedHashSet<String> names = new LinkedHashSet<>();
                if (st != null) {
                    int arity=methodArity(m.desc);
                    long sameArity=c.methods.stream().filter(x->x.name.equals(m.name)&&methodArity(x.desc)==arity).count();
                    Set<String> byArity=st.methodAliasesByRawArity.getOrDefault(m.name,Map.of()).get(arity);
                    if(byArity!=null && sameArity==1) names.addAll(byArity);
                    else if(byArity==null && c.methods.stream().filter(x->x.name.equals(m.name)).count()==1)
                        names.addAll(st.methodAliasesByRaw.getOrDefault(m.name,Set.of()));
                }
                names.addAll(src.useMethodAliasesByRawMember.getOrDefault(c.rawFqcn+"#"+m.name+m.desc, Set.of()));
                String sd = remapMethodDescriptor(m.desc, src);
                for (String alias : names) if (!alias.equals(m.name) && javaIdentifier(alias))
                    b.append("M\t").append(shadowOwner).append('\t').append(c.rawFqcn).append('\t').append(m.name)
                     .append('\t').append(m.desc).append('\t').append(alias).append('\t').append(sd).append('\n');
            }
        }
        // Explicit provenance for source-only shells. These are classes that JADX
        // emitted from a non-DEX auxiliary input (for example DebugProbesKt.bin) or a
        // synthetic decompiler artifact. They are intentionally allowed to exist in the
        // compile-time shadow even though there is no raw DEX owner to validate against.
        // The validator must distinguish these from an accidentally unanchored class.
        Set<String> mappedShadowOwners = dex.values().stream()
                .map(c -> mapRawInternal(c.rawInternal, src).replace('/', '.'))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        for (SourceType st : src.bySource.values()) {
            if (st.appOwned) continue;
            if (st.rawFqcn != null && dex.containsKey(st.rawFqcn)) continue;
            if (mappedShadowOwners.contains(st.fqcn)) continue;
            b.append("S\t").append(st.fqcn).append("\t-\t-\t-\tsource-only\t-\n");
        }
        return b.toString();
    }


    static byte[] emitShellClass(String internal, SourceType st, Opts o) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, internal, null, "java/lang/Object", null);
        emitPoisonConstructor(cw, "()V", Opcodes.ACC_PUBLIC);
        cw.visitEnd(); return cw.toByteArray();
    }

    static byte[] emitStubClass(SmaliClass c, String targetInternal, SourceType st, SourceIndex src, Opts o, List<String> innerChildren) {
        int access = classAccess(c.flags, o.permissive);
        String superInternal = descriptorObjectMapped(c.superDesc, src);
        if ((access & Opcodes.ACC_INTERFACE) != 0) superInternal = "java/lang/Object";
        if (superInternal == null) superInternal = "java/lang/Object";
        String[] interfaces = c.interfaceDescs.stream().map(d -> descriptorObjectMapped(d, src)).filter(Objects::nonNull).toArray(String[]::new);
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, access, targetInternal, remapSignature(c.signature, src), superInternal, interfaces);
        emitInnerMetadata(cw, targetInternal, access, innerChildren);

        Set<String> fieldKeys = new HashSet<>();
        for (SmaliField f : c.fields) {
            String desc = remapDescriptor(f.desc, src);
            LinkedHashSet<String> names = new LinkedHashSet<>(); names.add(f.name);
            if (st != null) names.addAll(st.fieldAliasesByRaw.getOrDefault(f.name, Set.of()));
            names.addAll(src.useFieldAliasesByRawOwner.getOrDefault(c.rawFqcn+"#"+f.name+":"+f.desc, Set.of()));
            for (String name : names) {
                if (!javaIdentifier(name)) continue;
                String key = name + ":" + desc; if (!fieldKeys.add(key)) continue;
                int fa = memberAccess(f.flags, false, o.permissive);
                Object constValue = f.constantValue;
                if ((access & Opcodes.ACC_INTERFACE) != 0) fa = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL;
                if (constValue != null) fa |= Opcodes.ACC_STATIC | Opcodes.ACC_FINAL;
                FieldVisitor fv = cw.visitField(fa, name, desc, remapSignature(f.signature, src), constValue); fv.visitEnd();
            }
        }

        Set<String> methodKeys = new HashSet<>();
        for (SmaliMethod m : c.methods) {
            String desc = remapMethodDescriptor(m.desc, src);
            LinkedHashSet<String> names = new LinkedHashSet<>();
            if (m.name.equals("<init>") || m.name.equals("<clinit>")) names.add(m.name);
            else {
                names.add(m.name);
                if (st != null) {
                    int arity=methodArity(m.desc);
                    long sameArity=c.methods.stream().filter(x->x.name.equals(m.name)&&methodArity(x.desc)==arity).count();
                    Set<String> byArity=st.methodAliasesByRawArity.getOrDefault(m.name,Map.of()).get(arity);
                    if(byArity!=null && sameArity==1) names.addAll(byArity);
                    else if(byArity==null && c.methods.stream().filter(x->x.name.equals(m.name)).count()==1)
                        names.addAll(st.methodAliasesByRaw.getOrDefault(m.name, Set.of()));
                }
                names.addAll(src.useMethodAliasesByRawMember.getOrDefault(c.rawFqcn+"#"+m.name+m.desc, Set.of()));
            }
            for (String name : names) {
                if (!(name.equals("<init>") || name.equals("<clinit>") || javaIdentifier(name))) continue;
                String key = name + desc; if (!methodKeys.add(key)) continue;
                int ma = memberAccess(m.flags, true, o.permissive);
                if (name.equals("<init>")) {
                    ma &= ~(Opcodes.ACC_STATIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_FINAL);
                    ma = widen(ma, o.permissive);
                }
                if (name.equals("<clinit>")) ma = Opcodes.ACC_STATIC;
                if ((access & Opcodes.ACC_INTERFACE) != 0 && !name.equals("<clinit>") && (ma & Opcodes.ACC_STATIC) == 0) {
                    ma &= ~(Opcodes.ACC_NATIVE | Opcodes.ACC_FINAL | Opcodes.ACC_SYNCHRONIZED);
                    ma |= Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT;
                }
                boolean noCode = (ma & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0;
                String[] exceptions = m.exceptionDescs.stream()
                        .map(d -> descriptorObjectMapped(d, src)).filter(Objects::nonNull).toArray(String[]::new);
                MethodVisitor mv = cw.visitMethod(ma, name, desc, remapSignature(m.signature, src),
                        exceptions.length == 0 ? null : exceptions);
                if (!noCode) {
                    mv.visitCode(); mv.visitInsn(Opcodes.ACONST_NULL); mv.visitInsn(Opcodes.ATHROW); mv.visitMaxs(1, argumentLocalSlots(desc, (ma & Opcodes.ACC_STATIC) == 0));
                }
                mv.visitEnd();
            }
        }

        // Some damaged decompiles lose every constructor declaration. Ensure javac
        // can instantiate a binary-owned shell when DEX metadata was incomplete.
        if (c.methods.stream().noneMatch(m -> m.name.equals("<init>")) && (access & Opcodes.ACC_INTERFACE) == 0) {
            emitPoisonConstructor(cw, "()V", Opcodes.ACC_PUBLIC);
        }
        cw.visitEnd(); return cw.toByteArray();
    }

    static void emitPoisonConstructor(ClassWriter cw, String desc, int access) {
        MethodVisitor mv = cw.visitMethod(access, "<init>", desc, null, null);
        mv.visitCode(); mv.visitInsn(Opcodes.ACONST_NULL); mv.visitInsn(Opcodes.ATHROW); mv.visitMaxs(1, argumentLocalSlots(desc, true)); mv.visitEnd();
    }

    static void addCapped(LinkedHashSet<String> dst, Set<String> src, int cap) {
        if (src == null) return; int n = 0;
        for (String s : src) { if (n++ >= cap) break; dst.add(s); }
    }

    static boolean javaIdentifier(String s) {
        if (s == null || s.isEmpty() || !Character.isJavaIdentifierStart(s.charAt(0))) return false;
        for (int i = 1; i < s.length(); i++) if (!Character.isJavaIdentifierPart(s.charAt(i))) return false;
        return !Set.of("class","interface","enum","extends","implements","new","this","super","return","if","else","for","while","switch","case","default","try","catch","finally","throw","throws","public","private","protected","static","final","abstract","native","synchronized","volatile","transient","strictfp","void","int","long","short","byte","char","float","double","boolean","null","true","false","package","import","instanceof","record","sealed","permits","var","yield").contains(s);
    }

    static int classAccess(Set<String> flags, boolean permissive) {
        int a = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        if (flags.contains("interface")) { a |= Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT; a &= ~Opcodes.ACC_SUPER; }
        if (flags.contains("abstract")) a |= Opcodes.ACC_ABSTRACT;
        if (flags.contains("annotation")) a |= Opcodes.ACC_ANNOTATION | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT;
        if (flags.contains("enum")) a |= Opcodes.ACC_ENUM;
        // Compile-time shadow classes are a *source-facing ABI facade*. javac deliberately
        // hides ACC_SYNTHETIC declarations from Java source lookup, even though javap and
        // reflection can see them. DEX/R8 frequently marks compatibility shims synthetic,
        // and JADX emits ordinary Java calls to those shims. Preserve the descriptor and
        // provenance, but intentionally clear ACC_SYNTHETIC in the shadow facade.
        if (flags.contains("final") && !permissive) a |= Opcodes.ACC_FINAL;
        return a;
    }

    static int memberAccess(Set<String> flags, boolean method, boolean permissive) {
        int a = 0;
        if (flags.contains("static")) a |= Opcodes.ACC_STATIC;
        if (flags.contains("abstract")) a |= Opcodes.ACC_ABSTRACT;
        if (flags.contains("native")) a |= Opcodes.ACC_NATIVE;
        if (flags.contains("synchronized") && method) a |= Opcodes.ACC_SYNCHRONIZED;
        // ACC_SYNTHETIC members are ignored by javac member/constructor lookup.  The APK
        // contains many R8/API compatibility shims with exactly that flag, while JADX
        // necessarily references them from reconstructed Java source.  The shadow JAR is
        // compileOnly, so expose the same ABI without source-hiding flags. ACC_BRIDGE is
        // also an implementation artifact and is unnecessary on the source-facing copy.
        if (flags.contains("varargs") && method) a |= Opcodes.ACC_VARARGS;
        if (flags.contains("volatile") && !method) a |= Opcodes.ACC_VOLATILE;
        if (flags.contains("transient") && !method) a |= Opcodes.ACC_TRANSIENT;
        if (flags.contains("enum") && !method) a |= Opcodes.ACC_ENUM;
        if (flags.contains("final") && !permissive) a |= Opcodes.ACC_FINAL;
        if (!permissive) {
            if (flags.contains("private")) a |= Opcodes.ACC_PRIVATE;
            else if (flags.contains("protected")) a |= Opcodes.ACC_PROTECTED;
            else if (flags.contains("public")) a |= Opcodes.ACC_PUBLIC;
        }
        return widen(a, permissive);
    }

    static int widen(int a, boolean permissive) {
        if (!permissive) return a;
        a &= ~(Opcodes.ACC_PRIVATE | Opcodes.ACC_PROTECTED);
        a |= Opcodes.ACC_PUBLIC;
        return a;
    }

    static void emitInnerMetadata(ClassWriter cw, String targetInternal, int access, List<String> children) {
        int dollar = targetInternal.lastIndexOf('$');
        if (dollar > 0) {
            String outer = targetInternal.substring(0, dollar);
            String simple = targetInternal.substring(dollar + 1);
            cw.visitInnerClass(targetInternal, outer, simple, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
        }
        for (String child : children) {
            int d = child.lastIndexOf('$');
            String simple = d >= 0 ? child.substring(d + 1) : child;
            cw.visitInnerClass(child, targetInternal, simple, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
        }
    }

    static String remapSignature(String sig, SourceIndex src) {
        if (sig == null || sig.isEmpty()) return null;
        Matcher m = Pattern.compile("L([^;<:]+)").matcher(sig);
        StringBuffer out = new StringBuffer();
        while (m.find()) {
            String mapped = mapRawInternal(m.group(1), src);
            m.appendReplacement(out, Matcher.quoteReplacement("L" + mapped));
        }
        m.appendTail(out);
        return out.toString();
    }

    static String descriptorObjectMapped(String desc, SourceIndex src) {
        String in = objectDescriptorInternal(desc); if (in == null) return null;
        return mapRawInternal(in, src);
    }

    static String mapRawInternal(String rawInternal, SourceIndex src) {
        String raw = rawInternal.replace('/', '.');
        String mapped = src.rawToSource.get(raw);
        return mapped == null ? rawInternal : mapped.replace('.', '/');
    }

    static String remapDescriptor(String desc, SourceIndex src) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < desc.length();) {
            char ch = desc.charAt(i);
            if (ch == 'L') {
                int semi = desc.indexOf(';', i); if (semi < 0) { out.append(desc.substring(i)); break; }
                String raw = desc.substring(i + 1, semi);
                out.append('L').append(mapRawInternal(raw, src)).append(';'); i = semi + 1;
            } else { out.append(ch); i++; }
        }
        return out.toString();
    }

    static String remapMethodDescriptor(String desc, SourceIndex src) { return remapDescriptor(desc, src); }

    static int argumentLocalSlots(String methodDesc, boolean hasThis) {
        int slots = hasThis ? 1 : 0; int i = methodDesc.indexOf('(') + 1;
        while (i > 0 && i < methodDesc.length() && methodDesc.charAt(i) != ')') {
            while (methodDesc.charAt(i) == '[') i++;
            char c = methodDesc.charAt(i++);
            if (c == 'L') { i = methodDesc.indexOf(';', i) + 1; slots += 1; }
            else slots += (c == 'J' || c == 'D') ? 2 : 1;
        }
        return slots;
    }

    static void writeOwnership(Opts o, SourceIndex src, Map<Path, Boolean> fileApp, int emitted, int dexCount, int missingSmali) throws IOException {
        Files.createDirectories(o.ownership.getParent());
        StringBuilder b = new StringBuilder();
        b.append("{\n  \"version\": 1,\n  \"engine\": \"javac-internal+asm-shadow\",\n");
        b.append("  \"java_root\": ").append(json(o.javaRoot.toString())).append(",\n");
        b.append("  \"app_prefixes\": ").append(jsonArray(o.appPrefixes)).append(",\n");
        b.append("  \"force_binary_regexes\": ").append(jsonArray(o.forceBinaryRegexes)).append(",\n");
        b.append("  \"jadx_map\": ").append(json(o.jadxMap == null ? "" : o.jadxMap.toString())).append(",\n");
        b.append("  \"shadow_classes\": ").append(emitted).append(",\n  \"dex_classes\": ").append(dexCount).append(",\n  \"shells_without_smali\": ").append(missingSmali).append(",\n");
        b.append("  \"app_sources\": [\n"); boolean first = true;
        for (var e : fileApp.entrySet()) if (e.getValue()) { if (!first) b.append(",\n"); first=false; b.append("    ").append(json(o.javaRoot.relativize(e.getKey()).toString().replace(File.separatorChar,'/'))); }
        b.append("\n  ],\n  \"binary_sources\": [\n"); first = true;
        for (var e : fileApp.entrySet()) if (!e.getValue()) { if (!first) b.append(",\n"); first=false; b.append("    ").append(json(o.javaRoot.relativize(e.getKey()).toString().replace(File.separatorChar,'/'))); }
        b.append("\n  ],\n  \"source_to_raw\": {\n"); first = true;
        for (SourceType st : src.bySource.values()) { if (!first) b.append(",\n"); first=false; b.append("    ").append(json(st.fqcn)).append(": ").append(json(st.rawFqcn)); }
        b.append("\n  }\n}\n");
        Files.writeString(o.ownership, b.toString());
    }


    // ---------------------------------------------------------------- shadow ABI validation against direct DEX truth

    static final class ClassSurface {
        int fields, methods, access;
        String internal, superInternal, signature;
        final Set<String> interfaces = new LinkedHashSet<>();
        final Set<String> fieldKeys = new LinkedHashSet<>();
        final Set<String> methodKeys = new LinkedHashSet<>();
        final Map<String,String> fieldSignatures = new LinkedHashMap<>();
        final Map<String,String> methodSignatures = new LinkedHashMap<>();
        final Map<String,Set<String>> methodExceptions = new LinkedHashMap<>();
    }

    static String remapDexDescriptor(String desc, Map<String,String> rawToShadow) {
        if (desc == null || desc.isEmpty()) return desc;
        StringBuilder out = new StringBuilder(desc.length() + 16);
        for (int i = 0; i < desc.length();) {
            char ch = desc.charAt(i);
            if (ch != 'L') { out.append(ch); i++; continue; }
            int semi = desc.indexOf(';', i);
            if (semi < 0) { out.append(desc.substring(i)); break; }
            String rawInternal = desc.substring(i + 1, semi);
            String raw = rawInternal.replace('/', '.');
            String shadow = rawToShadow.getOrDefault(raw, raw);
            out.append('L').append(shadow.replace('.', '/')).append(';');
            i = semi + 1;
        }
        return out.toString();
    }

    static String descriptorObjectInternalMapped(String desc, Map<String,String> rawToShadow) {
        String x = remapDexDescriptor(desc, rawToShadow);
        return x != null && x.startsWith("L") && x.endsWith(";") ? x.substring(1, x.length() - 1) : null;
    }

    static String remapDexSignature(String sig, Map<String,String> rawToShadow) {
        if (sig == null || sig.isEmpty()) return null;
        Matcher m = Pattern.compile("L([^;<:]+)").matcher(sig);
        StringBuffer out = new StringBuffer();
        while (m.find()) {
            String rawInternal = m.group(1);
            String raw = rawInternal.replace('/', '.');
            String shadow = rawToShadow.getOrDefault(raw, raw);
            m.appendReplacement(out, Matcher.quoteReplacement("L" + shadow.replace('.', '/')));
        }
        m.appendTail(out);
        return out.toString();
    }

    static void runValidate(Opts o) throws Exception {
        if (o.apk==null || !Files.isRegularFile(o.apk)) die("validate requires --apk");
        if (o.shadowJar==null || !Files.isRegularFile(o.shadowJar)) die("validate requires --shadow-jar");
        Map<String,DexReader.Clazz> dex=DexReader.readApk(o.apk);
        List<String> severe=new ArrayList<>();
        int mapped=0, shells=0, fanout=0, unmapped=0, classLinks=0, classCollisions=0, badClassAnchors=0, missingClassLinks=0;
        int aliasLinks=0, missingAliases=0, badAnchors=0;
        int missingRawMembers=0, hierarchyMismatches=0, kindMismatches=0, signatureMismatches=0, throwsMismatches=0;
        int dexSignaturesChecked=0, dexThrowsChecked=0;
        boolean provenanceMissing=false;
        StringBuilder details=new StringBuilder(); details.append("[\n"); boolean first=true;
        Map<String,ClassSurface> surfaces=new LinkedHashMap<>();
        List<String> aliasLines=new ArrayList<>();
        Map<String,String> classMap=new LinkedHashMap<>(); // shadow fqcn -> raw fqcn
        Map<String,String> rawToShadow=new LinkedHashMap<>();
        Set<String> sourceOnlyShells=new LinkedHashSet<>();
        try (java.util.jar.JarFile jar=new java.util.jar.JarFile(o.shadowJar.toFile())) {
            java.util.jar.JarEntry manifest=jar.getJarEntry("META-INF/apk2project-shadow-aliases.tsv");
            if(manifest!=null){
                try(InputStream in=jar.getInputStream(manifest)){aliasLines=Arrays.asList(new String(in.readAllBytes(),StandardCharsets.UTF_8).split("\n"));}
                for(String line:aliasLines){
                    if(line.isBlank()||line.startsWith("#"))continue; String[] q=line.split("\t",-1);
                    if(q.length>=2 && q[0].equals("S")){
                        sourceOnlyShells.add(q[1]);
                        continue;
                    }
                    if(q.length>=3 && q[0].equals("C")){
                        classLinks++;
                        String previousRaw = classMap.putIfAbsent(q[1], q[2]);
                        if(previousRaw != null && !previousRaw.equals(q[2])) {
                            classCollisions++;
                            severe.add("shadow class collision "+q[1]+" <- ["+previousRaw+", "+q[2]+"]");
                        }
                        String previousShadow = rawToShadow.putIfAbsent(q[2], q[1]);
                        if(previousShadow != null && !previousShadow.equals(q[1])) {
                            classCollisions++;
                            severe.add("raw class mapped to multiple shadow owners "+q[2]+" -> ["+previousShadow+", "+q[1]+"]");
                        }
                        if(!dex.containsKey(q[2])){badClassAnchors++;severe.add("bad class anchor "+q[1]+" -> "+q[2]);}
                    }
                }
            }
            var en=jar.entries();
            while(en.hasMoreElements()){
                java.util.jar.JarEntry je=en.nextElement(); if(je.isDirectory()||!je.getName().endsWith(".class"))continue;
                byte[] bytes; try(InputStream in=jar.getInputStream(je)){bytes=in.readAllBytes();}
                ClassSurface sf=classSurface(bytes); String source=sf.internal.replace('/','.'); surfaces.put(source,sf);
            }
        }

        // Backward-compatible forensic mode for pre-v27 jars that do not contain
        // provenance tables. We still compute useful DEX-vs-classfile diagnostics,
        // but such a jar can never pass the promotion gate because its anchors are
        // unverifiable.
        if(classMap.isEmpty() && !surfaces.isEmpty()){
            provenanceMissing=true;
            for(String source:surfaces.keySet()){
                String raw=dex.containsKey(source)?source:sourceToRawFqcn(source);
                if(dex.containsKey(raw)){classMap.put(source,raw);rawToShadow.put(raw,source);}
            }
        }

        for(var e:classMap.entrySet()){
            String source=e.getKey(), raw=e.getValue(); ClassSurface sf=surfaces.get(source); DexReader.Clazz dc=dex.get(raw);
            if(dc==null) continue;
            if(sf==null){missingClassLinks++;severe.add("class provenance missing from jar "+source+" -> "+raw);continue;}
            mapped++;
            int rf=dc.fields.size(), rm=dc.methods.size();
            boolean shell=(rf+rm>=8 && sf.fields+sf.methods<=2);
            boolean overF=sf.fields>Math.max(rf*4,rf+64), overM=sf.methods>Math.max(rm*4,rm+64);
            if(shell){shells++;severe.add(source+" -> "+raw+" shell "+sf.fields+"/"+sf.methods+" vs dex "+rf+"/"+rm);}
            if(overF||overM){fanout++;severe.add(source+" -> "+raw+" fanout "+sf.fields+"/"+sf.methods+" vs dex "+rf+"/"+rm);}

            // Exact raw ABI coverage. Synthetic JADX aliases are allowed in addition,
            // but the original DEX surface must always remain addressable under the
            // descriptor-remapped shadow namespace.
            int missingHere=0;
            for(DexReader.Field f:dc.fields){
                if(!javaIdentifier(f.name)) continue;
                String sd=remapDexDescriptor(f.desc,rawToShadow), key=f.name+":"+sd;
                if(!sf.fieldKeys.contains(key)){missingRawMembers++;missingHere++;severe.add("missing raw field "+source+"."+key+" from "+raw+"."+f.name+":"+f.desc);}
                if(f.signature!=null){
                    dexSignaturesChecked++;
                    String expected=remapDexSignature(f.signature,rawToShadow), actual=sf.fieldSignatures.get(key);
                    if(!Objects.equals(expected,actual)){signatureMismatches++;severe.add("field signature mismatch "+source+"."+key+" expected="+expected+" actual="+actual);}
                }
            }
            for(DexReader.Method m:dc.methods){
                if(!(m.name.equals("<init>")||m.name.equals("<clinit>")||javaIdentifier(m.name))) continue;
                String sd=remapDexDescriptor(m.desc,rawToShadow), key=m.name+sd;
                if(!sf.methodKeys.contains(key)){missingRawMembers++;missingHere++;severe.add("missing raw method "+source+"."+key+" from "+raw+"."+m.name+m.desc);}
                if(m.signature!=null){
                    dexSignaturesChecked++;
                    String expected=remapDexSignature(m.signature,rawToShadow), actual=sf.methodSignatures.get(key);
                    if(!Objects.equals(expected,actual)){signatureMismatches++;severe.add("method signature mismatch "+source+"."+key+" expected="+expected+" actual="+actual);}
                }
                if(!m.exceptions.isEmpty()){
                    dexThrowsChecked++;
                    Set<String> expected=m.exceptions.stream().map(x->descriptorObjectInternalMapped(x,rawToShadow)).filter(Objects::nonNull).collect(Collectors.toCollection(LinkedHashSet::new));
                    Set<String> actual=sf.methodExceptions.getOrDefault(key,Set.of());
                    if(!expected.equals(actual)){throwsMismatches++;severe.add("throws mismatch "+source+"."+key+" expected="+expected+" actual="+actual);}
                }
            }

            String expectedSuper=((dc.access&0x200)!=0)?"java/lang/Object":descriptorObjectInternalMapped(dc.superDesc,rawToShadow);
            if(expectedSuper==null) expectedSuper="java/lang/Object";
            Set<String> expectedIfaces=dc.interfaces.stream().map(x->descriptorObjectInternalMapped(x,rawToShadow)).filter(Objects::nonNull).collect(Collectors.toCollection(LinkedHashSet::new));
            boolean hierarchyBad=!Objects.equals(expectedSuper,sf.superInternal)||!expectedIfaces.equals(sf.interfaces);
            if(hierarchyBad){hierarchyMismatches++;severe.add("hierarchy mismatch "+source+" expected super="+expectedSuper+" ifaces="+expectedIfaces+" actual super="+sf.superInternal+" ifaces="+sf.interfaces);}
            boolean expectedInterface=(dc.access&0x200)!=0, actualInterface=(sf.access&Opcodes.ACC_INTERFACE)!=0;
            boolean expectedAnnotation=(dc.access&0x2000)!=0, actualAnnotation=(sf.access&Opcodes.ACC_ANNOTATION)!=0;
            boolean expectedEnum=(dc.access&0x4000)!=0, actualEnum=(sf.access&Opcodes.ACC_ENUM)!=0;
            if(expectedInterface!=actualInterface||expectedAnnotation!=actualAnnotation||expectedEnum!=actualEnum){
                kindMismatches++; severe.add("class kind mismatch "+source+" raw="+raw+" interface="+expectedInterface+"/"+actualInterface+" annotation="+expectedAnnotation+"/"+actualAnnotation+" enum="+expectedEnum+"/"+actualEnum);
            }
            if(dc.signature!=null){
                dexSignaturesChecked++;
                String expected=remapDexSignature(dc.signature,rawToShadow);
                if(!Objects.equals(expected,sf.signature)){signatureMismatches++;severe.add("class signature mismatch "+source+" expected="+expected+" actual="+sf.signature);}
            }

            if(shell||overF||overM||missingHere>0||hierarchyBad){
                if(!first)details.append(",\n");first=false;
                details.append("  {\"source\":").append(json(source)).append(",\"raw\":").append(json(raw))
                       .append(",\"shadow_fields\":").append(sf.fields).append(",\"shadow_methods\":").append(sf.methods)
                       .append(",\"dex_fields\":").append(rf).append(",\"dex_methods\":").append(rm)
                       .append(",\"shell\":").append(shell).append(",\"fanout\":").append(overF||overM)
                       .append(",\"missing_raw_members\":").append(missingHere).append(",\"hierarchy_mismatch\":").append(hierarchyBad).append("}");
            }
        }
        for(String source:surfaces.keySet()) if(!classMap.containsKey(source) && !sourceOnlyShells.contains(source)) unmapped++;
        int missingSourceOnlyShells=0;
        for(String source:sourceOnlyShells) if(!surfaces.containsKey(source)){missingSourceOnlyShells++;severe.add("declared source-only shell missing from jar "+source);}

        for(String line:aliasLines){
            if(line.isBlank()||line.startsWith("#"))continue; String[] q=line.split("\t",-1); if(q.length<7||q[0].equals("C")||q[0].equals("S"))continue; aliasLinks++;
            String kind=q[0], shadowOwner=q[1], rawOwner=q[2], rawName=q[3], rawDesc=q[4], alias=q[5], shadowDesc=q[6];
            DexReader.Clazz dc=dex.get(rawOwner); boolean anchor=false;
            if(dc!=null) anchor=kind.equals("F") ? dc.fields.stream().anyMatch(f->f.name.equals(rawName)&&f.desc.equals(rawDesc))
                                                  : kind.equals("M") && dc.methods.stream().anyMatch(m->m.name.equals(rawName)&&m.desc.equals(rawDesc));
            if(!anchor){badAnchors++;severe.add("bad alias anchor "+shadowOwner+"."+alias+" -> "+rawOwner+"."+rawName+rawDesc);continue;}
            ClassSurface sf=surfaces.get(shadowOwner); boolean present=sf!=null && (kind.equals("F") ? sf.fieldKeys.contains(alias+":"+shadowDesc) : sf.methodKeys.contains(alias+shadowDesc));
            if(!present){missingAliases++;severe.add("missing emitted alias "+shadowOwner+"."+alias+shadowDesc+" anchored at "+rawOwner+"."+rawName+rawDesc);}
        }
        details.append("\n]");
        String out="{\n  \"mapped_classes\": "+mapped+",\n  \"unmapped_classes\": "+unmapped+",\n  \"class_links\": "+classLinks+",\n  \"class_collisions\": "+classCollisions+",\n  \"bad_class_anchors\": "+badClassAnchors+",\n  \"missing_class_links\": "+missingClassLinks+",\n  \"shell_failures\": "+shells+",\n  \"fanout_failures\": "+fanout+",\n  \"missing_raw_members\": "+missingRawMembers+",\n  \"hierarchy_mismatches\": "+hierarchyMismatches+",\n  \"kind_mismatches\": "+kindMismatches+",\n  \"signature_mismatches\": "+signatureMismatches+",\n  \"throws_mismatches\": "+throwsMismatches+",\n  \"dex_signatures_checked\": "+dexSignaturesChecked+",\n  \"dex_throws_checked\": "+dexThrowsChecked+",\n  \"provenance_missing\": "+provenanceMissing+",\n  \"source_only_shells\": "+sourceOnlyShells.size()+",\n  \"missing_source_only_shells\": "+missingSourceOnlyShells+",\n  \"alias_links\": "+aliasLinks+",\n  \"bad_alias_anchors\": "+badAnchors+",\n  \"missing_aliases\": "+missingAliases+",\n  \"severe\": "+jsonArray(severe)+",\n  \"details\": "+details+"\n}\n";
        if(o.report!=null){Files.createDirectories(o.report.getParent());Files.writeString(o.report,out);} else System.out.print(out);
        log("shadow validation: mapped="+mapped+", classes="+classLinks+", sourceOnly="+sourceOnlyShells.size()+", collisions="+classCollisions+", shells="+shells+", fanout="+fanout+", missingRaw="+missingRawMembers+", hierarchy="+hierarchyMismatches+", kind="+kindMismatches+", signatures="+signatureMismatches+"/"+dexSignaturesChecked+", throws="+throwsMismatches+"/"+dexThrowsChecked+", provenanceMissing="+provenanceMissing+", aliases="+aliasLinks+", badClassAnchors="+badClassAnchors+", missingClassLinks="+missingClassLinks+", badAnchors="+badAnchors+", missingAliases="+missingAliases+", unmapped="+unmapped);
        boolean provenanceRequiresExactCoverage=classLinks>0;
        if(provenanceMissing||classCollisions>0||shells>0||fanout>0||missingRawMembers>0||hierarchyMismatches>0||kindMismatches>0||signatureMismatches>0||throwsMismatches>0||badClassAnchors>0||missingClassLinks>0||badAnchors>0||missingAliases>0||missingSourceOnlyShells>0||(provenanceRequiresExactCoverage&&unmapped>0)) System.exit(3);
    }


    static ClassSurface classSurface(byte[] bytes) {
        ClassSurface s=new ClassSurface(); ClassReader cr=new ClassReader(bytes);
        cr.accept(new ClassVisitor(Opcodes.ASM8){
            @Override public void visit(int version,int access,String name,String signature,String superName,String[] interfaces){
                s.internal=name;s.access=access;s.superInternal=superName;s.signature=signature;
                if(interfaces!=null)Collections.addAll(s.interfaces,interfaces);
            }
            @Override public FieldVisitor visitField(int access,String name,String desc,String sig,Object value){
                s.fields++;String key=name+":"+desc;s.fieldKeys.add(key);if(sig!=null)s.fieldSignatures.put(key,sig);return null;
            }
            @Override public MethodVisitor visitMethod(int access,String name,String desc,String sig,String[] ex){
                s.methods++;String key=name+desc;s.methodKeys.add(key);if(sig!=null)s.methodSignatures.put(key,sig);
                LinkedHashSet<String> xs=new LinkedHashSet<>();if(ex!=null)Collections.addAll(xs,ex);s.methodExceptions.put(key,xs);return null;
            }
        },ClassReader.SKIP_CODE|ClassReader.SKIP_DEBUG|ClassReader.SKIP_FRAMES); return s;
    }


    // ---------------------------------------------------------------- v27.2 decompiler-source normalization

    static final Pattern JADX_TYPE_INFERENCE_WARN = Pattern.compile(
            "/\\*\\s*JADX WARN:\\s*Type inference failed for:\\s*(r\\d+)v(\\d+)"
          + "(?:,\\s*types:\\s*\\[([^\\]]*)\\])?\\s*\\*/");

    static final class NormalizeEdit {
        int start, end;
        String replacement, kind, reason;
        NormalizeEdit(int start, int end, String replacement, String kind, String reason) {
            this.start=start; this.end=end; this.replacement=replacement; this.kind=kind; this.reason=reason;
        }
    }

    static final class MethodRange {
        long start, end;
        String name;
        MethodRange(long start,long end,String name){this.start=start;this.end=end;this.name=name;}
    }

    static final class TypeUniverse implements AutoCloseable {
        final Context context = new Context();
        final EngineDiagnostic dl = new EngineDiagnostic();
        final JavacTool tool = JavacTool.create();
        final JavacFileManager fm;
        final JavacTaskImpl task;
        final Types types;
        final com.sun.tools.javac.util.Names names;
        TypeUniverse(Path classpathFile) throws Exception {
            fm = tool.getStandardFileManager(dl, Locale.ROOT, StandardCharsets.UTF_8);
            List<String> opts = new ArrayList<>(List.of("-proc:none", "-Xlint:none"));
            if (classpathFile != null && Files.isRegularFile(classpathFile)) {
                String cp = String.join(File.pathSeparator, Files.readAllLines(classpathFile).stream().filter(x -> !x.isBlank()).toList());
                if (!cp.isBlank()) { opts.add("-classpath"); opts.add(cp); }
            }
            JavaFileObject dummy = new SimpleJavaFileObject(java.net.URI.create("string:///__Apk2ProjectTypeUniverse.java"), JavaFileObject.Kind.SOURCE) {
                @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) { return "final class __Apk2ProjectTypeUniverse {}"; }
            };
            task = (JavacTaskImpl) tool.getTask(null, fm, dl, opts, null, List.of(dummy), context);
            Iterable<? extends CompilationUnitTree> parsed = task.parse();
            task.enter(parsed);
            try { task.analyze(); } catch (Throwable ignored) { }
            types = Types.instance(context);
            names = com.sun.tools.javac.util.Names.instance(context);
        }
        Type resolve(String text) {
            if (text == null) return null;
            String n = eraseSourceType(text.trim());
            if (n.isEmpty() || n.equals("?") || n.equals("null")) return null;
            try {
                var el = task.getElements().getTypeElement(n);
                return el == null ? null : (Type)el.asType();
            } catch (Throwable ignored) { return null; }
        }
        String leastUpperBound(Collection<String> namesIn) {
            ArrayList<Type> ts = new ArrayList<>();
            for (String n : namesIn) { Type t=resolve(n); if(t!=null) ts.add(t); }
            if (ts.isEmpty()) return null;
            Type lub;
            try { lub = ts.size()==1 ? ts.get(0) : types.lub(com.sun.tools.javac.util.List.from(ts)); }
            catch (Throwable ex) { return null; }
            if (lub == null || lub.isErroneous()) return null;
            // Intersection LUBs are legal in casts but not useful as ordinary local
            // declarations. Prefer a concrete/interface constituent that accepts all
            // observed candidates.
            boolean allRaw = namesIn.stream().noneMatch(x -> x != null && x.indexOf('<') >= 0);
            if (allRaw) {
                try { lub = types.erasure(lub); } catch (Throwable ignored) { }
            }
            String rendered = lub.toString();
            if (rendered.contains("&")) {
                for (String n : namesIn) {
                    Type c=resolve(n); if(c==null) continue;
                    boolean all=true;
                    for(Type x:ts) try { if(!types.isAssignable(x,c)){all=false;break;} } catch(Throwable t){all=false;break;}
                    if(all) return c.toString();
                }
                return null;
            }
            return rendered;
        }
        boolean hasMember(String typeName, String member) {
            Type t=resolve(typeName); if(t==null) return false;
            try {
                for (Symbol s : types.membersClosure(t, false).getSymbolsByName(names.fromString(member))) return true;
            } catch (Throwable ignored) { }
            return false;
        }
        @Override public void close() throws Exception { fm.close(); }
    }

    static String eraseSourceType(String t) {
        t=t.trim();
        while(t.endsWith("[]")) t=t.substring(0,t.length()-2).trim();
        StringBuilder b=new StringBuilder(); int depth=0;
        for(char c:t.toCharArray()) {
            if(c=='<'){depth++;continue;} if(c=='>'){if(depth>0)depth--;continue;}
            if(depth==0)b.append(c);
        }
        return b.toString().replace("? extends ","").replace("? super ","").trim();
    }

    static List<String> splitTypeList(String raw) {
        ArrayList<String> out=new ArrayList<>(); if(raw==null||raw.isBlank()) return out;
        StringBuilder b=new StringBuilder(); int depth=0;
        for(char c:raw.toCharArray()) {
            if(c=='<')depth++; else if(c=='>')depth=Math.max(0,depth-1);
            if(c==','&&depth==0){String x=b.toString().trim();if(!x.isEmpty())out.add(x);b.setLength(0);} else b.append(c);
        }
        String x=b.toString().trim();if(!x.isEmpty())out.add(x);return out;
    }

    static String sourceFriendlyType(String fq, String source) {
        if(fq==null)return null;
        int dot=fq.lastIndexOf('.'); if(dot<0)return fq;
        String simple=fq.substring(dot+1), pkg=fq.substring(0,dot);
        if(pkg.equals("java.lang"))return simple;
        if(Pattern.compile("(?m)^\\s*import\\s+"+Pattern.quote(fq)+"\\s*;").matcher(source).find())return simple;
        if(Pattern.compile("(?m)^\\s*import\\s+"+Pattern.quote(pkg)+"\\.\\*\\s*;").matcher(source).find())return simple;
        return fq;
    }

    static String jsonNormalizeRecord(Path file,String kind,String register,String inferred,String reason,boolean applied,int known,int unknown) {
        return "{\"kind\":"+json(kind)+",\"file\":"+json(file.toString())+",\"register\":"+json(register)
                +",\"inferred\":"+json(inferred)+",\"reason\":"+json(reason)+",\"applied\":"+applied
                +",\"knownVersions\":"+known+",\"unknownVersions\":"+unknown+"}";
    }

    static List<MethodRange> methodRanges(CompilationUnitTree unit, SourcePositions sp) {
        ArrayList<MethodRange> out=new ArrayList<>();
        new TreePathScanner<Void,Void>() {
            @Override public Void visitMethod(MethodTree n,Void p){long a=sp.getStartPosition(unit,n),b=sp.getEndPosition(unit,n);if(a>=0&&b>=a)out.add(new MethodRange(a,b,n.getName().toString()));return super.visitMethod(n,p);}
        }.scan(unit,null); return out;
    }

    static MethodRange containingMethod(List<MethodRange> rs,long pos) {
        MethodRange best=null; long span=Long.MAX_VALUE;
        for(MethodRange r:rs) if(r.start<=pos&&pos<=r.end&&r.end-r.start<span){best=r;span=r.end-r.start;}
        return best;
    }

    static int expandAssignmentSemicolon(String source,int end,int blockEnd) {
        int p=end; while(p<blockEnd&&p<source.length()&&Character.isWhitespace(source.charAt(p)))p++;
        if(p<blockEnd&&p<source.length()&&source.charAt(p)==';')p++;
        return p;
    }

    /**
     * Convert the common JADX reconstruction of an interface <clinit>:
     *
     *   interface X { T A; static { A = expr; } }
     *
     * into legal Java source:
     *
     *   interface X { T A = expr; }
     *
     * We only perform this when the static block consists exclusively of one simple
     * assignment per previously-uninitialized interface field.  Complex control flow
     * is deliberately left untouched rather than deleting executable initialization.
     */
    static List<NormalizeEdit> interfaceClinitEdits(Path file,String source,CompilationUnitTree unit,SourcePositions sp,List<String> report) {
        ArrayList<NormalizeEdit> edits=new ArrayList<>();
        new TreePathScanner<Void,Void>() {
            @Override public Void visitClass(ClassTree ct,Void p) {
                if(!(ct.getKind()==Tree.Kind.INTERFACE||ct.getKind()==Tree.Kind.ANNOTATION_TYPE)) return super.visitClass(ct,p);
                LinkedHashMap<String,VariableTree> fields=new LinkedHashMap<>();
                for(Tree m:ct.getMembers()) if(m instanceof VariableTree v) fields.put(v.getName().toString(),v);
                for(Tree m:ct.getMembers()) {
                    if(!(m instanceof BlockTree bt)||!bt.isStatic())continue;
                    long bs=sp.getStartPosition(unit,bt),be=sp.getEndPosition(unit,bt); if(bs<0||be<=bs)continue;
                    LinkedHashMap<String,AssignmentTree> assigns=new LinkedHashMap<>(); boolean safe=true;
                    for(StatementTree st:bt.getStatements()) {
                        if(!(st instanceof ExpressionStatementTree es)||!(es.getExpression() instanceof AssignmentTree at)){safe=false;break;}
                        String lhs;
                        if(at.getVariable() instanceof IdentifierTree id) lhs=id.getName().toString();
                        else if(at.getVariable() instanceof MemberSelectTree ms && ms.getExpression().toString().equals(ct.getSimpleName().toString())) lhs=ms.getIdentifier().toString();
                        else {safe=false;break;}
                        VariableTree fv=fields.get(lhs);
                        if(fv==null||fv.getInitializer()!=null||assigns.put(lhs,at)!=null){safe=false;break;}
                    }
                    if(!safe||assigns.isEmpty()) {
                        report.add(jsonNormalizeRecord(file,"interface-clinit-unsupported","","","static block has control flow/non-field assignments; preserved for later binary/source decision",false,0,0));
                        continue;
                    }
                    for(var e:assigns.entrySet()) {
                        VariableTree fv=fields.get(e.getKey()); AssignmentTree at=e.getValue();
                        long fs=sp.getStartPosition(unit,fv),fe=sp.getEndPosition(unit,fv),rs=sp.getStartPosition(unit,at.getExpression()),re=sp.getEndPosition(unit,at.getExpression());
                        if(fs<0||fe<=fs||rs<0||re<=rs){safe=false;break;}
                        int semi=source.lastIndexOf(';',(int)fe-1); if(semi<(int)fs){safe=false;break;}
                        String rhs=source.substring((int)rs,(int)re);
                        edits.add(new NormalizeEdit(semi,semi," = "+rhs,"interface-clinit-field-initializer","move <clinit> assignment for "+e.getKey()+" into legal interface field initializer"));
                    }
                    if(safe) {
                        edits.add(new NormalizeEdit((int)bs,(int)be,"","remove-interface-clinit-block","all assignments were transferred to interface field initializers"));
                        report.add(jsonNormalizeRecord(file,"interface-clinit-legalized","","","simple DEX/JVM <clinit> reconstructed as legal field initializers",true,assigns.size(),0));
                    }
                }
                return super.visitClass(ct,p);
            }
        }.scan(unit,null);
        return edits;
    }

    static List<NormalizeEdit> ssaTypeInferenceEdits(Path file,String source,CompilationUnitTree unit,SourcePositions sp,TypeUniverse tu,List<String> report) {
        ArrayList<NormalizeEdit> edits=new ArrayList<>(); List<MethodRange> methods=methodRanges(unit,sp);
        record W(String reg,int ver,long pos,List<String> types,MethodRange method){}
        ArrayList<W> ws=new ArrayList<>(); Matcher m=JADX_TYPE_INFERENCE_WARN.matcher(source);
        while(m.find()) ws.add(new W(m.group(1),Integer.parseInt(m.group(2)),m.start(),splitTypeList(m.group(3)),containingMethod(methods,m.start())));
        Map<String,List<W>> groups=new LinkedHashMap<>();
        for(W w:ws){String scope=w.method()==null?"file":Long.toString(w.method().start);groups.computeIfAbsent(scope+"#"+w.reg(),k->new ArrayList<>()).add(w);}
        for(List<W> g:groups.values()) {
            String reg=g.get(0).reg(); LinkedHashSet<String> known=new LinkedHashSet<>();int unknown=0,knownVersions=0;
            for(W w:g){if(w.types().isEmpty())unknown++;else { knownVersions++; known.addAll(w.types()); }}
            if(known.isEmpty())continue; String lub=tu.leastUpperBound(known);
            if(lub==null||eraseSourceType(lub).equals("java.lang.Object")) {
                report.add(jsonNormalizeRecord(file,"jadx-ssa-lub",reg,lub==null?"":lub,"no useful non-Object common type",false,knownVersions,unknown));continue;
            }
            MethodRange mr=g.get(0).method(); int a=mr==null?0:(int)mr.start,b=mr==null?source.length():(int)mr.end;
            String region=source.substring(a,b);
            Matcher uses=Pattern.compile("\\b"+Pattern.quote(reg)+"\\s*\\.\\s*([A-Za-z_$][\\w$]*)").matcher(region); boolean memberOk=true;String bad="";
            while(uses.find()){String mem=uses.group(1);if(!tu.hasMember(lub,mem)){memberOk=false;bad=mem;break;}}
            if(!memberOk){report.add(jsonNormalizeRecord(file,"jadx-ssa-lub",reg,lub,"candidate lacks observed member "+bad,false,knownVersions,unknown));continue;}
            // Invalid JADX placeholder declaration.
            Matcher q=Pattern.compile("\\?\\?\\s+"+Pattern.quote(reg)+"\\b").matcher(region);
            if(q.find()) {
                String rep=sourceFriendlyType(lub,source);int s=a+q.start(),e=s+2;
                edits.add(new NormalizeEdit(s,e,rep,"jadx-ssa-lub-type","known SSA versions " + known + " => javac Types.lub="+lub+"; "+unknown+" unknown version(s) are non-vetoing"));
                report.add(jsonNormalizeRecord(file,"jadx-ssa-lub",reg,lub,"replace JADX ?? declaration from common javac type",true,knownVersions,unknown));continue;
            }
            // Legal but over-specific/Object declaration.  Only widen/specialize a
            // declaration if its current type is itself one of the observed candidates
            // (or Object) and all receiver-member uses exist on the LUB.
            Matcher d=Pattern.compile("(?<![\\w$.])([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*)\\s+"+Pattern.quote(reg)+"\\b").matcher(region);
            if(d.find()) {
                String old=d.group(1);String oldErased=eraseSourceType(old);boolean observed=oldErased.equals("Object")||oldErased.equals("java.lang.Object");
                for(String k:known){String ek=eraseSourceType(k);if(ek.equals(oldErased)||ek.endsWith("."+oldErased))observed=true;}
                if(observed && !eraseSourceType(lub).equals(oldErased) && !eraseSourceType(lub).endsWith("."+oldErased)) {
                    String rep=sourceFriendlyType(lub,source);int s=a+d.start(1),e=a+d.end(1);
                    edits.add(new NormalizeEdit(s,e,rep,"jadx-ssa-lub-type","known SSA versions " + known + " => javac Types.lub="+lub+"; source member-use constraints validated"));
                    report.add(jsonNormalizeRecord(file,"jadx-ssa-lub",reg,lub,"replace over-specific/Object register declaration",true,knownVersions,unknown));continue;
                }
            }
            report.add(jsonNormalizeRecord(file,"jadx-ssa-lub",reg,lub,"common type inferred but no safe rN declaration target was found",false,knownVersions,unknown));
        }
        return edits;
    }

    static String applyNormalizeEdits(String source,List<NormalizeEdit> edits) {
        // Deduplicate and reject overlaps; later source offsets are applied first.
        LinkedHashMap<String,NormalizeEdit> uniq=new LinkedHashMap<>();
        for(NormalizeEdit e:edits)uniq.put(e.start+":"+e.end+":"+e.replacement,e);
        ArrayList<NormalizeEdit> xs=new ArrayList<>(uniq.values());xs.sort(Comparator.comparingInt((NormalizeEdit e)->e.start).reversed());
        int previousStart=Integer.MAX_VALUE; String out=source;
        for(NormalizeEdit e:xs){if(e.start<0||e.end<e.start||e.end>out.length())continue;if(e.end>previousStart)continue;out=out.substring(0,e.start)+e.replacement+out.substring(e.end);previousStart=e.start;}
        return out;
    }

    static void runNormalize(Opts o) throws Exception {
        Set<String> excluded=new HashSet<>();
        if(o.sourceList!=null&&Files.isRegularFile(o.sourceList))for(String x:Files.readAllLines(o.sourceList))if(!x.isBlank())excluded.add(x.trim().replace('\\','/'));
        ArrayList<Path> files=new ArrayList<>();try(var st=Files.walk(o.javaRoot)){for(Path p:st.filter(x->x.toString().endsWith(".java")).sorted().toList()){String rel=o.javaRoot.relativize(p).toString().replace(File.separatorChar,'/');if(!excluded.contains(rel))files.add(p);}}
        ArrayList<String> report=new ArrayList<>();int changed=0,editsCount=0;
        Path backupRoot=(o.report==null?o.javaRoot.resolveSibling("java-normalize-backups"):o.report.getParent().resolve("normalize-backups"));
        try(TypeUniverse tu=new TypeUniverse(o.classpathFile)) {
            for(Path file:files) {
                String source=Files.readString(file,StandardCharsets.UTF_8);
                JavacTool tool=JavacTool.create();Context cx=new Context();EngineDiagnostic dl=new EngineDiagnostic();JavacFileManager fm=tool.getStandardFileManager(dl,Locale.ROOT,StandardCharsets.UTF_8);
                Iterable<? extends JavaFileObject> fos=fm.getJavaFileObjectsFromPaths(List.of(file));
                JavacTaskImpl task=(JavacTaskImpl)tool.getTask(null,fm,dl,List.of("-proc:none","-Xlint:none"),null,fos,cx);
                Iterable<? extends CompilationUnitTree> parsed=task.parse();Trees trees=Trees.instance(task);SourcePositions sp=trees.getSourcePositions();
                ArrayList<NormalizeEdit> edits=new ArrayList<>();
                for(CompilationUnitTree unit:parsed){edits.addAll(interfaceClinitEdits(file,source,unit,sp,report));edits.addAll(ssaTypeInferenceEdits(file,source,unit,sp,tu,report));}
                fm.close();if(edits.isEmpty())continue;String updated=applyNormalizeEdits(source,edits);if(updated.equals(source))continue;
                Path rel=o.javaRoot.relativize(file),backup=backupRoot.resolve(rel);Files.createDirectories(backup.getParent());if(!Files.exists(backup))Files.writeString(backup,source,StandardCharsets.UTF_8);
                Files.writeString(file,updated,StandardCharsets.UTF_8);changed++;editsCount+=edits.size();
                for(NormalizeEdit e:edits)report.add("{\"kind\":\"edit\",\"file\":"+json(file.toString())+",\"editKind\":"+json(e.kind)+",\"start\":"+e.start+",\"end\":"+e.end+",\"reason\":"+json(e.reason)+"}");
            }
        }
        if(o.report!=null){Files.createDirectories(o.report.getParent());Files.write(o.report,report,StandardCharsets.UTF_8);}
        log("source normalize: filesChanged="+changed+", edits="+editsCount+", report="+(o.report==null?"<stdout>":o.report));
        if(o.report==null)for(String x:report)System.out.println(x);
    }

    // ---------------------------------------------------------------- rich javac attribution diagnostics

    static JCDiagnostic unwrapDiagnostic(Diagnostic<? extends JavaFileObject> d) {
        if (d instanceof DiagnosticSourceUnwrapper u) return u.d;
        if (d instanceof JCDiagnostic jd) return jd;
        return null;
    }

    static String diagnosticArgJson(Object x, int depth) {
        if (x == null) return "null";
        if (depth > 6) return "{\"class\":" + json(x.getClass().getName()) + ",\"text\":" + json(String.valueOf(x)) + "}";
        if (x instanceof JCDiagnostic jd) {
            return "{\"class\":" + json(x.getClass().getName()) + ",\"code\":" + json(jd.getCode())
                    + ",\"text\":" + json(jd.getMessage(Locale.ROOT)) + ",\"args\":" + diagnosticArgsJson(jd.getArgs(), depth + 1) + "}";
        }
        if (x instanceof Type t) {
            Symbol ts = t.tsym;
            return "{\"class\":" + json(x.getClass().getName()) + ",\"kind\":\"type\",\"text\":" + json(t.toString())
                    + ",\"symbol\":" + json(ts == null ? "" : ts.getQualifiedName().toString()) + "}";
        }
        if (x instanceof Symbol sy) {
            return "{\"class\":" + json(x.getClass().getName()) + ",\"kind\":\"symbol\",\"text\":" + json(sy.toString())
                    + ",\"name\":" + json(sy.getSimpleName().toString()) + ",\"owner\":" + json(sy.owner == null ? "" : sy.owner.getQualifiedName().toString())
                    + ",\"type\":" + json(sy.type == null ? "" : sy.type.toString()) + "}";
        }
        if (x instanceof Iterable<?> it) {
            StringBuilder b = new StringBuilder("["); boolean first = true; int n = 0;
            for (Object y : it) { if (n++ > 100) break; if (!first) b.append(','); first = false; b.append(diagnosticArgJson(y, depth + 1)); }
            return b.append(']').toString();
        }
        return "{\"class\":" + json(x.getClass().getName()) + ",\"text\":" + json(String.valueOf(x)) + "}";
    }

    static String diagnosticArgsJson(Object[] args, int depth) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < args.length; i++) { if (i > 0) b.append(','); b.append(diagnosticArgJson(args[i], depth)); }
        return b.append(']').toString();
    }

    static void collectDiagnosticTypes(Object x, List<Type> out, int depth) {
        if (x == null || depth > 8) return;
        if (x instanceof Type t) { out.add(t); return; }
        if (x instanceof JCDiagnostic jd) { for (Object a : jd.getArgs()) collectDiagnosticTypes(a, out, depth + 1); return; }
        if (x instanceof Iterable<?> it) { for (Object a : it) collectDiagnosticTypes(a, out, depth + 1); }
    }

    static String diagnosticSemanticJson(JCDiagnostic raw, Types types) {
        if (raw == null) return "{}";
        List<Type> ts = new ArrayList<>();
        collectDiagnosticTypes(raw, ts, 0);
        if (raw.getCode().equals("compiler.err.prob.found.req") && ts.size() >= 2) {
            Type found = ts.get(0), required = ts.get(1);
            boolean convertible = false, castable = false, subtype = false, same = false;
            String lub = "";
            try { convertible = types.isConvertible(found, required); } catch (Throwable ignored) { }
            try { castable = types.isCastable(found, required); } catch (Throwable ignored) { }
            try { subtype = types.isSubtype(found, required); } catch (Throwable ignored) { }
            try { same = types.isSameType(found, required); } catch (Throwable ignored) { }
            try { lub = types.lub(found, required).toString(); } catch (Throwable ignored) { }
            return "{\"family\":\"found-required\",\"found\":" + json(found.toString())
                    + ",\"required\":" + json(required.toString())
                    + ",\"convertible\":" + convertible + ",\"castable\":" + castable
                    + ",\"subtype\":" + subtype + ",\"sameType\":" + same + ",\"lub\":" + json(lub) + "}";
        }
        return "{}";
    }

    static JCTree nearestAttributedTree(CompilationUnitTree unit, long pos, SourcePositions positions) {
        if (pos < 0) return null;
        final JCTree[] best = {null}; final long[] bestSpan = {Long.MAX_VALUE};
        new TreePathScanner<Void, Void>() {
            @Override public Void scan(Tree tree, Void p) {
                if (tree == null) return null;
                long s = positions.getStartPosition(unit, tree), e = positions.getEndPosition(unit, tree);
                if (s >= 0 && e >= s && s <= pos && pos <= e) {
                    long span = e - s;
                    if (span < bestSpan[0] && tree instanceof JCTree jt) { best[0] = jt; bestSpan[0] = span; }
                    return super.scan(tree, p);
                }
                return null;
            }
        }.scan(unit, null);
        return best[0];
    }

    static void runAnalyze(Opts o) throws Exception {
        SourceIndex src = scanSources(o);
        List<Path> files = new ArrayList<>();
        if (o.sourceList != null && Files.isRegularFile(o.sourceList)) {
            // source-list in shadow mode contains binary-owned sources. Analyze the complement.
            Set<String> excluded = new HashSet<>(Files.readAllLines(o.sourceList));
            try (var st = Files.walk(o.javaRoot)) {
                for (Path p : st.filter(x -> x.toString().endsWith(".java")).sorted().toList()) {
                    String rel = o.javaRoot.relativize(p).toString().replace(File.separatorChar, '/');
                    if (!excluded.contains(rel)) files.add(p);
                }
            }
        } else {
            for (var e : src.byFile.entrySet()) if (e.getValue().stream().anyMatch(t -> t.appOwned)) files.add(e.getKey());
        }
        if (files.isEmpty()) { log("analyze: no app-owned source files"); return; }

        JavacTool tool = JavacTool.create(); Context context = new Context(); EngineDiagnostic dl = new EngineDiagnostic();
        JavacFileManager fm = tool.getStandardFileManager(dl, Locale.ROOT, StandardCharsets.UTF_8);
        List<String> opts = new ArrayList<>(List.of("-proc:none", "-Xlint:none", "-Xmaxerrs", "10000"));
        if (o.classpathFile != null && Files.isRegularFile(o.classpathFile)) {
            String cp = String.join(File.pathSeparator, Files.readAllLines(o.classpathFile).stream().filter(x -> !x.isBlank()).toList());
            if (!cp.isBlank()) { opts.add("-classpath"); opts.add(cp); }
        }
        Iterable<? extends JavaFileObject> fos = fm.getJavaFileObjectsFromPaths(files);
        JavacTaskImpl task = (JavacTaskImpl) tool.getTask(null, fm, dl, opts, null, fos, context);
        Iterable<? extends CompilationUnitTree> parsed = task.parse();
        try { task.enter(parsed); task.analyze(); } catch (Throwable ignored) { /* diagnostics are the product */ }
        Types types = Types.instance(context);
        Trees trees = Trees.instance(task);
        SourcePositions sourcePositions = trees.getSourcePositions();
        Map<String, CompilationUnitTree> unitByPath = new LinkedHashMap<>();
        for (CompilationUnitTree u : parsed) {
            try { unitByPath.put(Path.of(u.getSourceFile().toUri()).toAbsolutePath().normalize().toString(), u); } catch (Exception ignored) { }
        }

        for (CompilationUnitTree u : parsed) {
            new TreePathScanner<Void, Void>() {
                @Override public Void visitIdentifier(IdentifierTree node, Void p) { emitTyped(node, u); return super.visitIdentifier(node,p); }
                @Override public Void visitMemberSelect(MemberSelectTree node, Void p) { emitTyped(node, u); return super.visitMemberSelect(node,p); }
                @Override public Void visitMethodInvocation(MethodInvocationTree node, Void p) { emitTyped(node, u); return super.visitMethodInvocation(node,p); }
                void emitTyped(Tree node, CompilationUnitTree unit) {
                    if (!(node instanceof JCTree jt)) return;
                    Symbol sym = TreeInfo.symbol(jt);
                    Type t = jt.type;
                    if (sym == null && (t == null || t.isErroneous())) return;
                    String owner = sym == null || sym.owner == null ? "" : sym.owner.getQualifiedName().toString();
                    String sn = sym == null ? "" : sym.getSimpleName().toString();
                    String st = sym == null || sym.type == null ? "" : sym.type.toString();
                    System.out.println("{\"kind\":\"typed\",\"tree\":" + json(node.getKind().name()) + ",\"text\":" + json(node.toString()) + ",\"type\":" + json(t == null ? "" : t.toString()) + ",\"symbol\":" + json(sn) + ",\"owner\":" + json(owner) + ",\"symbolType\":" + json(st) + "}");
                }
            }.scan(u, null);
        }
        for (Diagnostic<? extends JavaFileObject> d : dl.all) {
            String file = d.getSource() == null ? "" : d.getSource().getName();
            String normalized = file;
            try { normalized = Path.of(d.getSource().toUri()).toAbsolutePath().normalize().toString(); } catch (Exception ignored) { }
            CompilationUnitTree unit = unitByPath.get(normalized);
            JCTree near = unit == null ? null : nearestAttributedTree(unit, d.getPosition(), sourcePositions);
            Symbol nsym = near == null ? null : TreeInfo.symbol(near);
            JCDiagnostic raw = unwrapDiagnostic(d);
            String argsJson = raw == null ? "[]" : diagnosticArgsJson(raw.getArgs(), 0);
            String semanticJson = diagnosticSemanticJson(raw, types);
            System.out.println("{\"kind\":\"diagnostic\",\"severity\":" + json(d.getKind().name()) + ",\"code\":" + json(d.getCode())
                    + ",\"file\":" + json(file) + ",\"line\":" + d.getLineNumber() + ",\"column\":" + d.getColumnNumber() + ",\"position\":" + d.getPosition()
                    + ",\"message\":" + json(d.getMessage(Locale.ROOT))
                    + ",\"nearestTree\":" + json(near == null ? "" : near.getKind().name())
                    + ",\"nearestText\":" + json(near == null ? "" : near.toString())
                    + ",\"nearestType\":" + json(near == null || near.type == null ? "" : near.type.toString())
                    + ",\"nearestSymbol\":" + json(nsym == null ? "" : nsym.toString())
                    + ",\"semantic\":" + semanticJson
                    + ",\"args\":" + argsJson + "}");
        }
        fm.close();
    }

    // ---------------------------------------------------------------- tiny JSON helpers

    static String json(String s) {
        if (s == null) return "null"; StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) switch (c) {
            case '\\' -> b.append("\\\\"); case '"' -> b.append("\\\""); case '\n' -> b.append("\\n"); case '\r' -> b.append("\\r"); case '\t' -> b.append("\\t");
            default -> { if (c < 0x20) b.append(String.format("\\u%04x", (int)c)); else b.append(c); }
        }
        return b.append('"').toString();
    }
    static String jsonArray(Collection<String> xs) { return xs.stream().map(HybridCompiler::json).collect(Collectors.joining(", ", "[", "]")); }
}
