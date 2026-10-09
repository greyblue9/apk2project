package apk2project.javac;

import com.sun.source.tree.*;
import com.sun.source.util.*;
import com.sun.tools.javac.api.BasicJavacTask;
import com.sun.tools.javac.code.*;
import com.sun.tools.javac.code.Symbol.*;
import com.sun.tools.javac.main.JavaCompiler;
import com.sun.tools.javac.comp.CompileStates.CompileState;
import com.sun.tools.javac.tree.JCTree;
import com.sun.tools.javac.tree.JCTree.*;
import com.sun.tools.javac.tree.TreeInfo;
import com.sun.tools.javac.util.*;

import javax.lang.model.element.Element;
import javax.tools.JavaFileObject;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * apk2project compiler probe/repair substrate.
 *
 * Runs INSIDE the real javac invocation used by Gradle, so all diagnostics and
 * types come from javac's actual Context rather than terminal-text parsing.
 * The first version is intentionally read-only: it emits structured compiler
 * state which the repair planner can consume. Later revisions can use TreeMaker
 * and TreeTranslator against the same Context.
 */
public final class RichJavacPlugin implements Plugin {
    public static final String NAME = "Apk2ProjectRich";

    @Override public String getName() { return NAME; }

    @Override public void init(JavacTask task, String... args) {
        if (!(task instanceof BasicJavacTask bt)) {
            System.err.println("[APK2PROJECT-JAVAC] BasicJavacTask unavailable; rich probe disabled");
            return;
        }
        Config cfg = Config.parse(args);
        Context context = bt.getContext();
        JavaCompiler compiler = JavaCompiler.instance(context);
        // Continue through attribution/flow even when earlier recoverable errors exist.
        // This exposes a much fuller diagnostic frontier in one compile.
        compiler.shouldStopPolicyIfError = CompileState.FLOW;
        Probe probe = new Probe(task, context, cfg);
        probe.install();
    }

    static final class Config {
        Path out;
        boolean references = true;
        boolean members = true;
        static Config parse(String[] args) {
            Config c = new Config();
            for (String arg : args) {
                if (arg == null) continue;
                int eq = arg.indexOf('=');
                String k = eq < 0 ? arg : arg.substring(0, eq);
                String v = eq < 0 ? "true" : arg.substring(eq + 1);
                switch (k) {
                    case "out" -> c.out = Paths.get(v).toAbsolutePath();
                    case "references" -> c.references = Boolean.parseBoolean(v);
                    case "members" -> c.members = Boolean.parseBoolean(v);
                }
            }
            if (c.out == null) {
                String env = System.getenv("APK2PROJECT_JAVAC_RICH_OUT");
                c.out = Paths.get(env == null || env.isBlank() ? "analysis/rich-javac.jsonl" : env).toAbsolutePath();
            }
            return c;
        }
    }

    static final class Probe {
        final JavacTask task;
        final Context context;
        final Config cfg;
        final Log log;
        final Types types;
        final Symtab syms;
        final Trees trees;
        final Map<URI, CompilationUnitTree> units = new HashMap<>();
        final AtomicBoolean closed = new AtomicBoolean();
        BufferedWriter out;
        long diagnostics;
        long errors;
        long warnings;

        Probe(JavacTask task, Context context, Config cfg) {
            this.task = task; this.context = context; this.cfg = cfg;
            this.log = Log.instance(context);
            this.types = Types.instance(context);
            this.syms = Symtab.instance(context);
            this.trees = Trees.instance(task);
        }

        void install() {
            try {
                Files.createDirectories(cfg.out.getParent());
                out = Files.newBufferedWriter(cfg.out, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
                emit(mapOf("kind","session","time",Instant.now().toString(),"java",System.getProperty("java.version"),
                        "pid",ProcessHandle.current().pid(),"out",cfg.out.toString()));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            new Log.DiagnosticHandler() {
                { install(log); }
                @Override public void report(JCDiagnostic d) {
                    captureDiagnostic(d);
                    if (prev != null) prev.report(d);
                }
            };

            task.addTaskListener(new TaskListener() {
                @Override public void finished(TaskEvent e) {
                    try {
                        if (e.getKind() == TaskEvent.Kind.PARSE && e.getCompilationUnit() != null) {
                            JavaFileObject sf = e.getCompilationUnit().getSourceFile();
                            if (sf != null) units.put(sf.toUri().normalize(), e.getCompilationUnit());
                        } else if (e.getKind() == TaskEvent.Kind.ANALYZE && e.getTypeElement() != null) {
                            captureAnalyzedType(e);
                        } else if (e.getKind() == TaskEvent.Kind.COMPILATION) {
                            close();
                        }
                    } catch (Throwable t) {
                        safePluginError("task-listener", t);
                    }
                }
            });
            Runtime.getRuntime().addShutdownHook(new Thread(this::close, "apk2project-javac-probe-close"));
        }

        synchronized void captureDiagnostic(JCDiagnostic d) {
            try {
                diagnostics++;
                switch (d.getKind()) {
                    case ERROR -> errors++;
                    case WARNING, MANDATORY_WARNING -> warnings++;
                }
                LinkedHashMap<String,Object> j = new LinkedHashMap<>();
                j.put("kind", "diagnostic");
                j.put("severity", d.getKind().name());
                j.put("code", d.getCode());
                JavaFileObject source = d.getSource();
                j.put("file", source == null ? null : pathOf(source));
                j.put("line", d.getLineNumber());
                j.put("column", d.getColumnNumber());
                j.put("start", d.getStartPosition());
                j.put("position", d.getPosition());
                j.put("end", d.getEndPosition());
                j.put("message", d.getMessage(Locale.ROOT));
                j.put("args", describeArgs(d.getArgs(), 0));

                JCTree tree = d.getDiagnosticPosition() == null ? null : d.getDiagnosticPosition().getTree();
                if (tree != null) {
                    j.put("tree", describeTree(tree));
                    addEnclosing(j, source, tree);
                }
                emit(j);
            } catch (Throwable t) {
                safePluginError("diagnostic", t);
            }
        }

        void addEnclosing(Map<String,Object> out, JavaFileObject source, JCTree tree) {
            if (source == null) return;
            CompilationUnitTree unit = units.get(source.toUri().normalize());
            if (unit == null) return;
            TreePath path = TreePath.getPath(unit, tree);
            if (path == null) return;
            String method = null, owner = null;
            for (TreePath p = path; p != null; p = p.getParentPath()) {
                Tree leaf = p.getLeaf();
                if (method == null && leaf instanceof JCMethodDecl md) method = md.name.toString();
                if (owner == null && leaf instanceof JCClassDecl cd && cd.sym != null) owner = cd.sym.getQualifiedName().toString();
                if (method != null && owner != null) break;
            }
            out.put("owner", owner);
            out.put("method", method);
        }

        Map<String,Object> describeTree(JCTree t) {
            LinkedHashMap<String,Object> m = new LinkedHashMap<>();
            m.put("tag", t.getTag().name());
            m.put("class", t.getClass().getSimpleName());
            m.put("type", describeType(t.type));
            Symbol sym = TreeInfo.symbol(t);
            if (sym != null) m.put("symbol", describeSymbol(sym));
            if (t instanceof JCFieldAccess fa) {
                m.put("member", fa.name.toString());
                m.put("receiverType", describeType(fa.selected == null ? null : fa.selected.type));
                Symbol rs = fa.selected == null ? null : TreeInfo.symbol(fa.selected);
                if (rs != null) m.put("receiverSymbol", describeSymbol(rs));
            } else if (t instanceof JCIdent id) {
                m.put("name", id.name.toString());
            } else if (t instanceof JCMethodInvocation mi) {
                m.put("callee", String.valueOf(mi.meth));
                m.put("calleeType", describeType(mi.meth == null ? null : mi.meth.type));
                ArrayList<Object> at = new ArrayList<>();
                for (JCExpression a : mi.args) at.add(describeType(a.type));
                m.put("argumentTypes", at);
            } else if (t instanceof JCNewClass nc) {
                m.put("clazz", String.valueOf(nc.clazz));
                ArrayList<Object> at = new ArrayList<>();
                for (JCExpression a : nc.args) at.add(describeType(a.type));
                m.put("argumentTypes", at);
                if (nc.constructor != null) m.put("constructor", describeSymbol(nc.constructor));
            }
            return m;
        }

        Object describeType(Type t) {
            if (t == null) return null;
            LinkedHashMap<String,Object> m = new LinkedHashMap<>();
            m.put("text", types.toString(t));
            m.put("tag", t.getTag().name());
            m.put("erroneous", t.isErroneous());
            m.put("primitive", t.isPrimitive());
            if (t.tsym != null) {
                m.put("symbol", t.tsym.getQualifiedName().toString());
                m.put("symbolKind", t.tsym.getKind().name());
            }
            if (t instanceof Type.MethodType mt) {
                ArrayList<Object> ps = new ArrayList<>();
                for (Type p : mt.argtypes) ps.add(describeType(p));
                m.put("parameters", ps);
                m.put("return", describeType(mt.restype));
                ArrayList<Object> th = new ArrayList<>();
                for (Type x : mt.thrown) th.add(describeType(x));
                m.put("throws", th);
            }
            return m;
        }

        Object describeSymbol(Symbol s) {
            if (s == null) return null;
            LinkedHashMap<String,Object> m = new LinkedHashMap<>();
            m.put("kind", s.getKind().name());
            m.put("name", s.getSimpleName().toString());
            m.put("qualified", s.getQualifiedName().toString());
            m.put("owner", s.owner == null ? null : s.owner.getQualifiedName().toString());
            m.put("flags", Flags.toString(s.flags()));
            m.put("type", describeType(s.type));
            return m;
        }

        Object describeArgs(Object[] args, int depth) {
            ArrayList<Object> out = new ArrayList<>();
            if (args == null) return out;
            for (Object x : args) out.add(describeArg(x, depth));
            return out;
        }

        Object describeArg(Object x, int depth) {
            if (x == null) return null;
            if (depth > 4) return String.valueOf(x);
            if (x instanceof Type t) return mapOf("kind","type","value",describeType(t));
            if (x instanceof Symbol s) return mapOf("kind","symbol","value",describeSymbol(s));
            if (x instanceof JCDiagnostic d) return mapOf("kind","diagnostic-fragment","code",d.getCode(),
                    "text",d.getMessage(Locale.ROOT),"args",describeArgs(d.getArgs(), depth + 1));
            if (x instanceof Iterable<?> it) {
                ArrayList<Object> a = new ArrayList<>(); for (Object y : it) a.add(describeArg(y, depth + 1)); return a;
            }
            return mapOf("kind",x.getClass().getSimpleName(),"text",String.valueOf(x));
        }

        void captureAnalyzedType(TaskEvent e) {
            if (!(e.getTypeElement() instanceof ClassSymbol cs)) return;
            LinkedHashMap<String,Object> j = new LinkedHashMap<>();
            j.put("kind", "analyzed-type");
            j.put("name", cs.getQualifiedName().toString());
            j.put("flags", Flags.toString(cs.flags()));
            j.put("type", describeType(cs.type));
            if (cfg.members) {
                ArrayList<Object> members = new ArrayList<>();
                try {
                    for (Symbol s : cs.members().getSymbols()) {
                        if (s.owner == cs) members.add(describeSymbol(s));
                    }
                } catch (Throwable ignored) {}
                j.put("members", members);
            }
            if (cfg.references && e.getCompilationUnit() != null) {
                j.put("references", referenceSummary(e.getCompilationUnit(), cs));
            }
            emit(j);
        }

        Object referenceSummary(CompilationUnitTree unit, ClassSymbol owner) {
            TreePath typePath = trees.getPath(owner);
            if (typePath == null) return Collections.emptyList();
            TreeMap<String,Integer> counts = new TreeMap<>();
            new TreePathScanner<Void,Void>() {
                void add(Symbol s) {
                    if (s == null || s.owner == null) return;
                    Symbol o = s.owner;
                    while (o != null && !(o instanceof ClassSymbol)) o = o.owner;
                    if (o instanceof ClassSymbol c && c != owner) counts.merge(c.getQualifiedName().toString(), 1, Integer::sum);
                }
                @Override public Void visitIdentifier(IdentifierTree n, Void p) { if (n instanceof JCIdent x) add(x.sym); return super.visitIdentifier(n,p); }
                @Override public Void visitMemberSelect(MemberSelectTree n, Void p) { if (n instanceof JCFieldAccess x) add(x.sym); return super.visitMemberSelect(n,p); }
                @Override public Void visitNewClass(NewClassTree n, Void p) { if (n instanceof JCNewClass x) add(x.constructor); return super.visitNewClass(n,p); }
            }.scan(typePath, null);
            ArrayList<Object> r = new ArrayList<>();
            for (var x : counts.entrySet()) r.add(mapOf("target",x.getKey(),"count",x.getValue()));
            return r;
        }

        synchronized void emit(Map<String,Object> m) {
            if (closed.get() || out == null) return;
            try { out.write(Json.value(m)); out.newLine(); out.flush(); }
            catch (IOException e) { throw new UncheckedIOException(e); }
        }

        synchronized void safePluginError(String where, Throwable t) {
            try { emit(mapOf("kind","plugin-error","where",where,"error",t.toString())); }
            catch (Throwable ignored) {}
        }

        synchronized void close() {
            if (!closed.compareAndSet(false, true)) return;
            if (out == null) return;
            try {
                // closed is already true, so write summary directly.
                LinkedHashMap<String,Object> m = new LinkedHashMap<>();
                m.put("kind","summary"); m.put("diagnostics",diagnostics); m.put("errors",errors); m.put("warnings",warnings);
                out.write(Json.value(m)); out.newLine(); out.flush(); out.close();
            } catch (IOException ignored) {}
        }

        static String pathOf(JavaFileObject f) {
            try { return Paths.get(f.toUri()).toAbsolutePath().toString(); }
            catch (Exception e) { return f.getName(); }
        }
    }

    static LinkedHashMap<String,Object> mapOf(Object... kv) {
        LinkedHashMap<String,Object> m = new LinkedHashMap<>();
        for (int i=0;i+1<kv.length;i+=2) m.put(String.valueOf(kv[i]), kv[i+1]);
        return m;
    }
}
