package apk2project.repair;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import javax.lang.model.element.Modifier;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import com.sun.source.tree.*;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;

/**
 * Dependency-free Java source structure extractor for apk2project.
 *
 * It intentionally does NOT rewrite javac's internal AST.  Instead it emits exact
 * source offsets and structural facts.  The Python repair engine then performs
 * auditable text edits against those ranges.  This avoids com.sun.tools.javac.*
 * internals and --add-exports flags while still using javac's real parser.
 */
public final class SourceAnalyzer {
    private static final int TRACE_LEVEL = parseTraceLevel(System.getenv("APK2PROJECT_TREE_TRACE"));
    private static final boolean COLOR = System.getenv("NO_COLOR") == null
            && !"dumb".equalsIgnoreCase(System.getenv().getOrDefault("TERM", ""));
    private static final String RESET = COLOR ? "\u001b[0m" : "";
    private static final String DIM = COLOR ? "\u001b[2m" : "";
    private static final String RED = COLOR ? "\u001b[91m" : "";
    private static final String GREEN = COLOR ? "\u001b[92m" : "";
    private static final String YELLOW = COLOR ? "\u001b[93m" : "";
    private static final String BLUE = COLOR ? "\u001b[94m" : "";
    private static final String MAGENTA = COLOR ? "\u001b[95m" : "";
    private static final String CYAN = COLOR ? "\u001b[96m" : "";
    private static final String BOLD = COLOR ? "\u001b[1m" : "";

    private final Map<String, Integer> counts = new LinkedHashMap<>();

    private static int parseTraceLevel(String raw) {
        if (raw == null || raw.isBlank()) return 2; // useful detail by default
        raw = raw.trim().toLowerCase(Locale.ROOT);
        return switch (raw) {
            case "off", "false", "no", "0" -> 0;
            case "summary", "1" -> 1;
            case "detail", "2", "true", "yes" -> 2;
            case "verbose", "3" -> 3;
            default -> {
                try { yield Math.max(0, Math.min(3, Integer.parseInt(raw))); }
                catch (NumberFormatException ignored) { yield 2; }
            }
        };
    }

    private static String clip(String s, int n) {
        if (s == null) return "";
        s = s.replace('\n', ' ').replace('\r', ' ').replaceAll("\\s+", " ").trim();
        return s.length() <= n ? s : s.substring(0, Math.max(0, n - 1)) + "…";
    }

    private static void trace(int level, String color, String tag, String message) {
        if (TRACE_LEVEL < level) return;
        System.err.println(color + BOLD + "[JAVA-TREE]" + RESET + color + "[" + tag + "] " + RESET + message);
        System.err.flush();
    }

    private final CompilationUnitTree unit;
    private final SourcePositions positions;
    private final String source;
    private final Path path;
    private final Deque<String> typeStack = new ArrayDeque<>();
    private final Deque<String> methodStack = new ArrayDeque<>();

    private SourceAnalyzer(CompilationUnitTree unit, Trees trees, String source, Path path) {
        this.unit = unit;
        this.positions = trees.getSourcePositions();
        this.source = source;
        this.path = path;
    }

    private long start(Tree t) { return t == null ? -1 : positions.getStartPosition(unit, t); }
    private long end(Tree t) { return t == null ? -1 : positions.getEndPosition(unit, t); }
    private long line(long pos) {
        if (pos < 0 || unit.getLineMap() == null) return -1;
        return unit.getLineMap().getLineNumber(pos);
    }
    private String text(Tree t) {
        long s = start(t), e = end(t);
        if (s < 0 || e < s || e > source.length()) return t == null ? "" : t.toString();
        return source.substring((int)s, (int)e);
    }
    private String enclosingType() { return typeStack.peek() == null ? "" : typeStack.peek(); }
    private String enclosingMethod() { return methodStack.peek() == null ? "" : methodStack.peek(); }

    private static String json(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder(s.length() + 16).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int)c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private static String value(Object v) {
        if (v == null) return "null";
        if (v instanceof Number || v instanceof Boolean) return v.toString();
        if (v instanceof Collection<?>) {
            StringBuilder b = new StringBuilder("["); boolean first = true;
            for (Object x : (Collection<?>)v) {
                if (!first) b.append(','); first = false; b.append(value(x));
            }
            return b.append(']').toString();
        }
        return json(String.valueOf(v));
    }

    private void emit(String kind, Object... kv) {
        counts.merge(kind, 1, Integer::sum);
        StringBuilder b = new StringBuilder("{\"kind\":").append(json(kind));
        b.append(",\"file\":").append(json(path.toString()));
        for (int i = 0; i + 1 < kv.length; i += 2) {
            b.append(',').append(json(String.valueOf(kv[i]))).append(':').append(value(kv[i+1]));
        }
        System.out.println(b.append('}'));
    }

    private void scan() {
        long scanStarted = System.nanoTime();
        String pkg = unit.getPackageName() == null ? "" : unit.getPackageName().toString();
        trace(1, CYAN, "SCAN", path.getFileName() + "  package=" + (pkg.isEmpty() ? "<default>" : pkg)
                + "  imports=" + unit.getImports().size() + "  chars=" + source.length());
        emit("unit", "package", pkg, "sourceLength", source.length());
        for (ImportTree it : unit.getImports()) {
            emit("import", "name", it.getQualifiedIdentifier().toString(), "static", it.isStatic(),
                 "start", start(it), "end", end(it), "line", line(start(it)));
        }

        new TreePathScanner<Void, Void>() {
            @Override public Void visitClass(ClassTree node, Void p) {
                String simple = node.getSimpleName().toString();
                String parent = enclosingType();
                String fq = parent.isEmpty() ? (pkg.isEmpty() ? simple : pkg + "." + simple) : parent + "$" + simple;
                typeStack.push(fq);
                emit("type", "name", simple, "fqcn", fq, "parent", parent,
                     "typeKind", node.getKind().name(), "start", start(node), "end", end(node),
                     "line", line(start(node)), "extends", node.getExtendsClause() == null ? "" : text(node.getExtendsClause()),
                     "implements", node.getImplementsClause().stream().map(SourceAnalyzer.this::text).toList(),
                     "modifiers", node.getModifiers().getFlags().stream().map(Enum::name).toList());
                trace(2, BLUE, "TYPE", fq + "  " + node.getKind().name().toLowerCase(Locale.ROOT)
                        + "  line=" + line(start(node))
                        + (node.getExtendsClause() == null ? "" : "  extends=" + clip(text(node.getExtendsClause()), 70))
                        + (node.getImplementsClause().isEmpty() ? "" : "  implements=" + clip(node.getImplementsClause().stream().map(SourceAnalyzer.this::text).toList().toString(), 100)));
                Void r = super.visitClass(node, p);
                typeStack.pop();
                return r;
            }

            @Override public Void visitMethod(MethodTree node, Void p) {
                String name = node.getName().toString();
                String owner = enclosingType();
                String id = owner + "#" + name + "@" + start(node);
                methodStack.push(id);
                BlockTree body = node.getBody();
                List<String> params = new ArrayList<>(), paramNames = new ArrayList<>();
                for (VariableTree v : node.getParameters()) {
                    params.add(v.getType() == null ? "" : text(v.getType()));
                    paramNames.add(v.getName().toString());
                }
                emit("method", "name", name, "owner", owner, "id", id,
                     "returnType", node.getReturnType() == null ? "<constructor>" : text(node.getReturnType()),
                     "params", params, "paramNames", paramNames,
                     "start", start(node), "end", end(node), "line", line(start(node)),
                     "bodyStart", body == null ? -1 : start(body), "bodyEnd", body == null ? -1 : end(body),
                     "modifiers", node.getModifiers().getFlags().stream().map(Enum::name).toList());
                trace(2, MAGENTA, "METHOD", owner + "." + name + "(" + clip(String.join(", ", params), 110) + ")"
                        + (node.getReturnType() == null ? "  <ctor>" : " -> " + clip(text(node.getReturnType()), 55))
                        + "  line=" + line(start(node)));
                Void r = super.visitMethod(node, p);
                methodStack.pop();
                return r;
            }

            @Override public Void visitVariable(VariableTree node, Void p) {
                Tree type = node.getType();
                ExpressionTree init = node.getInitializer();
                emit("variable", "name", node.getName().toString(), "declaredType", type == null ? "" : text(type),
                     "typeStart", start(type), "typeEnd", end(type),
                     "init", init == null ? "" : text(init), "initKind", init == null ? "" : init.getKind().name(),
                     "initStart", start(init), "initEnd", end(init),
                     "start", start(node), "end", end(node), "line", line(start(node)),
                     "owner", enclosingType(), "method", enclosingMethod());
                trace(3, DIM + CYAN, "VAR", (type == null ? "?" : clip(text(type), 50)) + " " + node.getName()
                        + (init == null ? "" : " = " + clip(text(init), 95)) + "  line=" + line(start(node)));
                return super.visitVariable(node, p);
            }

            @Override public Void visitAssignment(AssignmentTree node, Void p) {
                emit("assignment", "lhs", text(node.getVariable()), "rhs", text(node.getExpression()),
                     "rhsKind", node.getExpression().getKind().name(), "start", start(node), "end", end(node),
                     "line", line(start(node)), "owner", enclosingType(), "method", enclosingMethod());
                return super.visitAssignment(node, p);
            }

            @Override public Void visitCompoundAssignment(CompoundAssignmentTree node, Void p) {
                emit("compoundAssignment", "lhs", text(node.getVariable()), "rhs", text(node.getExpression()),
                     "operator", node.getKind().name(), "start", start(node), "end", end(node),
                     "line", line(start(node)), "owner", enclosingType(), "method", enclosingMethod());
                return super.visitCompoundAssignment(node, p);
            }

            @Override public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
                ExpressionTree select = node.getMethodSelect();
                String receiver = "", name = text(select);
                if (select instanceof MemberSelectTree) {
                    MemberSelectTree ms = (MemberSelectTree) select;
                    receiver = text(ms.getExpression());
                    name = ms.getIdentifier().toString();
                } else if (select instanceof IdentifierTree) {
                    name = ((IdentifierTree) select).getName().toString();
                }
                List<String> args = node.getArguments().stream().map(SourceAnalyzer.this::text).toList();
                emit("call", "name", name, "receiver", receiver, "args", args,
                     "start", start(node), "end", end(node), "line", line(start(node)),
                     "owner", enclosingType(), "method", enclosingMethod());
                trace(3, DIM + BLUE, "CALL", (receiver.isEmpty() ? "" : clip(receiver, 55) + ".") + name
                        + "(" + clip(String.join(", ", args), 95) + ")  line=" + line(start(node)));
                return super.visitMethodInvocation(node, p);
            }

            @Override public Void visitMemberSelect(MemberSelectTree node, Void p) {
                emit("member", "receiver", text(node.getExpression()), "name", node.getIdentifier().toString(),
                     "start", start(node), "end", end(node), "line", line(start(node)),
                     "owner", enclosingType(), "method", enclosingMethod());
                return super.visitMemberSelect(node, p);
            }

            @Override public Void visitNewClass(NewClassTree node, Void p) {
                emit("new", "type", text(node.getIdentifier()), "start", start(node), "end", end(node),
                     "line", line(start(node)), "owner", enclosingType(), "method", enclosingMethod());
                return super.visitNewClass(node, p);
            }

            @Override public Void visitTypeCast(TypeCastTree node, Void p) {
                emit("cast", "type", text(node.getType()), "expr", text(node.getExpression()),
                     "start", start(node), "end", end(node), "line", line(start(node)),
                     "owner", enclosingType(), "method", enclosingMethod());
                return super.visitTypeCast(node, p);
            }

            @Override public Void visitInstanceOf(InstanceOfTree node, Void p) {
                emit("instanceof", "expr", text(node.getExpression()), "type", node.getType() == null ? "" : text(node.getType()),
                     "start", start(node), "end", end(node), "line", line(start(node)),
                     "owner", enclosingType(), "method", enclosingMethod());
                return super.visitInstanceOf(node, p);
            }

            @Override public Void visitEnhancedForLoop(EnhancedForLoopTree node, Void p) {
                VariableTree v = node.getVariable();
                ExpressionTree expr = node.getExpression();
                emit("enhancedFor", "varName", v.getName().toString(),
                     "varType", v.getType() == null ? "" : text(v.getType()),
                     "expr", text(expr), "exprStart", start(expr), "exprEnd", end(expr),
                     "start", start(node), "end", end(node), "line", line(start(node)),
                     "owner", enclosingType(), "method", enclosingMethod());
                return super.visitEnhancedForLoop(node, p);
            }

            @Override public Void visitReturn(ReturnTree node, Void p) {
                emit("return", "expr", node.getExpression() == null ? "" : text(node.getExpression()),
                     "start", start(node), "end", end(node), "line", line(start(node)),
                     "owner", enclosingType(), "method", enclosingMethod());
                return super.visitReturn(node, p);
            }

            @Override public Void visitErroneous(ErroneousTree node, Void p) {
                emit("erroneous", "text", text(node), "start", start(node), "end", end(node),
                     "line", line(start(node)), "owner", enclosingType(), "method", enclosingMethod());
                trace(1, RED, "ERRONEOUS", path.getFileName() + ":" + line(start(node)) + "  " + clip(text(node), 150));
                return super.visitErroneous(node, p);
            }

            @Override public Void visitBlock(BlockTree node, Void p) {
                emit("block", "static", node.isStatic(), "start", start(node), "end", end(node),
                     "line", line(start(node)), "owner", enclosingType(), "method", enclosingMethod());
                return super.visitBlock(node, p);
            }

            @Override public Void visitAnnotation(AnnotationTree node, Void p) {
                emit("annotation", "name", text(node.getAnnotationType()), "start", start(node), "end", end(node),
                     "line", line(start(node)), "owner", enclosingType(), "method", enclosingMethod());
                return super.visitAnnotation(node, p);
            }
        }.scan(unit, null);
        long elapsedMs = (System.nanoTime() - scanStarted) / 1_000_000L;
        trace(1, GREEN, "DONE", path.getFileName() + "  " + elapsedMs + "ms"
                + "  types=" + counts.getOrDefault("type", 0)
                + "  methods=" + counts.getOrDefault("method", 0)
                + "  vars=" + counts.getOrDefault("variable", 0)
                + "  calls=" + counts.getOrDefault("call", 0)
                + "  members=" + counts.getOrDefault("member", 0)
                + "  erroneous=" + counts.getOrDefault("erroneous", 0));
    }

    private static int analyze(Path p) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            System.err.println("No system Java compiler. Run with a JDK, not a JRE.");
            return 3;
        }
        String src = Files.readString(p, StandardCharsets.UTF_8);
        trace(1, CYAN, "OPEN", p + "  bytes=" + src.getBytes(StandardCharsets.UTF_8).length);
        try (StandardJavaFileManager fm = compiler.getStandardFileManager(null, Locale.ROOT, StandardCharsets.UTF_8)) {
            Iterable<? extends JavaFileObject> files = fm.getJavaFileObjectsFromFiles(List.of(p.toFile()));
            List<String> opts = List.of("-proc:none", "-Xlint:none");
            JavacTask task = (JavacTask) compiler.getTask(null, fm, d -> {
                String c = d.getKind() == javax.tools.Diagnostic.Kind.ERROR ? RED : YELLOW;
                trace(1, c, "PARSE", p.getFileName() + ":" + d.getLineNumber() + ":" + d.getColumnNumber()
                        + "  " + d.getKind().name().toLowerCase(Locale.ROOT) + "  " + clip(d.getMessage(Locale.ROOT), 180));
            }, opts, null, files);
            Iterable<? extends CompilationUnitTree> units = task.parse();
            Trees trees = Trees.instance(task);
            for (CompilationUnitTree u : units) new SourceAnalyzer(u, trees, src, p).scan();
        }
        return 0;
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("usage: SourceAnalyzer FILE.java [FILE.java ...]");
            System.exit(2);
        }
        int rc = 0;
        trace(1, CYAN, "BEGIN", "analyzing " + args.length + " Java source file(s), trace-level=" + TRACE_LEVEL);
        for (String arg : args) {
            Path p = Path.of(arg).toAbsolutePath().normalize();
            try { rc = Math.max(rc, analyze(p)); }
            catch (Throwable t) {
                System.err.println("SourceAnalyzer failed for " + p + ": " + t);
                rc = Math.max(rc, 4);
            }
        }
        System.exit(rc);
    }
}
