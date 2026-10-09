package apk2project.hybrid;

import java.io.*;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import com.android.tools.smali.dexlib2.iface.instruction.formats.*;
import com.android.tools.smali.dexlib2.iface.reference.*;
import com.android.tools.smali.dexlib2.iface.value.*;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction3rc;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.rewriter.*;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.*;

/**
 * v28 DEX-preserving hybrid runtime rebuilder.
 *
 * The direct DexReader remains authoritative for planning/validation.  Runtime
 * DEX filtering/writing uses the official standalone Google smali-dexlib2 API
 * directly.  This class is compiled lazily only after the app's validated javac
 * boundary has succeeded, so dexlib2 can never destabilize source ownership.
 */
public final class DexHybridRebuilder {
    private static final Pattern DEX_ENTRY = Pattern.compile("classes(?:\\d+)?\\.dex");

    // v29: merge diagnostics are intentionally verbose by default.  The hybrid
    // runtime leg is where representation-boundary mistakes become expensive, so
    // keep a chronological trace of every universe/rewrite/validation transition.
    // Set APK2PROJECT_DEX_MERGE_VERBOSE=0 to suppress these diagnostics.
    private static final boolean MERGE_VERBOSE =
            !"0".equals(System.getenv().getOrDefault("APK2PROJECT_DEX_MERGE_VERBOSE", "1"));
    private static long mergeStartNanos;
    private static int mergePhaseNo;
    private static String mergePhaseTitle = "not-started";

    private static void mergeLog(String format, Object... args) {
        if (!MERGE_VERBOSE) return;
        double seconds = mergeStartNanos == 0L ? 0.0 :
                (System.nanoTime() - mergeStartNanos) / 1_000_000_000.0;
        String body = args.length == 0 ? format : String.format(Locale.ROOT, format, args);
        System.out.printf(Locale.ROOT, "[*] v29 merge +%7.3fs | %s%n", seconds, body);
        System.out.flush();
    }

    private static void mergePhase(String title) {
        mergePhaseTitle = title;
        mergeLog("PHASE %02d | %s", ++mergePhaseNo, title);
    }

    private static void mergeItems(String label, Collection<?> values, int limit) {
        if (!MERGE_VERBOSE) return;
        mergeLog("%s: count=%d", label, values.size());
        int i = 0;
        for (Object value : values) {
            if (i >= limit) {
                mergeLog("  ... %d more", values.size() - i);
                break;
            }
            mergeLog("  [%d] %s", i, String.valueOf(value));
            i++;
        }
    }

    private static String humanBytes(long n) {
        if (n < 1024) return n + " B";
        double v = n; String[] u = {"KiB", "MiB", "GiB"}; int i = -1;
        do { v /= 1024.0; i++; } while (v >= 1024.0 && i < u.length - 1);
        return String.format(Locale.ROOT, "%.1f %s", v, u[i]);
    }

    private static final class Args {
        String command = "inventory";
        Path apk, replacementDir, removeList, outDir, report;
        int api = 35, minApi = 21;
    }

    public static void main(String[] argv) throws Exception {
        Args a = parse(argv);
        switch (a.command) {
            case "inventory" -> inventory(a);
            case "merge" -> {
                try {
                    merge(a);
                } catch (Throwable t) {
                    mergeLog("FAILED during PHASE %02d (%s): %s: %s",
                            mergePhaseNo, mergePhaseTitle, t.getClass().getName(), String.valueOf(t.getMessage()));
                    throw t;
                }
            }
            default -> die("unknown command: " + a.command);
        }
    }

    private static Args parse(String[] argv) {
        Args a = new Args(); int i=0;
        if (argv.length>0 && !argv[0].startsWith("--")) { a.command=argv[0]; i=1; }
        while (i<argv.length) {
            String k=argv[i++];
            String v=(i<argv.length?argv[i]:null);
            switch(k) {
                case "--apk" -> { a.apk=Path.of(req(k,v)); i++; }
                case "--replacement-dir" -> { a.replacementDir=Path.of(req(k,v)); i++; }
                case "--remove-list" -> { a.removeList=Path.of(req(k,v)); i++; }
                case "--out-dir" -> { a.outDir=Path.of(req(k,v)); i++; }
                case "--report" -> { a.report=Path.of(req(k,v)); i++; }
                case "--api" -> { a.api=Integer.parseInt(req(k,v)); i++; }
                case "--min-api" -> { a.minApi=Integer.parseInt(req(k,v)); i++; }
                default -> die("unknown option: "+k);
            }
        }
        return a;
    }
    private static String req(String k,String v){ if(v==null) die(k+" requires value"); return v; }
    private static void die(String s){ throw new IllegalArgumentException(s); }

    /** Dependency-free inventory used before dexlib2 is even located. */
    private static void inventory(Args a) throws Exception {
        if (a.apk==null) die("inventory requires --apk");
        Map<String,DexReader.Clazz> m=DexReader.readApk(a.apk);
        Map<String,List<String>> byDex=new TreeMap<>(DexHybridRebuilder::dexEntryCompare);
        for (DexReader.Clazz c:m.values()) byDex.computeIfAbsent(c.dexEntry,x->new ArrayList<>()).add(desc(c.fqcn));
        for(List<String> l:byDex.values()) Collections.sort(l);
        StringBuilder j=new StringBuilder();
        j.append("{\n  \"class_count\": ").append(m.size()).append(",\n  \"dex\": {");
        boolean firstDex=true;
        for(var e:byDex.entrySet()){
            if(!firstDex)j.append(','); firstDex=false;
            j.append("\n    ").append(q(e.getKey())).append(": [");
            boolean f=true; for(String d:e.getValue()){if(!f)j.append(',');f=false;j.append("\n      ").append(q(d));}
            if(!e.getValue().isEmpty())j.append('\n').append("    "); j.append(']');
        }
        j.append("\n  }\n}\n");
        if(a.report!=null){Files.createDirectories(a.report.toAbsolutePath().getParent());Files.writeString(a.report,j);}
        System.out.print(j);
    }

    private static String desc(String fqcn){return "L"+fqcn.replace('.','/')+";";}

    private static final class ReplacementDex {
        final Path source;
        final DexFile dex;
        final int constructorBridgeRewrites;
        final List<String> constructorBridgeRules;
        ReplacementDex(Path source,DexFile dex,int rewrites,List<String> rules){
            this.source=source; this.dex=dex; this.constructorBridgeRewrites=rewrites; this.constructorBridgeRules=rules;
        }
    }

    /**
     * Rewrite only DEX entries affected by replacement classes. Untouched DEX
     * entries are copied byte-for-byte. Replacement classes prefer the DEX entry
     * where the same descriptor lived originally; newly generated companions are
     * placed with their nearest replacement owner, then in the first touched DEX.
     */
    private static void merge(Args a) throws Exception {
        mergeStartNanos=System.nanoTime(); mergePhaseNo=0;
        mergePhase("startup / arguments");
        if(a.apk==null||a.replacementDir==null||a.removeList==null||a.outDir==null)
            die("merge requires --apk --replacement-dir --remove-list --out-dir");
        mergeLog("apk=%s",a.apk.toAbsolutePath());
        mergeLog("replacementDir=%s",a.replacementDir.toAbsolutePath());
        mergeLog("removeList=%s",a.removeList.toAbsolutePath());
        mergeLog("outDir=%s",a.outDir.toAbsolutePath());
        mergeLog("report=%s",a.report==null?"<none>":a.report.toAbsolutePath());
        mergeLog("api=%d minApi=%d dexlibVerbose=%s",a.api,a.minApi,MERGE_VERBOSE);
        Files.createDirectories(a.outDir);
        LinkedHashSet<String> requestedRemove=new LinkedHashSet<>();
        for(String s:Files.readAllLines(a.removeList)){s=s.trim();if(!s.isEmpty()&&!s.startsWith("#"))requestedRemove.add(s);}
        mergeItems("requested source-owned replacement descriptors",requestedRemove,100);

        mergePhase("initialize dexlib2 runtime");
        Dexlib dl=new Dexlib(a.api);
        mergeLog("dexlib namespace=com.android.tools.smali.dexlib2 opcodes.api=%d",dl.opcodes.api);
        List<String> dexEntries=new ArrayList<>();
        Map<String,byte[]> originalBytes=new LinkedHashMap<>();
        Map<String,DexFile> originalDexFiles=new LinkedHashMap<>();
        Map<String,String> originalOwner=new HashMap<>();
        Map<String,ClassDef> originalClasses=new HashMap<>();
        mergePhase("read original APK DEX universe");
        try(ZipFile z=new ZipFile(a.apk.toFile())){
            for(ZipEntry ze:Collections.list(z.entries())) if(DEX_ENTRY.matcher(ze.getName()).matches()) dexEntries.add(ze.getName());
            dexEntries.sort(DexHybridRebuilder::dexEntryCompare);
            mergeItems("original DEX entries",dexEntries,100);
            for(String entry:dexEntries){
                ZipEntry ze=z.getEntry(entry); byte[] b;
                try(InputStream in=z.getInputStream(ze)){b=in.readAllBytes();}
                originalBytes.put(entry,b);
                DexFile df=dl.readDex(b); originalDexFiles.put(entry,df);
                List<ClassDef> dexClasses=dl.classes(df);
                mergeLog("read %s: zipBytes=%s dexClasses=%d dexApi=%d",entry,humanBytes(b.length),dexClasses.size(),dl.dexOpcodes(df).api);
                for(ClassDef c:dexClasses){
                    String t=dl.type(c);
                    String prior=originalOwner.put(t,entry);
                    if(prior!=null) {
                        mergeLog("FATAL duplicate original class %s in %s and %s",t,prior,entry);
                        throw new IllegalStateException("duplicate original class "+t);
                    }
                    originalClasses.put(t,c);
                }
            }
        }
        if(dexEntries.isEmpty()) throw new IllegalStateException("APK contains no classes*.dex");
        mergeLog("original runtime universe: dexFiles=%d classes=%d",dexEntries.size(),originalClasses.size());

        // DEX can legally allocate a subclass and invoke its direct superclass
        // constructor without declaring a constructor on the allocated class. Java
        // classfiles cannot express that pattern, so the javac/D8 ABI facade exposes a
        // compile-only constructor. Recover the APK's exact constructor-bypass rules and
        // lower D8's synthetic T.<init> reference back to the original S.<init> owner
        // before runtime linkage validation.
        mergePhase("discover original DEX constructor-owner bridges");
        Dexlib.ConstructorBridgePlan constructorBridges=dl.discoverConstructorBridges(originalClasses.values());
        mergeLog("constructor bridge discovery: proven=%d ambiguous=%d",constructorBridges.targets.size(),constructorBridges.ambiguous.size());
        List<String> bridgeDescriptions=new ArrayList<>();
        for(var e:constructorBridges.targets.entrySet()) bridgeDescriptions.add(e.getKey()+" => "+e.getValue());
        mergeItems("proven constructor bridge rules",bridgeDescriptions,100);
        if(!constructorBridges.ambiguous.isEmpty()){
            List<String> amb=new ArrayList<>();
            for(var e:constructorBridges.ambiguous.entrySet()) amb.add(e.getKey()+" => "+e.getValue());
            mergeItems("AMBIGUOUS constructor bridge candidates (never rewritten)",amb,100);
        }

        // Load all D8 output dex files as one replacement class universe, applying only
        // constructor-owner rewrites that are directly proven by the original APK.
        mergePhase("load and lower D8 replacement DEX");
        List<Path> replPaths=new ArrayList<>();
        try(var st=Files.list(a.replacementDir)){st.filter(p->DEX_ENTRY.matcher(p.getFileName().toString()).matches()).sorted((x,y)->dexEntryCompare(x.getFileName().toString(),y.getFileName().toString())).forEach(replPaths::add);}
        if(replPaths.isEmpty()) throw new IllegalStateException("replacement directory contains no classes*.dex: "+a.replacementDir);
        List<String> replPathNames=new ArrayList<>(); for(Path p:replPaths) replPathNames.add(p.getFileName()+" ("+humanBytes(Files.size(p))+")");
        mergeItems("D8 replacement DEX inputs",replPathNames,100);
        List<ReplacementDex> replDex=new ArrayList<>();
        LinkedHashMap<String,ClassDef> replClasses=new LinkedHashMap<>();
        int constructorBridgeRewriteCount=0;
        LinkedHashSet<String> constructorBridgeRulesUsed=new LinkedHashSet<>();
        for(Path p:replPaths){
            byte[] rawBytes=Files.readAllBytes(p);
            DexFile raw=dl.readDex(rawBytes);
            List<ClassDef> rawClasses=dl.classes(raw);
            mergeLog("replacement input %s: bytes=%s classes=%d dexApi=%d",p.getFileName(),humanBytes(rawBytes.length),rawClasses.size(),dl.dexOpcodes(raw).api);
            Dexlib.LoweredDex lowered=dl.lowerConstructorBridges(raw,constructorBridges);
            mergeLog("  constructor lowering: rewrites=%d rulesUsed=%d",lowered.rewrites,lowered.rulesUsed.size());
            if(!lowered.rulesUsed.isEmpty()) mergeItems("  rules used in "+p.getFileName(),lowered.rulesUsed,100);
            ReplacementDex rd=new ReplacementDex(p,lowered.dex,lowered.rewrites,lowered.rulesUsed);
            replDex.add(rd); constructorBridgeRewriteCount+=lowered.rewrites; constructorBridgeRulesUsed.addAll(lowered.rulesUsed);
            for(ClassDef c:dl.classes(lowered.dex)){
                String t=dl.type(c);
                if(replClasses.putIfAbsent(t,c)!=null) {
                    mergeLog("FATAL duplicate replacement class %s while reading %s",t,p.getFileName());
                    throw new IllegalStateException("duplicate replacement class "+t);
                }
            }
        }
        mergeLog("replacement runtime universe: dexFiles=%d classes=%d constructorRewrites=%d",replDex.size(),replClasses.size(),constructorBridgeRewriteCount);
        mergeItems("replacement class descriptors",replClasses.keySet(),200);

        // Any replacement descriptor already in the APK must be removed even if
        // the planner omitted it (e.g. javac/D8 generated a nested companion).
        mergePhase("compute exact original-class removal set");
        LinkedHashSet<String> removal=new LinkedHashSet<>(requestedRemove);
        LinkedHashSet<String> inferredRemoval=new LinkedHashSet<>();
        for(String t:replClasses.keySet()) if(originalOwner.containsKey(t) && removal.add(t)) inferredRemoval.add(t);
        for(String t:requestedRemove) if(!originalOwner.containsKey(t)) {
            mergeLog("FATAL requested replacement owner is absent from original DEX: %s",t);
            throw new IllegalStateException("requested replacement owner not present in original DEX: "+t);
        }
        mergeItems("additional removal descriptors inferred from D8 output",inferredRemoval,100);
        List<String> removalPlacement=new ArrayList<>();
        for(String t:removal) removalPlacement.add(t+" <- "+originalOwner.get(t));
        mergeItems("final removal set with original DEX ownership",removalPlacement,200);

        // Keep D8 output as a separate appended DEX set. Original DEX entries are
        // only filtered: untouched entries are byte-copied, touched entries are rewritten
        // with old replacement definitions omitted. D8 replacement DEX itself remains
        // byte-for-byte unless a proven DEX constructor bridge must be lowered.
        mergePhase("plan touched vs byte-copied original DEX entries");
        LinkedHashSet<String> touched=new LinkedHashSet<>();
        for(String t:removal){String e=originalOwner.get(t);if(e!=null)touched.add(e);}
        LinkedHashSet<String> untouchedPlan=new LinkedHashSet<>(dexEntries); untouchedPlan.removeAll(touched);
        mergeItems("touched original DEX entries (will be rewritten)",touched,100);
        mergeItems("untouched original DEX entries (will be byte-copied)",untouchedPlan,100);
        if(a.minApi<21)
            throw new IllegalStateException("hybrid append-only replacement DEX currently requires minSdk >= 21; got "+a.minApi+
                    ". Pre-L multidex needs an explicit main-dex/MultiDex installation proof before it is safe.");

        mergePhase("emit filtered original DEX entries");
        LinkedHashMap<String,String> outHash=new LinkedHashMap<>();
        int retained=0, removed=0;
        for(String entry:dexEntries){
            Path out=a.outDir.resolve(entry);
            if(!touched.contains(entry)){
                int classCount=dl.classes(originalDexFiles.get(entry)).size();
                Files.write(out,originalBytes.get(entry));
                String hash=sha256(out); outHash.put(entry,hash);
                retained += classCount;
                mergeLog("BYTE-COPY %s: classes=%d bytes=%s sha256=%s",entry,classCount,humanBytes(Files.size(out)),hash);
                continue;
            }
            LinkedHashMap<String,ClassDef> filtered=new LinkedHashMap<>();
            List<String> removedHere=new ArrayList<>();
            List<ClassDef> originalHere=dl.classes(originalDexFiles.get(entry));
            for(ClassDef c:originalHere){
                String t=dl.type(c);
                if(removal.contains(t)){removed++;removedHere.add(t);continue;}
                filtered.put(t,c); retained++;
            }
            mergeLog("REWRITE %s: beforeClasses=%d remove=%d retain=%d",entry,originalHere.size(),removedHere.size(),filtered.size());
            mergeItems("  removed from "+entry,removedHere,200);
            dl.writeDex(out,filtered.values(),dl.dexOpcodes(originalDexFiles.get(entry)));
            String hash=sha256(out); outHash.put(entry,hash);
            mergeLog("  wrote %s: bytes=%s sha256=%s",entry,humanBytes(Files.size(out)),hash);
        }

        // Append D8's DEX files after the highest original multidex index.  No D8
        // replacement is interned into an original DEX. Cross-DEX references are
        // native on API 21+, which is the explicit safety floor above.
        mergePhase("append replacement DEX after original multidex set");
        int nextDex=1;
        for(String e:dexEntries) nextDex=Math.max(nextDex,dexNum(e)+1);
        mergeLog("next appended multidex index=%d",nextDex);
        LinkedHashMap<String,String> appendedReplacementDex=new LinkedHashMap<>();
        List<String> finalDexEntries=new ArrayList<>(dexEntries);
        if(constructorBridgeRewriteCount>0)
            System.out.println("[*] v29: lowered "+constructorBridgeRewriteCount+" DEX constructor bridge reference(s): "+String.join(" | ",constructorBridgeRulesUsed));

        for(ReplacementDex rd:replDex){
            String outName=nextDex==1?"classes.dex":"classes"+nextDex+".dex";
            nextDex++;
            Path out=a.outDir.resolve(outName);
            int replacementClassCount=dl.classes(rd.dex).size();
            if(rd.constructorBridgeRewrites==0) {
                Files.copy(rd.source,out,StandardCopyOption.REPLACE_EXISTING);
                mergeLog("APPEND %s -> %s: byte-copy D8 output, classes=%d",rd.source.getFileName(),outName,replacementClassCount);
            } else {
                dl.writeDex(out,dl.classes(rd.dex),dl.dexOpcodes(rd.dex));
                mergeLog("APPEND %s -> %s: re-encoded after %d constructor bridge rewrite(s), classes=%d",rd.source.getFileName(),outName,rd.constructorBridgeRewrites,replacementClassCount);
            }
            appendedReplacementDex.put(rd.source.getFileName().toString(),outName);
            finalDexEntries.add(outName);
            String hash=sha256(out); outHash.put(outName,hash);
            mergeLog("  appended output: bytes=%s sha256=%s",humanBytes(Files.size(out)),hash);
        }
        finalDexEntries.sort(DexHybridRebuilder::dexEntryCompare);
        mergeItems("final DEX entry order",finalDexEntries,100);

        // Validate exact final class universe with the dependency-free reader by
        // temporarily packaging output dex files into a tiny zip/APK container.
        mergePhase("validate exact final class universe");
        Path probe=Files.createTempFile("apk2project-v29-merged-", ".apk");
        mergeLog("temporary class-universe probe=%s",probe);
        try(ZipOutputStream zo=new ZipOutputStream(Files.newOutputStream(probe))){
            for(String e:finalDexEntries){zo.putNextEntry(new ZipEntry(e));Files.copy(a.outDir.resolve(e),zo);zo.closeEntry();}
        }
        Map<String,DexReader.Clazz> finalMap=DexReader.readApk(probe); Files.deleteIfExists(probe);
        LinkedHashSet<String> expected=new LinkedHashSet<>(originalClasses.keySet());
        expected.removeAll(removal); expected.addAll(replClasses.keySet());
        LinkedHashSet<String> actual=new LinkedHashSet<>(); for(String fq:finalMap.keySet())actual.add(desc(fq));
        LinkedHashSet<String> missing=new LinkedHashSet<>(expected);missing.removeAll(actual);
        LinkedHashSet<String> extra=new LinkedHashSet<>(actual);extra.removeAll(expected);
        mergeLog("class universe counts: original=%d removal=%d replacement=%d expectedFinal=%d actualFinal=%d",originalClasses.size(),removal.size(),replClasses.size(),expected.size(),actual.size());
        if(!missing.isEmpty()||!extra.isEmpty()) {
            mergeItems("MISSING final class descriptors",missing,500);
            mergeItems("EXTRA final class descriptors",extra,500);
            throw new IllegalStateException("final DEX universe mismatch: missing="+missing+" extra="+extra);
        }
        mergeLog("final class universe: OK");

        // Structural ABI gate.  Instruction linkage alone cannot see Android lifecycle
        // callbacks, reflection, XML inflation, or framework entry points. Compare each
        // explicitly source-owned replacement against its original DEX declaration and
        // refuse hierarchy/kind/visible-member regressions before packaging.
        mergePhase("validate structural replacement ABI compatibility");
        Map<String,DexReader.Clazz> originalAbi=DexReader.readApk(a.apk);
        mergeLog("ABI gate input: explicitly requested replacement owners=%d",requestedRemove.size());
        RuntimeAbiValidator.AbiCompat abiCompat=RuntimeAbiValidator.validateReplacementAbi(originalAbi,finalMap,requestedRemove);
        mergeLog("ABI gate result: errors=%d warnings=%d",abiCompat.errors.size(),abiCompat.warnings.size());
        if(!abiCompat.warnings.isEmpty()) mergeItems("ABI compatibility warnings",abiCompat.warnings,200);
        if(!abiCompat.errors.isEmpty()) {
            mergeItems("ABI compatibility ERRORS",abiCompat.errors,500);
            throw new IllegalStateException("replacement ABI compatibility failed ("+abiCompat.errors.size()+"): "+
                    String.join(" | ",abiCompat.errors.subList(0,Math.min(20,abiCompat.errors.size()))));
        }

        // Runtime-linkage gate: D8 program instructions and declarations must resolve
        // against the final raw DEX universe (or the platform boot classpath).  This is
        // what catches a source/JADX alias that escaped RuntimeDealiaser before we ever
        // package/sign an APK.
        mergePhase("validate replacement -> final-runtime DEX references");
        mergeLog("runtime linkage gate input: replacementClasses=%d finalUniverseClasses=%d",replClasses.size(),finalMap.size());
        List<String> linkageErrors=dl.validateReplacementReferences(replClasses.values(), finalMap);
        mergeLog("runtime linkage gate result: errors=%d",linkageErrors.size());
        if(!linkageErrors.isEmpty()) {
            mergeItems("replacement runtime linkage ERRORS",linkageErrors,500);
            explainLinkageErrors(linkageErrors,finalMap,50);
            mergeLog("constructor bridge context: discovered=%d ambiguous=%d rewrites=%d",constructorBridges.targets.size(),constructorBridges.ambiguous.size(),constructorBridgeRewriteCount);
            if(!constructorBridgeRulesUsed.isEmpty()) mergeItems("constructor bridge rules actually used",constructorBridgeRulesUsed,200);
            throw new IllegalStateException("replacement DEX runtime linkage failed ("+linkageErrors.size()+"): "+String.join(" | ",linkageErrors.subList(0,Math.min(20,linkageErrors.size()))));
        }

        // Also validate the opposite edge of the replacement boundary.  Retained
        // original classes may call fields/methods on a source-owned class that we
        // just replaced.  A decompiler can omit a synthetic/private member and the
        // replacement would still compile, while an untouched original caller would
        // later fail with NoSuchMethodError/NoSuchFieldError.  Restrict this scan to
        // references whose defining owner is one of the replacement types so optional
        // references elsewhere in the original APK do not become false positives.
        mergePhase("validate retained-original -> replacement boundary references");
        List<ClassDef> retainedOriginal=new ArrayList<>();
        for(var e:originalClasses.entrySet()) if(!removal.contains(e.getKey())) retainedOriginal.add(e.getValue());
        mergeLog("reverse linkage gate input: retainedOriginalClasses=%d replacementTypes=%d",retainedOriginal.size(),replClasses.size());
        List<String> reverseLinkageErrors=dl.validateRetainedToReplacementReferences(
                retainedOriginal,replClasses.keySet(),finalMap);
        mergeLog("reverse linkage gate result: errors=%d",reverseLinkageErrors.size());
        if(!reverseLinkageErrors.isEmpty()) {
            mergeItems("retained -> replacement runtime linkage ERRORS",reverseLinkageErrors,500);
            explainLinkageErrors(reverseLinkageErrors,finalMap,50);
            throw new IllegalStateException("retained->replacement DEX linkage failed ("+reverseLinkageErrors.size()+"): "+String.join(" | ",reverseLinkageErrors.subList(0,Math.min(20,reverseLinkageErrors.size()))));
        }

        mergePhase("write merge report");
        StringBuilder j=new StringBuilder();
        j.append("{\n");
        kv(j,"dexlib_namespace","com.android.tools.smali.dexlib2",true); kv(j,"original_classes",originalClasses.size(),true);
        kv(j,"replacement_classes",replClasses.size(),true); kv(j,"removed_classes",removal.size(),true);
        kv(j,"retained_classes",retained,true); kv(j,"final_classes",actual.size(),true);
        j.append("  \"touched_dex\": ").append(arr(touched)).append(",\n");
        LinkedHashSet<String> untouched=new LinkedHashSet<>(dexEntries);untouched.removeAll(touched);
        j.append("  \"byte_copied_dex\": ").append(arr(untouched)).append(",\n");
        j.append("  \"appended_replacement_dex\": {"); boolean fa=true; for(var e:appendedReplacementDex.entrySet()){if(!fa)j.append(',');fa=false;j.append("\n    ").append(q(e.getKey())).append(": ").append(q(e.getValue()));} if(!appendedReplacementDex.isEmpty())j.append('\n').append("  "); j.append("},\n");
        j.append("  \"removed\": ").append(arr(removal)).append(",\n");
        j.append("  \"replacement\": ").append(arr(replClasses.keySet())).append(",\n");
        kv(j,"constructor_bridge_rules_discovered",constructorBridges.targets.size(),true);
        kv(j,"constructor_bridge_rewrites",constructorBridgeRewriteCount,true);
        j.append("  \"constructor_bridge_rules_used\": ").append(arr(constructorBridgeRulesUsed)).append(",\n");
        kv(j,"runtime_linkage_errors",linkageErrors.size(),true);
        kv(j,"reverse_runtime_linkage_errors",reverseLinkageErrors.size(),true);
        kv(j,"abi_compatibility_errors",abiCompat.errors.size(),true);
        kv(j,"abi_compatibility_warnings",abiCompat.warnings.size(),true);
        j.append("  \"abi_warnings\": ").append(arr(abiCompat.warnings)).append(",\n");
        j.append("  \"sha256\": {"); boolean fh=true;for(var e:outHash.entrySet()){if(!fh)j.append(',');fh=false;j.append("\n    ").append(q(e.getKey())).append(": ").append(q(e.getValue()));}if(!outHash.isEmpty())j.append('\n').append("  ");j.append("}\n}\n");
        if(a.report!=null){
            Files.createDirectories(a.report.toAbsolutePath().getParent());Files.writeString(a.report,j);
            mergeLog("merge report written: %s (%s)",a.report.toAbsolutePath(),humanBytes(Files.size(a.report)));
        }
        mergePhase("merge complete");
        mergeLog("summary: originalClasses=%d removed=%d retained=%d replacementClasses=%d finalClasses=%d touchedDex=%d appendedDex=%d",
                originalClasses.size(),removed,retained,replClasses.size(),actual.size(),touched.size(),appendedReplacementDex.size());
        mergeLog("SUCCESS");
        System.out.print(j);
    }


    /**
     * Expand symbolic linkage failures into useful ABI context.  The validator's
     * compact error remains the authority; this diagnostic tells us what the final
     * DEX universe actually declares on the referenced owner and its hierarchy.
     */
    private static void explainLinkageErrors(List<String> errors, Map<String,DexReader.Clazz> universe, int limit) {
        if (!MERGE_VERBOSE || errors==null || errors.isEmpty()) return;
        mergeLog("linkage ABI context follows (up to %d failures)",Math.min(limit,errors.size()));
        int shown=0;
        for(String error:errors){
            if(shown++>=limit) break;
            int mm=error.indexOf("missing method ");
            int mf=error.indexOf("missing field ");
            if(mm>=0){
                String ref=error.substring(mm+"missing method ".length()).trim();
                int arrow=ref.indexOf("->");
                int paren=ref.indexOf('(',arrow+2);
                if(arrow<0||paren<0){mergeLog("  cannot parse method failure: %s",ref);continue;}
                String owner=ref.substring(0,arrow), name=ref.substring(arrow+2,paren);
                String desc=ref.substring(paren);
                mergeLog("  missing method detail: owner=%s name=%s desc=%s",owner,name,desc);
                explainOwner(owner,name,true,universe);
            } else if(mf>=0){
                String ref=error.substring(mf+"missing field ".length()).trim();
                int arrow=ref.indexOf("->"), colon=ref.lastIndexOf(':');
                if(arrow<0||colon<arrow){mergeLog("  cannot parse field failure: %s",ref);continue;}
                String owner=ref.substring(0,arrow), name=ref.substring(arrow+2,colon), desc=ref.substring(colon+1);
                mergeLog("  missing field detail: owner=%s name=%s type=%s",owner,name,desc);
                explainOwner(owner,name,false,universe);
            }
        }
    }

    private static void explainOwner(String ownerDesc, String memberName, boolean method, Map<String,DexReader.Clazz> universe) {
        String cur=ownerDesc;
        HashSet<String> seen=new HashSet<>();
        for(int depth=0; depth<12 && cur!=null && !externalForDiag(cur); depth++){
            String f=fqForDiag(cur);
            if(f==null || !seen.add(f)) break;
            DexReader.Clazz c=universe.get(f);
            if(c==null){
                mergeLog("    hierarchy[%d] %s: NOT PRESENT in final DEX universe",depth,cur);
                break;
            }
            mergeLog("    hierarchy[%d] %s: dex=%s super=%s interfaces=%s declaredMethods=%d declaredFields=%d",
                    depth,cur,c.dexEntry,c.superDesc,c.interfaces,c.methods.size(),c.fields.size());
            if(method){
                List<String> sameName=new ArrayList<>();
                List<String> ctors=new ArrayList<>();
                for(DexReader.Method m:c.methods){
                    if(m.name.equals(memberName)) sameName.add(m.name+m.desc+" access=0x"+Integer.toHexString(m.access));
                    if(m.name.equals("<init>")) ctors.add(m.name+m.desc+" access=0x"+Integer.toHexString(m.access));
                }
                if(!sameName.isEmpty()) mergeItems("    declared methods named "+memberName+" on "+cur,sameName,50);
                if(memberName.equals("<init>") || sameName.isEmpty()) mergeItems("    declared constructors on "+cur,ctors,50);
            } else {
                List<String> sameName=new ArrayList<>();
                for(DexReader.Field f0:c.fields) if(f0.name.equals(memberName))
                    sameName.add(f0.name+":"+f0.desc+" access=0x"+Integer.toHexString(f0.access));
                mergeItems("    declared fields named "+memberName+" on "+cur,sameName,50);
            }
            cur=c.superDesc;
        }
    }

    private static String fqForDiag(String d){
        if(d==null)return null; while(d.startsWith("["))d=d.substring(1);
        return d.startsWith("L")&&d.endsWith(";")?d.substring(1,d.length()-1).replace('/','.') : null;
    }

    private static boolean externalForDiag(String d){
        if(d==null||d.isEmpty())return true; while(d.startsWith("["))d=d.substring(1);
        if(d.length()==1)return true;
        return d.startsWith("Ljava/")||d.startsWith("Ljavax/")||d.startsWith("Landroid/")||
               d.startsWith("Ldalvik/")||d.startsWith("Lcom/android/internal/")||d.startsWith("Lorg/w3c/")||
               d.startsWith("Lorg/xml/")||d.startsWith("Ljdk/")||d.startsWith("Lsun/");
    }

    /** Direct adapter for the official com.android.tools.smali:smali-dexlib2 API. */
    private static final class Dexlib {
        final Opcodes opcodes;

        Dexlib(int api) {
            opcodes=Opcodes.forApi(api);
        }

        DexBackedDexFile readDex(byte[] b) throws IOException {
            try(InputStream in=new BufferedInputStream(new ByteArrayInputStream(b))){
                return DexBackedDexFile.fromInputStream(opcodes,in);
            }
        }

        List<ClassDef> classes(DexFile df) {
            return new ArrayList<>(df.getClasses());
        }

        String type(ClassDef c) { return c.getType(); }
        Opcodes dexOpcodes(DexFile dexFile) { return dexFile.getOpcodes(); }

        void writeDex(Path out,Collection<? extends ClassDef> classes,Opcodes outputOpcodes) throws IOException {
            DexFile view=new DexFile(){
                @Override public Set<? extends ClassDef> getClasses(){ return new LinkedHashSet<>(classes); }
                @Override public Opcodes getOpcodes(){ return outputOpcodes; }
            };
            Files.createDirectories(out.toAbsolutePath().getParent());
            DexPool.writeTo(out.toString(),view);
        }

        static final class ConstructorBridgePlan {
            final Map<String,String> targets;
            final Map<String,Set<String>> ambiguous;
            ConstructorBridgePlan(Map<String,String> targets,Map<String,Set<String>> ambiguous){
                this.targets=targets; this.ambiguous=ambiguous;
            }
        }

        static final class LoweredDex {
            final DexFile dex;
            final int rewrites;
            final List<String> rulesUsed;
            LoweredDex(DexFile dex,int rewrites,List<String> rulesUsed){this.dex=dex;this.rewrites=rewrites;this.rulesUsed=rulesUsed;}
        }

        /**
         * R8/D8 can leave a DEX class with no declared <init> and instantiate it by
         * invoking the direct superclass constructor on the newly allocated register:
         *
         *   new-instance v0, LT;
         *   invoke-direct {v0,...}, LS;-><init>(...)V   // S == direct superclass of T
         *
         * Java classfiles cannot encode this. javac therefore sees a compile-only
         * facade constructor T.<init>, which D8 faithfully emits back as a method ref
         * that does not exist in the original runtime ABI. Learn only those bridge
         * rules actually observed in the original APK. Ambiguous rules are refused.
         */
        ConstructorBridgePlan discoverConstructorBridges(Collection<? extends ClassDef> classes) {
            LinkedHashMap<String,ClassDef> byType=new LinkedHashMap<>();
            for(ClassDef c:classes) byType.put(c.getType(),c);
            LinkedHashMap<String,LinkedHashSet<String>> candidates=new LinkedHashMap<>();

            for(ClassDef owner:classes) for(Method method:owner.getMethods()) {
                MethodImplementation impl=method.getImplementation();
                if(impl==null) continue;
                HashMap<Integer,String> pendingNew=new HashMap<>();
                for(Instruction insn:impl.getInstructions()) {
                    Opcode op=insn.getOpcode();
                    if(op==Opcode.NEW_INSTANCE && insn instanceof OneRegisterInstruction r &&
                       insn instanceof ReferenceInstruction rr && rr.getReference() instanceof TypeReference tr) {
                        pendingNew.put(r.getRegisterA(),tr.getType());
                        continue;
                    }

                    if((op==Opcode.INVOKE_DIRECT || op==Opcode.INVOKE_DIRECT_RANGE) &&
                       insn instanceof ReferenceInstruction rr && rr.getReference() instanceof MethodReference mr &&
                       mr.getName().equals("<init>")) {
                        int receiver=firstInvokeRegister(insn);
                        String allocated=pendingNew.get(receiver);
                        if(allocated!=null) {
                            String target=mr.getDefiningClass(), d=methodDesc(mr);
                            ClassDef allocatedClass=byType.get(allocated);
                            if(allocatedClass!=null && !allocated.equals(target) &&
                               Objects.equals(allocatedClass.getSuperclass(),target) &&
                               !declaresConstructor(allocatedClass,d)) {
                                candidates.computeIfAbsent(ctorKey(allocated,d),k->new LinkedHashSet<>()).add(target);
                            }
                            pendingNew.remove(receiver);
                        }
                        continue;
                    }

                    // Preserve the allocation type through ordinary object moves while
                    // waiting for constructor arguments to be prepared in other regs.
                    if((op==Opcode.MOVE_OBJECT || op==Opcode.MOVE_OBJECT_FROM16 || op==Opcode.MOVE_OBJECT_16) &&
                       insn instanceof TwoRegisterInstruction r) {
                        String t=pendingNew.get(r.getRegisterB());
                        if(t==null) pendingNew.remove(r.getRegisterA()); else pendingNew.put(r.getRegisterA(),t);
                        continue;
                    }

                    // Any other register-producing instruction kills a pending NEW value
                    // in its destination register.
                    if(op.setsRegister() && insn instanceof OneRegisterInstruction r)
                        pendingNew.remove(r.getRegisterA());
                }
            }

            LinkedHashMap<String,String> targets=new LinkedHashMap<>();
            LinkedHashMap<String,Set<String>> ambiguous=new LinkedHashMap<>();
            for(var e:candidates.entrySet()) {
                if(e.getValue().size()==1) targets.put(e.getKey(),e.getValue().iterator().next());
                else ambiguous.put(e.getKey(),Collections.unmodifiableSet(e.getValue()));
            }
            return new ConstructorBridgePlan(Collections.unmodifiableMap(targets),Collections.unmodifiableMap(ambiguous));
        }

        LoweredDex lowerConstructorBridges(DexFile dex,ConstructorBridgePlan plan) {
            if(plan.targets.isEmpty()) return new LoweredDex(dex,0,List.of());
            int rewrites=0;
            LinkedHashSet<String> used=new LinkedHashSet<>();
            for(ClassDef c:dex.getClasses()) for(Method m:c.getMethods()) {
                MethodImplementation impl=m.getImplementation(); if(impl==null)continue;
                for(Instruction insn:impl.getInstructions()) {
                    MethodReference mr=constructorReference(insn); if(mr==null)continue;
                    String d=methodDesc(mr), target=plan.targets.get(ctorKey(mr.getDefiningClass(),d));
                    if(target!=null) { rewrites++; used.add(bridgeRule(mr.getDefiningClass(),d,target)); }
                }
            }
            if(rewrites==0) return new LoweredDex(dex,0,List.of());

            RewriterModule module=new RewriterModule(){
                @Override public Rewriter<Instruction> getInstructionRewriter(Rewriters rewriters){
                    return new InstructionRewriter(rewriters){
                        @Override public Instruction rewrite(Instruction instruction){
                            Instruction base=super.rewrite(instruction);
                            MethodReference mr=constructorReference(base); if(mr==null)return base;
                            String d=methodDesc(mr), target=plan.targets.get(ctorKey(mr.getDefiningClass(),d));
                            if(target==null)return base;
                            ImmutableMethodReference ref=new ImmutableMethodReference(target,"<init>",mr.getParameterTypes(),mr.getReturnType());
                            if(base instanceof Instruction35c x)
                                return new ImmutableInstruction35c(base.getOpcode(),x.getRegisterCount(),x.getRegisterC(),x.getRegisterD(),x.getRegisterE(),x.getRegisterF(),x.getRegisterG(),ref);
                            if(base instanceof Instruction3rc x)
                                return new ImmutableInstruction3rc(base.getOpcode(),x.getStartRegister(),x.getRegisterCount(),ref);
                            throw new IllegalStateException("unsupported invoke-direct constructor instruction format: "+base.getClass().getName());
                        }
                    };
                }
            };
            DexFile lowered=new DexRewriter(module).getDexFileRewriter().rewrite(dex);
            return new LoweredDex(lowered,rewrites,new ArrayList<>(used));
        }

        private static MethodReference constructorReference(Instruction insn) {
            Opcode op=insn.getOpcode();
            if(op!=Opcode.INVOKE_DIRECT && op!=Opcode.INVOKE_DIRECT_RANGE) return null;
            if(!(insn instanceof ReferenceInstruction r) || !(r.getReference() instanceof MethodReference m)) return null;
            return m.getName().equals("<init>") ? m : null;
        }

        private static int firstInvokeRegister(Instruction insn) {
            if(insn instanceof FiveRegisterInstruction x && x.getRegisterCount()>0) return x.getRegisterC();
            if(insn instanceof RegisterRangeInstruction x && x.getRegisterCount()>0) return x.getStartRegister();
            return -1;
        }

        private static boolean declaresConstructor(ClassDef c,String desc) {
            for(Method m:c.getMethods()) if(m.getName().equals("<init>") && methodDesc(m).equals(desc)) return true;
            return false;
        }

        private static String ctorKey(String owner,String desc){ return owner+"#<init>"+desc; }
        private static String bridgeRule(String allocated,String desc,String target){
            return allocated+"-><init>"+desc+" => "+target+"-><init>"+desc;
        }

        List<String> validateReplacementReferences(Collection<? extends ClassDef> replacement,
                                                    Map<String,DexReader.Clazz> universe) {
            LinkedHashSet<String> errors=new LinkedHashSet<>();
            LinkedHashSet<String> replacementTypes=new LinkedHashSet<>();
            for(ClassDef c:replacement) replacementTypes.add(c.getType());

            // Declarations, annotations and encoded constants can contain runtime
            // references even when no executable instruction directly mentions them.
            for(ClassDef cdef:replacement){
                String t=cdef.getType();
                DexReader.Clazz c=universe.get(fq(t));
                if(c==null){ errors.add("replacement class missing after merge: "+t); continue; }
                checkType(c.superDesc,universe,errors,"super of "+t);
                for(String x:c.interfaces) checkType(x,universe,errors,"interface of "+t);
                for(DexReader.Field f:c.fields) checkDescriptorTypes(f.desc,universe,errors,t+"."+f.name);
                for(DexReader.Method m:c.methods) checkDescriptorTypes(m.desc,universe,errors,t+"."+m.name+m.desc);
                checkAnnotations(cdef.getAnnotations(),universe,errors,t+" annotations");
                for(Field f:cdef.getFields()){
                    checkType(f.getType(),universe,errors,t+"."+f.getName());
                    checkEncodedValue(f.getInitialValue(),universe,errors,t+"."+f.getName()+" initial-value");
                    checkAnnotations(f.getAnnotations(),universe,errors,t+"."+f.getName()+" annotations");
                }
                for(Method m:cdef.getMethods()){
                    checkDescriptorTypes(methodDesc(m),universe,errors,t+"."+m.getName());
                    checkAnnotations(m.getAnnotations(),universe,errors,t+"."+m.getName()+" annotations");
                    int pi=0;
                    for(MethodParameter p:m.getParameters()){
                        checkType(p.getType(),universe,errors,t+"."+m.getName()+" param "+pi);
                        checkAnnotations(p.getAnnotations(),universe,errors,t+"."+m.getName()+" param "+pi+" annotations");
                        pi++;
                    }
                }
            }

            for(ClassDef c:replacement){
                String owner=c.getType();
                for(Method method:c.getMethods()){
                    String mn=method.getName();
                    MethodImplementation impl=method.getImplementation();
                    if(impl==null) continue;
                    int pc=0;
                    for(Instruction insn:impl.getInstructions()){
                        if(insn instanceof ReferenceInstruction r)
                            checkReference(r.getReference(),universe,errors,owner+"."+mn+"@"+pc);
                        if(insn instanceof DualReferenceInstruction r)
                            checkReference(r.getReference2(),universe,errors,owner+"."+mn+"@"+pc+"#2");
                        pc+=insn.getCodeUnits();
                    }
                }
            }
            return new ArrayList<>(errors);
        }

        List<String> validateRetainedToReplacementReferences(Collection<? extends ClassDef> retained,
                                                               Collection<String> replacementTypes,
                                                               Map<String,DexReader.Clazz> universe) {
            LinkedHashSet<String> errors=new LinkedHashSet<>();
            LinkedHashSet<String> targets=new LinkedHashSet<>(replacementTypes);
            for(ClassDef c:retained){
                String owner=c.getType();
                for(Method method:c.getMethods()){
                    String mn=method.getName();
                    MethodImplementation impl=method.getImplementation();
                    if(impl==null) continue;
                    int pc=0;
                    for(Instruction insn:impl.getInstructions()){
                        if(insn instanceof ReferenceInstruction r){
                            Reference ref=r.getReference();
                            if(referenceTargetsOwner(ref,targets))
                                checkReference(ref,universe,errors,owner+"."+mn+"@"+pc+" -> replacement");
                        }
                        if(insn instanceof DualReferenceInstruction r){
                            Reference ref=r.getReference2();
                            if(referenceTargetsOwner(ref,targets))
                                checkReference(ref,universe,errors,owner+"."+mn+"@"+pc+"#2 -> replacement");
                        }
                        pc+=insn.getCodeUnits();
                    }
                }
            }
            return new ArrayList<>(errors);
        }

        private static boolean referenceTargetsOwner(Reference ref,Set<String> targets){
            if(ref instanceof MethodReference m) return targets.contains(m.getDefiningClass());
            if(ref instanceof FieldReference f) return targets.contains(f.getDefiningClass());
            if(ref instanceof MethodHandleReference h) return referenceTargetsOwner(h.getMemberReference(),targets);
            if(ref instanceof CallSiteReference c){
                if(referenceTargetsOwner(c.getMethodHandle(),targets)) return true;
                for(EncodedValue x:c.getExtraArguments()) if(encodedValueTargetsOwner(x,targets)) return true;
            }
            return false;
        }

        private static boolean encodedValueTargetsOwner(EncodedValue v,Set<String> targets){
            if(v==null) return false;
            if(v instanceof MethodEncodedValue x) return referenceTargetsOwner(x.getValue(),targets);
            if(v instanceof MethodHandleEncodedValue x) return referenceTargetsOwner(x.getValue(),targets);
            if(v instanceof FieldEncodedValue x) return referenceTargetsOwner(x.getValue(),targets);
            if(v instanceof EnumEncodedValue x) return referenceTargetsOwner(x.getValue(),targets);
            if(v instanceof ArrayEncodedValue x){ for(EncodedValue y:x.getValue()) if(encodedValueTargetsOwner(y,targets)) return true; }
            if(v instanceof AnnotationEncodedValue x){ for(AnnotationElement e:x.getElements()) if(encodedValueTargetsOwner(e.getValue(),targets)) return true; }
            return false;
        }

        private static String fq(String d){
            if(d==null)return null;while(d.startsWith("["))d=d.substring(1);
            return d.startsWith("L")&&d.endsWith(";")?d.substring(1,d.length()-1).replace('/','.') : null;
        }
        private static boolean external(String d){
            if(d==null||d.isEmpty())return true;while(d.startsWith("["))d=d.substring(1);
            if(d.length()==1)return true;
            return d.startsWith("Ljava/")||d.startsWith("Ljavax/")||d.startsWith("Landroid/")||
                   d.startsWith("Ldalvik/")||d.startsWith("Lcom/android/internal/")||d.startsWith("Lorg/w3c/")||
                   d.startsWith("Lorg/xml/")||d.startsWith("Ljdk/")||d.startsWith("Lsun/");
        }
        private static void checkType(String d,Map<String,DexReader.Clazz> u,Set<String> errors,String where){
            if(d==null||external(d))return;String f=fq(d);if(f!=null&&!u.containsKey(f))errors.add(where+": missing type "+d);
        }
        private static void checkDescriptorTypes(String d,Map<String,DexReader.Clazz> u,Set<String> errors,String where){
            if(d==null)return;for(int i=0;i<d.length();){if(d.charAt(i)!='L'){i++;continue;}int e=d.indexOf(';',i);if(e<0)break;checkType(d.substring(i,e+1),u,errors,where);i=e+1;}
        }
        private static String methodDesc(MethodReference ref){
            StringBuilder b=new StringBuilder("(");for(CharSequence p:ref.getParameterTypes())b.append(p);return b.append(')').append(ref.getReturnType()).toString();
        }
        private static String methodDesc(MethodProtoReference ref){
            StringBuilder b=new StringBuilder("(");for(CharSequence p:ref.getParameterTypes())b.append(p);return b.append(')').append(ref.getReturnType()).toString();
        }
        private static void checkReference(Reference ref,Map<String,DexReader.Clazz> u,Set<String> errors,String where){
            if(ref==null)return;
            if(ref instanceof MethodReference m){
                String d=methodDesc(m);checkDescriptorTypes(d,u,errors,where);
                if(!resolveMethod(m.getDefiningClass(),m.getName(),d,u,new HashSet<>()))
                    errors.add(where+": missing method "+m.getDefiningClass()+"->"+m.getName()+d);
                return;
            }
            if(ref instanceof FieldReference f){
                checkType(f.getType(),u,errors,where);
                if(!resolveField(f.getDefiningClass(),f.getName(),f.getType(),u,new HashSet<>()))
                    errors.add(where+": missing field "+f.getDefiningClass()+"->"+f.getName()+":"+f.getType());
                return;
            }
            if(ref instanceof TypeReference t){ checkType(t.getType(),u,errors,where); return; }
            if(ref instanceof MethodProtoReference p){ checkDescriptorTypes(methodDesc(p),u,errors,where); return; }
            if(ref instanceof MethodHandleReference h){ checkReference(h.getMemberReference(),u,errors,where+"/method-handle"); return; }
            if(ref instanceof CallSiteReference c){
                checkReference(c.getMethodHandle(),u,errors,where+"/call-site-handle");
                checkReference(c.getMethodProto(),u,errors,where+"/call-site-proto");
                int i=0;for(EncodedValue x:c.getExtraArguments())checkEncodedValue(x,u,errors,where+"/call-site-arg-"+(i++));
            }
        }
        private static void checkEncodedValue(EncodedValue v,Map<String,DexReader.Clazz> u,Set<String> errors,String where){
            if(v==null)return;
            if(v instanceof TypeEncodedValue x){checkType(x.getValue(),u,errors,where);return;}
            if(v instanceof MethodEncodedValue x){checkReference(x.getValue(),u,errors,where);return;}
            if(v instanceof MethodHandleEncodedValue x){checkReference(x.getValue(),u,errors,where);return;}
            if(v instanceof MethodTypeEncodedValue x){checkReference(x.getValue(),u,errors,where);return;}
            if(v instanceof FieldEncodedValue x){checkReference(x.getValue(),u,errors,where);return;}
            if(v instanceof EnumEncodedValue x){checkReference(x.getValue(),u,errors,where);return;}
            if(v instanceof ArrayEncodedValue x){int i=0;for(EncodedValue y:x.getValue())checkEncodedValue(y,u,errors,where+"["+(i++)+"]");return;}
            if(v instanceof AnnotationEncodedValue x){
                checkType(x.getType(),u,errors,where+" annotation-type");
                for(AnnotationElement e:x.getElements())checkEncodedValue(e.getValue(),u,errors,where+"."+e.getName());
            }
        }
        private static void checkAnnotations(Iterable<? extends Annotation> annotations,Map<String,DexReader.Clazz> u,Set<String> errors,String where){
            if(annotations==null)return;
            for(Annotation a:annotations){
                checkType(a.getType(),u,errors,where+" type");
                for(AnnotationElement e:a.getElements())checkEncodedValue(e.getValue(),u,errors,where+"."+e.getName());
            }
        }
        private static boolean resolveMethod(String owner,String name,String desc,Map<String,DexReader.Clazz> u,Set<String> seen){
            if(external(owner))return true;String f=fq(owner);if(f==null)return true;DexReader.Clazz c=u.get(f);if(c==null)return false;
            if(!seen.add(f))return false;
            for(DexReader.Method m:c.methods)if(m.name.equals(name)&&m.desc.equals(desc))return true;
            if(name.equals("<init>")||name.equals("<clinit>"))return false;
            if(c.superDesc!=null){
                if(external(c.superDesc)){ if(!looksJadxMemberAlias(name)) return true; }
                else if(resolveMethod(c.superDesc,name,desc,u,seen))return true;
            }
            for(String i:c.interfaces){
                if(external(i)){ if(!looksJadxMemberAlias(name)) return true; }
                else if(resolveMethod(i,name,desc,u,seen))return true;
            }
            return false;
        }
        private static boolean resolveField(String owner,String name,String desc,Map<String,DexReader.Clazz> u,Set<String> seen){
            if(external(owner))return true;String f=fq(owner);if(f==null)return true;DexReader.Clazz c=u.get(f);if(c==null)return false;
            if(!seen.add(f))return false;for(DexReader.Field x:c.fields)if(x.name.equals(name)&&x.desc.equals(desc))return true;
            if(c.superDesc!=null){
                if(external(c.superDesc)){ if(!looksJadxMemberAlias(name)) return true; }
                else if(resolveField(c.superDesc,name,desc,u,seen))return true;
            }
            for(String i:c.interfaces){
                if(external(i)){ if(!looksJadxMemberAlias(name)) return true; }
                else if(resolveField(i,name,desc,u,seen))return true;
            }
            return false;
        }
        private static boolean looksJadxMemberAlias(String n){return n!=null&&n.matches("(?:m|mo|f)\\d+.*");}
    }



    private static int dexEntryCompare(String a,String b){return Integer.compare(dexNum(a),dexNum(b));}
    private static int dexNum(String s){if(s.equals("classes.dex"))return 1;try{return Integer.parseInt(s.substring(7,s.length()-4));}catch(Exception e){return Integer.MAX_VALUE;}}
    private static String sha256(Path p)throws Exception{MessageDigest md=MessageDigest.getInstance("SHA-256");try(InputStream in=Files.newInputStream(p)){byte[]b=new byte[1<<16];for(int n;(n=in.read(b))>0;)md.update(b,0,n);}StringBuilder s=new StringBuilder();for(byte x:md.digest())s.append(String.format("%02x",x));return s.toString();}
    private static String q(String s){return "\""+s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n")+"\"";}
    private static String arr(Collection<String> xs){StringBuilder b=new StringBuilder("[");boolean f=true;for(String x:xs){if(!f)b.append(',');f=false;b.append(q(x));}return b.append(']').toString();}
    private static void kv(StringBuilder b,String k,Object v,boolean comma){b.append("  ").append(q(k)).append(": ");if(v instanceof Number||v instanceof Boolean)b.append(v);else b.append(q(String.valueOf(v)));if(comma)b.append(',');b.append('\n');}
}
