import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.*;

/** Recover confirmed, already-decoded ROM entries without changing code units or context. */
public class RecoverDecoded extends GhidraScript {
  private static final Gson GSON = new GsonBuilder().serializeNulls().setPrettyPrinting().create();
  private static final int DECOMP_SECONDS = 15;

  private static final class Target {
    String mode, name;
    Address address;
    Target(String mode, Address address, String name) {
      this.mode = mode; this.address = address; this.name = name;
    }
  }

  private static final class Result {
    String address, mode, repo_name, status, function_name = "", tmode = "";
    String detail = "", decompile_status = "skipped", decompile_error = "";
    String c_file = "", asm_file = "";
    int warning_count = 0;
    boolean decompile_completed = false;
    long body_size = 0;
    List<Map<String, String>> body_ranges = new ArrayList<Map<String, String>>();
    Result(Target t) {
      address = hex(t.address); mode = t.mode; repo_name = t.name;
    }
  }

  @Override public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 2)
      throw new IllegalArgumentException("usage: RecoverDecoded.java <targets.tsv> <output-directory>");
    Path out = Paths.get(args[1]); Files.createDirectories(out);
    List<Target> targets = readTargets(Paths.get(args[0]));

    Map<String, Object> before = snapshot(targets);
    writeJson(out.resolve("before.json"), before);
    List<Result> results = new ArrayList<Result>();
    for (Target t : targets) {
      monitor.checkCancelled();
      Result r = recover(t, out);
      results.add(r);
      println("RECOVER " + r.address + " " + r.status + " " + r.function_name + " " + r.detail);
    }
    Map<String, Object> after = snapshot(targets);
    writeJson(out.resolve("after.json"), after);
    Map<String, Object> report = new LinkedHashMap<String, Object>();
    report.put("results", results);
    List<Result> preexisting = new ArrayList<Result>();
    for (Result r : results) if ("preexisting".equals(r.status)) preexisting.add(r);
    report.put("preexisting_entries", preexisting);
    report.put("target_count", results.size());
    report.put("invariants", compareSnapshots(before, after));
    writeJson(out.resolve("targets.json"), report);
  }

  private List<Target> readTargets(Path path) throws IOException {
    List<Target> out = new ArrayList<Target>(); Set<String> seen = new HashSet<String>(); int n = 0;
    for (String raw : Files.readAllLines(path, StandardCharsets.UTF_8)) {
      n++; String line = raw.trim();
      if (line.isEmpty() || line.startsWith("#")) continue;
      String[] f = line.split("\\t", -1);
      if (f.length != 3) throw new IOException("invalid TSV row " + n + ": expected mode<TAB>address<TAB>name");
      String mode = f[0].trim().toLowerCase(Locale.ROOT);
      if (!mode.equals("arm") && !mode.equals("thumb")) throw new IOException("invalid mode at row " + n + ": " + mode);
      Address a = toAddr(f[1].trim());
      if (!seen.add(a.toString())) throw new IOException("duplicate address at row " + n + ": " + a);
      if (f[2].trim().isEmpty()) throw new IOException("empty name at row " + n);
      out.add(new Target(mode, a, f[2].trim()));
    }
    return out;
  }

  private Result recover(Target t, Path out) throws Exception {
    Result r = new Result(t);
    FunctionManager fm = currentProgram.getFunctionManager();
    Function f = fm.getFunctionAt(t.address);
    r.tmode = tmode(t.address);
    Instruction ins = currentProgram.getListing().getInstructionAt(t.address);
    if (f != null) {
      r.status = "preexisting"; r.function_name = f.getName(); r.detail = "function already existed; preserved";
      fillBody(r, f); return r;
    }
    if (ins == null) {
      r.status = "missing_entry_instruction"; r.detail = "no instruction exactly at target; no disassembly attempted"; return r;
    }
    String expected = t.mode.equals("thumb") ? "1" : "0";
    if (!expected.equals(r.tmode)) {
      r.status = "wrong_tmode"; r.detail = "expected TMode=" + expected + "; no context or code-unit changes attempted"; return r;
    }

    CreateFunctionCmd cmd = new CreateFunctionCmd(t.name, t.address, null, SourceType.USER_DEFINED);
    boolean ok = cmd.applyTo(currentProgram, monitor);
    f = fm.getFunctionAt(t.address);
    if (!ok || f == null) {
      r.status = "create_failed";
      r.detail = cmd.getStatusMsg() == null ? "CreateFunctionCmd did not create a function" : cmd.getStatusMsg();
      return r;
    }
    r.status = "created"; r.function_name = f.getName(); r.detail = "CreateFunctionCmd accepted existing decoded entry";
    fillBody(r, f);
    r.asm_file = fileStem(t) + ".asm"; writeAsm(out.resolve(r.asm_file), f);
    decompile(out, t, f, r);
    return r;
  }

  private void fillBody(Result r, Function f) {
    r.body_size = f.getBody().getNumAddresses();
    for (AddressRange range : f.getBody().getAddressRanges()) {
      Map<String, String> item = new LinkedHashMap<String, String>();
      item.put("start", hex(range.getMinAddress())); item.put("end", hex(range.getMaxAddress()));
      r.body_ranges.add(item);
    }
  }

  private void decompile(Path out, Target t, Function f, Result r) {
    DecompInterface di = new DecompInterface();
    try {
      if (!di.openProgram(currentProgram)) {
        r.decompile_status = "open_failed"; r.decompile_error = safe(di.getLastMessage()); return;
      }
      DecompileResults d = di.decompileFunction(f, DECOMP_SECONDS, monitor);
      if (d == null) {
        r.decompile_status = "no_result"; r.decompile_error = safe(di.getLastMessage()); return;
      }
      if (d.getDecompiledFunction() != null) {
        String c = d.getDecompiledFunction().getC();
        r.c_file = fileStem(t) + ".c";
        Files.write(out.resolve(r.c_file), c.getBytes(StandardCharsets.UTF_8));
        r.warning_count = countWarnings(c);
      }
      r.decompile_completed = d.decompileCompleted();
      r.decompile_status = r.decompile_completed ? "completed" : "incomplete";
      if (!d.decompileCompleted()) r.decompile_error = firstNonempty(d.getErrorMessage(), di.getLastMessage());
    } catch (Exception e) {
      r.decompile_status = "error"; r.decompile_error = e.getClass().getSimpleName() + ": " + safe(e.getMessage());
    } finally { di.dispose(); }
  }

  private void writeAsm(Path path, Function f) throws IOException {
    try (BufferedWriter w = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
      w.write("; " + f.getName() + " " + hex(f.getEntryPoint()) + " body=" + f.getBody().getNumAddresses() + " bytes\n");
      InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
      while (it.hasNext()) {
        Instruction i = it.next();
        w.write(hex(i.getAddress()) + "  " + i + "\n");
      }
    }
  }

  /** cmp.py consumes normalized_result entries with address/value/procedure fields. */
  private Map<String, Object> exportProcedures() {
    List<Map<String, Object>> normalized = new ArrayList<Map<String, Object>>();
    List<Function> fs = allFunctions();
    for (Function f : fs) {
      if (f.isExternal()) continue;
      Function thunk = f.isThunk() ? f.getThunkedFunction(false) : null;
      Map<String, Object> proc = new LinkedHashMap<String, Object>();
      proc.put("external", f.isExternal()); proc.put("thunk", f.isThunk());
      proc.put("thunk_target", thunk == null ? null : hex(thunk.getEntryPoint()));
      Map<String, Object> item = new LinkedHashMap<String, Object>();
      item.put("address", hex(f.getEntryPoint())); item.put("value", f.getName()); item.put("procedure", proc);
      normalized.add(item);
    }
    Map<String, Object> result = new LinkedHashMap<String, Object>(); result.put("normalized_result", normalized);
    return result;
  }

  private Map<String, Object> snapshot(List<Target> targets) throws Exception {
    Map<String, Object> s = new LinkedHashMap<String, Object>();
    s.put("program", currentProgram.getName()); s.put("language", currentProgram.getLanguageID().toString());
    s.put("compiler", currentProgram.getCompiler());
    List<String> entries = new ArrayList<String>();
    List<Map<String, Object>> bodies = new ArrayList<Map<String, Object>>();
    for (Function f : allFunctions()) {
      entries.add(hex(f.getEntryPoint()));
      Map<String, Object> b = new LinkedHashMap<String, Object>();
      b.put("entry", hex(f.getEntryPoint())); b.put("name", f.getName()); b.put("external", f.isExternal());
      List<Map<String, String>> ranges = new ArrayList<Map<String, String>>();
      for (AddressRange range : f.getBody().getAddressRanges()) {
        Map<String, String> rr = new LinkedHashMap<String, String>();
        rr.put("start", hex(range.getMinAddress())); rr.put("end", hex(range.getMaxAddress())); ranges.add(rr);
      }
      b.put("body_ranges", ranges); bodies.add(b);
    }
    s.put("function_entries", entries); s.put("functions", bodies); s.put("function_count", entries.size());
    s.put("normalized_result", exportProcedures().get("normalized_result"));
    s.put("initialized_memory_sha256", memoryHashes());
    List<Map<String, Object>> inspected = new ArrayList<Map<String, Object>>();
    for (Target t : targets) inspected.add(targetSnapshot(t));
    s.put("targets", inspected);
    return s;
  }

  private List<Function> allFunctions() {
    List<Function> fs = new ArrayList<Function>();
    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
    while (it.hasNext()) fs.add(it.next());
    Collections.sort(fs, new Comparator<Function>() {
      public int compare(Function a, Function b) { return a.getEntryPoint().compareTo(b.getEntryPoint()); }
    });
    return fs;
  }

  private Map<String, String> memoryHashes() throws Exception {
    Map<String, String> hashes = new LinkedHashMap<String, String>();
    byte[] buffer = new byte[65536];
    for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
      if (!block.isInitialized()) continue;
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      Address p = block.getStart();
      while (p.compareTo(block.getEnd()) <= 0) {
        long remaining = block.getEnd().subtract(p) + 1;
        int count = (int)Math.min((long)buffer.length, remaining);
        int got = currentProgram.getMemory().getBytes(p, buffer, 0, count);
        if (got != count) throw new IOException("short read hashing memory block " + block.getName() + " at " + p);
        digest.update(buffer, 0, got); p = p.add(got);
      }
      hashes.put(block.getName() + "@" + hex(block.getStart()) + ".." + hex(block.getEnd()), toHex(digest.digest()));
    }
    return hashes;
  }

  private Map<String, Object> targetSnapshot(Target t) throws Exception {
    Map<String, Object> x = new LinkedHashMap<String, Object>();
    x.put("mode", t.mode); x.put("address", hex(t.address)); x.put("repo_name", t.name);
    x.put("tmode", tmode(t.address)); x.put("entry_bytes", readBytes(t.address, 16));
    Instruction i = currentProgram.getListing().getInstructionAt(t.address);
    Map<String, Object> instruction = null;
    if (i != null) {
      instruction = new LinkedHashMap<String, Object>();
      instruction.put("address", hex(i.getAddress())); instruction.put("length", i.getLength());
      instruction.put("text", i.toString()); instruction.put("bytes", readBytes(i.getAddress(), i.getLength()));
      instruction.put("flow_type", i.getFlowType().toString());
      List<String> flows = new ArrayList<String>(); for (Address a : i.getFlows()) flows.add(hex(a));
      instruction.put("flows", flows);
      Address fall = i.getFallThrough(); instruction.put("fallthrough", fall == null ? null : hex(fall));
    }
    x.put("instruction_at_entry", instruction);
    List<Map<String, Object>> refs = new ArrayList<Map<String, Object>>();
    ReferenceIterator rit = currentProgram.getReferenceManager().getReferencesTo(t.address);
    while (rit.hasNext()) {
      Reference ref = rit.next(); Map<String, Object> entry = new LinkedHashMap<String, Object>();
      entry.put("source", hex(ref.getFromAddress())); entry.put("kind", ref.getReferenceType().toString());
      entry.put("operand_index", ref.getOperandIndex());
      refs.add(entry);
    }
    x.put("references_to_entry", refs);
    return x;
  }

  private String readBytes(Address a, int wanted) throws Exception {
    MemoryBlock b = currentProgram.getMemory().getBlock(a);
    if (b == null || !b.isInitialized()) return "";
    int n = (int)Math.min((long)wanted, b.getEnd().subtract(a) + 1);
    byte[] bytes = new byte[n]; int got = currentProgram.getMemory().getBytes(a, bytes);
    return toHex(Arrays.copyOf(bytes, got));
  }

  private Map<String, Object> compareSnapshots(Map<String, Object> before, Map<String, Object> after) {
    Map<String, Object> checks = new LinkedHashMap<String, Object>();
    checks.put("initialized_memory_hashes_unchanged", before.get("initialized_memory_sha256").equals(after.get("initialized_memory_sha256")));
    checks.put("target_bytes_tmode_instructions_and_references_unchanged", before.get("targets").equals(after.get("targets")));
    checks.put("all_function_names_and_bodies_unchanged", before.get("functions").equals(after.get("functions")));
    checks.put("function_entry_set_before", before.get("function_entries"));
    checks.put("function_entry_set_after", after.get("function_entries"));
    checks.put("function_entries_added", difference((List<?>)after.get("function_entries"), (List<?>)before.get("function_entries")));
    checks.put("function_entries_removed", difference((List<?>)before.get("function_entries"), (List<?>)after.get("function_entries")));
    return checks;
  }

  private List<Object> difference(List<?> a, List<?> b) {
    List<Object> out = new ArrayList<Object>(); for (Object v : a) if (!b.contains(v)) out.add(v); return out;
  }

  private String tmode(Address a) {
    Register r = currentProgram.getProgramContext().getRegister("TMode");
    if (r == null) return "missing-register";
    BigInteger value = currentProgram.getProgramContext().getValue(r, a, false);
    return value == null ? "undefined" : value.toString(16);
  }

  private void writeJson(Path path, Object value) throws IOException {
    Files.write(path, (GSON.toJson(value) + "\n").getBytes(StandardCharsets.UTF_8));
  }

  private static int countWarnings(String c) {
    int count = 0, from = 0;
    while ((from = c.indexOf("WARNING", from)) >= 0) { count++; from += 7; }
    return count;
  }
  private static String firstNonempty(String a, String b) { return a != null && !a.isEmpty() ? a : safe(b); }
  private static String safe(String s) { return s == null ? "" : s; }
  private static String fileStem(Target t) { return String.format(Locale.ROOT, "%08x_%s", t.address.getOffset(), t.name.replaceAll("[^A-Za-z0-9_.-]", "_")); }
  private static String hex(Address a) { return "0x" + Long.toHexString(a.getOffset()); }
  private static String toHex(byte[] b) {
    StringBuilder s = new StringBuilder(); for (byte v : b) s.append(String.format(Locale.ROOT, "%02x", v & 0xff)); return s.toString();
  }
}
