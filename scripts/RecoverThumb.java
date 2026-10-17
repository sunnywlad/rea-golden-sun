import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Ghidra headless postscript for recovering confirmed ARM Thumb entries from TSV. */
public class RecoverThumb extends GhidraScript {
  private static final int DECOMP_SECONDS = 15;
  private final List<Target> targets = new ArrayList<Target>();
  private final TreeSet<Address> repoStarts = new TreeSet<Address>();
  private static final class Target {
    final Address address; final String name;
    Target(Address a, String n) { address = a; name = n; }
  }
  private static final class Result {
    final String address, name;
    String status = "pending", detail = "", tmode = "", error = "", cFile = "", asmFile = "", preexistingName = "";
    long bodySize = 0;
    boolean disassembled = false, decompiled = false;
    Result(Target t) { address = hex(t.address); name = t.name; }
  }
  private static final class Failure extends Exception {}

  @Override public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 3) throw new IllegalArgumentException("usage: RecoverThumb.java targets.tsv all-repo-boundaries.tsv output-directory");
    Path out = Paths.get(args[2]); Files.createDirectories(out);
    readTargets(Paths.get(args[0]));
    readBoundaries(Paths.get(args[1]));
    exportProcedures(out.resolve("before.json"));
    List<Result> results = new ArrayList<Result>();
    for (Target t : targets) {
      monitor.checkCancelled();
      Result r = recover(t, out); results.add(r);
      println("RECOVER " + r.address + " " + r.status + " body=" + r.bodySize + " " + r.detail);
    }
    exportProcedures(out.resolve("after.json"));
    writeResults(out.resolve("targets.json"), results);
    writePreexisting(out.resolve("preexisting_entries.json"), results);
  }

  private void readTargets(Path path) throws IOException {
    Set<String> seen = new HashSet<String>(); int lineNo = 0;
    for (String raw : Files.readAllLines(path, StandardCharsets.UTF_8)) {
      lineNo++; String line = raw.trim();
      if (line.isEmpty() || line.startsWith("#")) continue;
      String[] f = line.split("\\t", -1);
      if (f.length != 2 || f[0].trim().isEmpty() || f[1].trim().isEmpty())
        throw new IOException("invalid TSV row " + lineNo + ": expected address<TAB>repo_name");
      Address a = toAddr(f[0].trim());
      if ((a.getOffset() & 1) != 0) throw new IOException("unaligned Thumb entry " + a);
      if (!seen.add(a.toString())) throw new IOException("duplicate target " + a);
      targets.add(new Target(a, f[1].trim()));
    }
  }

  private void readBoundaries(Path path) throws IOException {
    int lineNo = 0;
    for (String raw : Files.readAllLines(path, StandardCharsets.UTF_8)) {
      lineNo++; String line = raw.trim();
      if (line.isEmpty() || line.startsWith("#")) continue;
      String[] f = line.split("\\t", -1);
      if (f.length != 2 || f[0].trim().isEmpty() || f[1].trim().isEmpty())
        throw new IOException("invalid boundary TSV row " + lineNo + ": expected address<TAB>repo_name");
      repoStarts.add(toAddr(f[0].trim()));
    }
    if (repoStarts.isEmpty()) throw new IOException("repo boundaries TSV is empty");
  }

  private Result recover(Target t, Path out) throws Exception {
    Result r = new Result(t);
    FunctionManager fm = currentProgram.getFunctionManager();
    Listing listing = currentProgram.getListing();
    Function exact = fm.getFunctionAt(t.address), containing = fm.getFunctionContaining(t.address);
    Instruction existingInstruction = listing.getInstructionContaining(t.address);
    Data existingData = listing.getDefinedDataContaining(t.address);
    if (exact != null) {
      r.status = "preexisting_function"; r.bodySize = exact.getBody().getNumAddresses();
      r.preexistingName = exact.getName();
      r.detail = "baseline auto-analysis function " + exact.getName();
      r.tmode = tmodeAt(t.address); return r;
    }
    if (containing != null) {
      r.status = "conflict_inside_function";
      r.detail = "inside baseline function " + containing.getName() + " at " + hex(containing.getEntryPoint());
      r.tmode = tmodeAt(t.address); return r;
    }
    if ((existingInstruction != null && !existingInstruction.getAddress().equals(t.address)) || existingData != null) {
      r.status = "conflict_defined_code_unit";
      CodeUnit unit = existingInstruction != null ? existingInstruction : existingData;
      r.detail = unit.getClass().getSimpleName() + " " + hex(unit.getMinAddress()) + ".." + hex(unit.getMaxAddress());
      r.tmode = tmodeAt(t.address); return r;
    }
    if (existingInstruction != null && !"1".equals(tmodeAt(t.address))) {
      r.status = "predecoded_wrong_mode_conflict";
      r.detail = "entry instruction already exists but TMode is " + tmodeAt(t.address) + "; preserving existing code unit";
      r.tmode = tmodeAt(t.address); return r;
    }
    if (!currentProgram.getMemory().contains(t.address) || currentProgram.getMemory().getBlock(t.address) == null ||
        !currentProgram.getMemory().getBlock(t.address).isExecute()) {
      r.status = "not_executable"; r.detail = "outside executable memory"; r.tmode = tmodeAt(t.address); return r;
    }

    Address end = boundedEnd(t.address);
    AddressSet restricted = new AddressSet(t.address, end);
    boolean changesMayRemain = false;
    try {
      Register tm = currentProgram.getProgramContext().getRegister("TMode");
      if (tm == null) throw new IllegalStateException("program has no TMode register");
      BigInteger currentTMode = currentProgram.getProgramContext().getValue(tm, t.address, false);
      if (!BigInteger.ONE.equals(currentTMode)) {
        currentProgram.getProgramContext().setValue(tm, t.address, t.address, BigInteger.ONE);
        changesMayRemain = true;
      }
      Instruction atEntry = listing.getInstructionAt(t.address);
      if (atEntry == null) {
        ArmDisassembleCommand cmd = new ArmDisassembleCommand(t.address, restricted, true);
        cmd.enableCodeAnalysis(false); // postscript must not launch a full or incremental analysis pass
        changesMayRemain = true; // disassembly can make partial progress even when it returns false
        r.disassembled = cmd.applyTo(currentProgram, monitor);
        if (!r.disassembled || listing.getInstructionAt(t.address) == null) {
          r.status = "disassembly_failed";
          r.detail = cmd.getStatusMsg() == null ? "entry produced no instruction" : cmd.getStatusMsg();
          throw new Failure();
        }
      } else {
        // Existing instruction is retained; never clear/recreate code units just to change context.
        r.disassembled = true;
        r.detail = "reused predecoded entry instruction";
      }
      AddressSetView body = CreateFunctionCmd.getFunctionBody(currentProgram, t.address, false, monitor);
      r.bodySize = body.getNumAddresses();
      if (body.isEmpty() || !body.contains(t.address)) {
        r.status = "empty_body"; r.detail = "Ghidra flow analysis returned no body at entry"; throw new Failure();
      }
      AddressSet outside = new AddressSet(body);
      outside.delete(restricted);
      AddressSet boundedBody = new AddressSet(body).intersect(restricted);
      // Check every outgoing edge even when an undefined destination contributes no body bytes.
      TreeSet<Address> tailDestinations = new TreeSet<Address>();
      String invalidTail = validateTailBranches(boundedBody, restricted, outside, tailDestinations);
      if (invalidTail != null) {
        r.status = "body_crosses_boundary";
        r.detail = "Ghidra flow body has an invalid external edge: " + invalidTail;
        throw new Failure();
      }
      if (!tailDestinations.isEmpty()) {
        r.detail = "tail branches to known repo entries " + addresses(tailDestinations);
      }
      Iterator<Function> overlaps = fm.getFunctionsOverlapping(boundedBody);
      if (overlaps.hasNext()) {
        Function f = overlaps.next(); r.status = "conflict_function_body";
        r.detail = "decoded body overlaps " + f.getName() + " at " + hex(f.getEntryPoint()); throw new Failure();
      }
      Function f = fm.createFunction(t.name, t.address, boundedBody, SourceType.USER_DEFINED);
      if (f == null) { r.status = "create_function_failed"; r.detail = "FunctionManager returned null"; throw new Failure(); }
      r.status = "created"; r.bodySize = f.getBody().getNumAddresses();
      if (r.detail.isEmpty()) r.detail = "bounded end " + hex(end);
      else r.detail += "; bounded end " + hex(end);
    } catch (Failure e) {
      if (changesMayRemain) r.detail += (r.detail.isEmpty() ? "" : "; ") + "context/disassembly retained after failure";
    } catch (Exception e) {
      r.status = "error"; r.detail = e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage());
      if (changesMayRemain) r.detail += "; context/disassembly retained after failure";
    }
    Function created = fm.getFunctionAt(t.address);
    if (r.status.equals("created") && created != null) {
      r.bodySize = created.getBody().getNumAddresses(); r.tmode = tmodeAt(t.address);
      String stem = stem(t);
      writeAsm(out.resolve(stem + ".asm"), created); r.asmFile = stem + ".asm";
      decompile(created, out, r, t);
    } else r.tmode = tmodeAt(t.address);
    return r;
  }

  /** Limit disassembly and accepted CFG body to the next repository or existing function entry. */
  private Address boundedEnd(Address start) {
    Address max = currentProgram.getMemory().getBlock(start).getEnd();
    Address next = repoStarts.higher(start);
    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(start, true);
    while (it.hasNext()) {
      Address a = it.next().getEntryPoint();
      if (a.compareTo(start) > 0 && (next == null || a.compareTo(next) < 0)) next = a;
      if (next != null && a.compareTo(next) >= 0) break;
    }
    if (next != null && next.compareTo(max) <= 0) {
      Address before = next.subtract(1);
      if (before.compareTo(max) < 0) max = before;
    }
    return max;
  }

  /**
   * A CFG can follow a terminal branch into a neighboring repo function that Ghidra has not
   * created yet. Accept that case only when every external non-call edge is a direct jump to a
   * known repo entry, no fallthrough leaves the interval, and every outside body byte belongs to
   * one of those known-entry ranges.
   */
  private String validateTailBranches(AddressSetView internal, AddressSetView allowed,
      AddressSetView outside, Set<Address> destinations) {
    if (internal.isEmpty()) return "no in-interval instructions to validate";
    InstructionIterator it = currentProgram.getListing().getInstructions(internal, true);
    while (it.hasNext()) {
      Instruction ins = it.next();
      Address fall = ins.getFallThrough();
      if (fall != null && !allowed.contains(fall))
        return "fallthrough escapes interval at " + hex(ins.getAddress()) + " to " + hex(fall);
      for (Address dst : ins.getFlows()) {
        if (allowed.contains(dst) || ins.getFlowType().isCall()) continue;
        if (!ins.getFlowType().isJump())
          return "non-call flow escapes interval at " + hex(ins.getAddress()) + " to " + hex(dst);
        if (ins.getFlowType().isComputed())
          return "computed external jump at " + hex(ins.getAddress()) + " to " + hex(dst);
        if (!repoStarts.contains(dst))
          return "external direct jump at " + hex(ins.getAddress()) + " has unknown target " + hex(dst);
        destinations.add(dst);
      }
    }
    if (outside.isEmpty()) return null;
    if (destinations.isEmpty()) return "outside body is not explained by a direct branch to a known repo entry";
    AddressSet tailRanges = new AddressSet();
    for (Address dst : destinations) tailRanges.add(dst, boundedEnd(dst));
    AddressSet unexplained = new AddressSet(outside);
    unexplained.delete(tailRanges);
    if (!unexplained.isEmpty())
      return "outside body contains bytes beyond validated repo tail targets at " +
        hex(unexplained.getMinAddress()) + ".." + hex(unexplained.getMaxAddress());
    return null;
  }

  private String tmodeAt(Address a) {
    Register r = currentProgram.getProgramContext().getRegister("TMode");
    if (r == null) return "unavailable";
    BigInteger v = currentProgram.getProgramContext().getValue(r, a, false);
    return v == null ? "unset" : v.toString(16);
  }

  private void decompile(Function f, Path out, Result r, Target t) throws IOException {
    DecompInterface di = new DecompInterface();
    try {
      di.openProgram(currentProgram);
      DecompileResults d = di.decompileFunction(f, DECOMP_SECONDS, monitor);
      r.decompiled = d != null && d.decompileCompleted();
      if (d != null && d.getDecompiledFunction() != null) {
        r.cFile = stem(t) + ".c";
        Files.write(out.resolve(r.cFile), d.getDecompiledFunction().getC().getBytes(StandardCharsets.UTF_8));
      }
      if (!r.decompiled) r.error = d == null ? "no result" : nonempty(d.getErrorMessage(), di.getLastMessage());
    } catch (Exception e) {
      r.error = e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage());
    } finally { di.dispose(); }
  }

  private void writeAsm(Path path, Function f) throws IOException {
    try (BufferedWriter w = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
      w.write("; " + f.getName() + " " + hex(f.getEntryPoint()) + " body=" + f.getBody().getNumAddresses() + " bytes\n");
      InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
      int n = 0;
      while (it.hasNext() && n++ < 160) { Instruction i = it.next(); w.write(hex(i.getAddress()) + "  " + i + "\n"); }
      if (it.hasNext()) w.write("; listing truncated at 160 instructions\n");
    }
  }

  /** Shape consumed by scripts/cmp.py: normalized_result[{address,value,procedure}]. */
  private void exportProcedures(Path path) throws IOException {
    List<Function> fs = new ArrayList<Function>();
    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
    while (it.hasNext()) fs.add(it.next());
    Collections.sort(fs, new Comparator<Function>() {
      public int compare(Function a, Function b) { return a.getEntryPoint().compareTo(b.getEntryPoint()); }
    });
    try (BufferedWriter w = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
      w.write("{\"normalized_result\":["); boolean first = true;
      for (Function f : fs) {
        if (!first) w.write(","); first = false;
        Function thunk = f.isThunk() ? f.getThunkedFunction(false) : null;
        w.write("{\"address\":\"" + hex(f.getEntryPoint()) + "\",\"value\":\"" + json(f.getName()) +
          "\",\"procedure\":{\"external\":" + f.isExternal() + ",\"thunk\":" + f.isThunk() +
          ",\"thunk_target\":" + (thunk == null ? "null" : "\"" + hex(thunk.getEntryPoint()) + "\"") + "}}");
      }
      w.write("]}\n");
    }
  }

  private void writeResults(Path path, List<Result> rs) throws IOException {
    try (BufferedWriter w = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
      w.write("{\"results\":[");
      for (int i = 0; i < rs.size(); i++) {
        Result r = rs.get(i); if (i > 0) w.write(",");
        w.write("{\"address\":\"" + json(r.address) + "\",\"repo_name\":\"" + json(r.name) +
          "\",\"status\":\"" + json(r.status) + "\",\"detail\":\"" + json(r.detail) +
          "\",\"body_size\":" + r.bodySize + ",\"disassemble_success\":" + r.disassembled +
          ",\"tmode\":\"" + json(r.tmode) + "\",\"decompile_completed\":" + r.decompiled +
          ",\"decompile_error\":\"" + json(r.error) + "\",\"c_file\":\"" + json(r.cFile) +
          "\",\"asm_file\":\"" + json(r.asmFile) + "\"}");
      }
      w.write("],\"preexisting_entries\":["); boolean first = true;
      for (Result r : rs) if (r.status.equals("preexisting_function")) {
        if (!first) w.write(","); first = false;
        w.write("{\"address\":\"" + json(r.address) + "\",\"repo_name\":\"" + json(r.name) +
          "\",\"detail\":\"" + json(r.detail) + "\"}");
      }
      w.write("]}\n");
    }
  }

  private void writePreexisting(Path path, List<Result> rs) throws IOException {
    try (BufferedWriter w = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
      w.write("["); boolean first = true;
      for (Result r : rs) if (r.status.equals("preexisting_function")) {
        if (!first) w.write(","); first = false;
        w.write("{\"address\":\"" + json(r.address) + "\",\"repo_name\":\"" + json(r.name) +
          "\",\"function_name\":\"" + json(r.preexistingName) + "\",\"body_size\":" + r.bodySize + "}");
      }
      w.write("]\n");
    }
  }

  private static String stem(Target t) { return String.format(Locale.ROOT, "%08x_%s", t.address.getOffset(), t.name.replaceAll("[^A-Za-z0-9_.-]", "_")); }
  private static String hex(Address a) { return "0x" + Long.toHexString(a.getOffset()); }
  private static String addresses(Set<Address> a) { StringBuilder b = new StringBuilder(); for (Address x : a) { if (b.length() > 0) b.append(","); b.append(hex(x)); } return b.toString(); }
  private static String nonempty(String a, String b) { return a != null && !a.isEmpty() ? a : (b == null ? "" : b); }
  private static String json(String s) {
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '"') b.append("\\\"");
      else if (c == '\\') b.append("\\\\");
      else if (c == '\n') b.append("\\n");
      else if (c == '\r') b.append("\\r");
      else if (c == '\t') b.append("\\t");
      else if (c < 0x20) b.append(String.format("\\u%04x", (int)c));
      else b.append(c);
    }
    return b.toString();
  }
}
