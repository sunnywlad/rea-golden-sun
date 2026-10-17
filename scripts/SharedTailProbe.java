import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Read-only inspection and isolated split/annotation probes for Golden Sun's shared tail. */
public class SharedTailProbe extends GhidraScript {
  private static final class DecompInfo {
    String entry, name, status, error = "", cFile = "";
    boolean completed;
    int warningCount;
  }

  @Override public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 2) throw new IllegalArgumentException("usage: SharedTailProbe.java <inspect|split|annotate> <output-directory>");
    String mode = args[0].toLowerCase(Locale.ROOT);
    if (!mode.equals("inspect") && !mode.equals("split") && !mode.equals("annotate"))
      throw new IllegalArgumentException("unknown mode: " + mode);
    Path out = Paths.get(args[1]); Files.createDirectories(out);

    Address a0 = toAddr(0x080f9ac0L), a2 = toAddr(0x080f9ac2L);
    Address ae0 = toAddr(0x080f9ae0L), b10 = toAddr(0x080f9b10L);
    Map<String, DecompInfo> decomp = new LinkedHashMap<String, DecompInfo>();

    String before = snapshot(a0, a2, ae0, b10);
    writeState(out.resolve("before.json"), mode, before);
    addDecomp("before", a0, out, decomp);
    addDecomp("before", b10, out, decomp);

    String operationStatus = mode.equals("inspect") ? "read-only inspection" : "";
    boolean operationResult = true;
    if (mode.equals("split")) {
      Function existing = currentProgram.getFunctionManager().getFunctionAt(a0);
      if (existing == null) {
        CreateFunctionCmd cmd = new CreateFunctionCmd("Func_f9ac0", a0, null, SourceType.USER_DEFINED);
        operationResult = cmd.applyTo(currentProgram, monitor);
        operationStatus = cmd.getStatusMsg() == null ? "" : cmd.getStatusMsg();
      } else {
        operationResult = true;
        operationStatus = "preexisting function at 0x80f9ac0";
      }
      println("SPLIT applyTo=" + operationResult + " status=" + operationStatus +
        " result=" + currentProgram.getFunctionManager().getFunctionAt(a0));
    } else if (mode.equals("annotate")) {
      FunctionManager fm = currentProgram.getFunctionManager();
      Function fA0 = fm.getFunctionAt(a0);
      Function fB10 = fm.getFunctionAt(b10);
      if (fB10 == null) throw new IllegalStateException("missing baseline function at 0x80f9b10");
      SymbolTable symbols = currentProgram.getSymbolTable();
      if (fA0 == null)
        symbols.createLabel(a0, "Func_f9ac0", currentProgram.getGlobalNamespace(), SourceType.USER_DEFINED);
      else
        fA0.setName("Func_f9ac0", SourceType.USER_DEFINED);
      symbols.createLabel(a2, "shared_tail_f9ac2", currentProgram.getGlobalNamespace(), SourceType.USER_DEFINED);
      fB10.setName("Func_f9b10", SourceType.USER_DEFINED);
      setPlate(a0, "Func_f9ac0 entry: pushes LR, then falls through into the shared tail at 0x080f9ac2.");
      setPlate(a2, "Shared tail: LR was pushed by Func_f9ac0 or Func_f9b10; both paths use this block.");
      setPlate(b10, "Branches at 0x080f9b1e and 0x080f9b30 enter shared tail 0x080f9ac2.");
      operationStatus = "labels, comments, and function name applied";
    }

    String after = snapshot(a0, a2, ae0, b10);
    if (mode.equals("annotate")) {
      if (!snapshotKeysUnchanged(before, after))
        throw new IllegalStateException("annotation mode changed function entries, body ranges, bytes, or flow destinations");
    }
    writeState(out.resolve("after.json"), mode, after);
    Files.write(out.resolve("operation.json"), ("{\"mode\":\"" + json(mode) +
      "\",\"result\":" + operationResult + ",\"status\":\"" + json(operationStatus) + "\"}\n")
      .getBytes(StandardCharsets.UTF_8));
    addDecomp("after", a0, out, decomp);
    addDecomp("after", b10, out, decomp);
    writeDecompResults(out.resolve("decomp_status.json"), decomp);
    println("PROBE mode=" + mode + " complete; before/after snapshots and decompiler results written to " + out);
  }

  private String snapshot(Address a0, Address a2, Address ae0, Address b10) throws Exception {
    StringBuilder b = new StringBuilder();
    b.append("{\"function_entries\":").append(functionEntries())
      .append(",\"functions\":{")
      .append("\"0x80f9ac0\":").append(functionSummary(a0)).append(",")
      .append("\"0x80f9ae0\":").append(functionSummary(ae0)).append(",")
      .append("\"0x80f9b10\":").append(functionSummary(b10)).append("},")
      .append("\"shared_tail_owner\":").append(ownerSummary(a2)).append(",")
      .append("\"annotations\":{\"a0_labels\":").append(labelsAt(a0))
      .append(",\"a2_labels\":").append(labelsAt(a2))
      .append(",\"a0_plate\":\"").append(json(currentProgram.getListing().getComment(CommentType.PLATE, a0)))
      .append("\",\"a2_plate\":\"").append(json(currentProgram.getListing().getComment(CommentType.PLATE, a2)))
      .append("\",\"b10_plate\":\"").append(json(currentProgram.getListing().getComment(CommentType.PLATE, b10))).append("\"},")
      .append("\"code_ranges\":[")
      .append(codeRange(toAddr(0x080f9ac0L), toAddr(0x080f9adfL))).append(",")
      .append(codeRange(toAddr(0x080f9b10L), toAddr(0x080f9b3dL))).append("]}");
    return b.toString();
  }

  private String functionEntries() {
    List<String> entries = new ArrayList<String>();
    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
    while (it.hasNext()) entries.add(hex(it.next().getEntryPoint()));
    Collections.sort(entries);
    return stringArray(entries);
  }

  private String functionSummary(Address entry) {
    Function f = currentProgram.getFunctionManager().getFunctionAt(entry);
    if (f == null) return "null";
    List<String> ranges = new ArrayList<String>();
    for (AddressRange r : f.getBody().getAddressRanges())
      ranges.add("{\"start\":\"" + hex(r.getMinAddress()) + "\",\"end\":\"" + hex(r.getMaxAddress()) + "\"}");
    StringBuilder b = new StringBuilder("{\"entry\":\"").append(hex(entry)).append("\",\"name\":\"")
      .append(json(f.getName())).append("\",\"body_ranges\":[");
    for (int i = 0; i < ranges.size(); i++) { if (i > 0) b.append(","); b.append(ranges.get(i)); }
    List<String> called = new ArrayList<String>();
    for (Function callee : f.getCalledFunctions(monitor)) called.add(hex(callee.getEntryPoint()));
    Collections.sort(called);
    return b.append("],\"called_functions\":").append(stringArray(called)).append("}").toString();
  }

  private String ownerSummary(Address a) {
    Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
    if (f == null) return "null";
    return "{\"address\":\"" + hex(a) + "\",\"entry\":\"" + hex(f.getEntryPoint()) +
      "\",\"name\":\"" + json(f.getName()) + "\"}";
  }

  private String labelsAt(Address a) {
    List<String> names = new ArrayList<String>();
    for (Symbol s : currentProgram.getSymbolTable().getSymbols(a))
      names.add(s.getSymbolType() + ":" + s.getName());
    Collections.sort(names);
    return stringArray(names);
  }

  private String codeRange(Address start, Address end) throws Exception {
    StringBuilder raw = new StringBuilder();
    for (Address a = start; a.compareTo(end) <= 0; a = a.add(1)) {
      if (raw.length() > 0) raw.append(" ");
      raw.append(String.format(Locale.ROOT, "%02x", currentProgram.getMemory().getByte(a) & 0xff));
    }
    AddressSet set = new AddressSet(start, end);
    InstructionIterator it = currentProgram.getListing().getInstructions(set, true);
    List<String> insns = new ArrayList<String>();
    while (it.hasNext()) {
      Instruction ins = it.next();
      byte[] bytes = new byte[ins.getLength()];
      currentProgram.getMemory().getBytes(ins.getAddress(), bytes);
      List<String> flows = new ArrayList<String>();
      for (Address flow : ins.getFlows()) flows.add(hex(flow));
      Collections.sort(flows);
      String ft = ins.getFlowType().toString();
      Address fall = ins.getFallThrough();
      insns.add("{\"address\":\"" + hex(ins.getAddress()) + "\",\"bytes\":\"" + bytesHex(bytes) +
        "\",\"text\":\"" + json(ins.toString()) + "\",\"flow_type\":\"" + json(ft) +
        "\",\"flows\":" + stringArray(flows) + ",\"fallthrough\":" +
        (fall == null ? "null" : "\"" + hex(fall) + "\"") + "}");
    }
    StringBuilder ib = new StringBuilder("[");
    for (int i = 0; i < insns.size(); i++) { if (i > 0) ib.append(","); ib.append(insns.get(i)); }
    return "{\"start\":\"" + hex(start) + "\",\"end\":\"" + hex(end) +
      "\",\"raw_bytes\":\"" + raw + "\",\"instructions\":" + ib + "]}";
  }

  private boolean snapshotKeysUnchanged(String before, String after) {
    // Function names and labels are intentionally allowed to change. Compare structural fields.
    String bEntries = field(before, "\"function_entries\":", ",\"functions\"");
    String aEntries = field(after, "\"function_entries\":", ",\"functions\"");
    if (!bEntries.equals(aEntries)) return false;
    String bBodies = bodiesKey(before), aBodies = bodiesKey(after);
    if (!bBodies.equals(aBodies)) return false;
    String bCode = codeRangesKey(before), aCode = codeRangesKey(after);
    return bCode.equals(aCode);
  }

  private String bodiesKey(String json) {
    StringBuilder result = new StringBuilder();
    int functionMap = json.indexOf("\"functions\":{");
    if (functionMap < 0) return "<missing>";
    for (String entry : new String[] {"0x80f9ac0", "0x80f9ae0", "0x80f9b10"}) {
      String marker = "\"" + entry + "\":";
      int i = json.indexOf(marker, functionMap);
      if (i < 0) return "<missing>";
      int start = json.indexOf("\"body_ranges\":", i);
      if (json.startsWith("null", i + marker.length())) { result.append("null;"); continue; }
      if (start < 0) return "<missing>";
      start = json.indexOf('[', start);
      int depth = 0, end = start;
      for (; end < json.length(); end++) {
        char c = json.charAt(end);
        if (c == '[') depth++;
        else if (c == ']' && --depth == 0) break;
      }
      result.append(json.substring(start, end + 1)).append(';');
    }
    String owner = field(json, "\"shared_tail_owner\":", ",\"code_ranges\"");
    result.append(owner.contains("null") ? "null" : field(owner, "\"entry\":\"", "\","));
    return result.toString();
  }

  private String codeRangesKey(String json) {
    int start = json.indexOf("\"code_ranges\":");
    return start < 0 ? "<missing>" : json.substring(start);
  }

  private static String field(String json, String startToken, String endToken) {
    int s = json.indexOf(startToken);
    if (s < 0) return "<missing>";
    s += startToken.length();
    int e = json.indexOf(endToken, s);
    return e < 0 ? "<missing>" : json.substring(s, e);
  }

  private void addDecomp(String phase, Address entry, Path out, Map<String, DecompInfo> all) throws IOException {
    Function f = currentProgram.getFunctionManager().getFunctionAt(entry);
    if (f == null) return;
    DecompInfo info = new DecompInfo();
    info.entry = hex(entry); info.name = f.getName();
    DecompInterface di = new DecompInterface();
    try {
      if (!di.openProgram(currentProgram)) {
        info.status = "open_failed"; info.error = di.getLastMessage();
      } else {
        DecompileResults d = di.decompileFunction(f, 15, monitor);
        info.completed = d != null && d.decompileCompleted();
        if (d != null && d.getDecompiledFunction() != null) {
          String c = d.getDecompiledFunction().getC();
          info.warningCount = countWarnings(c);
          info.cFile = phase + "_" + entry.getOffset() + ".c";
          Files.write(out.resolve(info.cFile), c.getBytes(StandardCharsets.UTF_8));
        }
        if (d == null) { info.status = "no_result"; info.error = di.getLastMessage(); }
        else if (info.completed) info.status = "completed";
        else { info.status = "incomplete"; info.error = nonempty(d.getErrorMessage(), di.getLastMessage()); }
      }
    } catch (Exception e) {
      info.status = "error"; info.error = e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage());
    } finally { di.dispose(); }
    all.put(phase + ":" + info.entry, info);
  }

  private void writeState(Path path, String mode, String snapshot) throws IOException {
    Files.write(path, ("{\"mode\":\"" + json(mode) + "\",\"state\":" + snapshot + "}\n").getBytes(StandardCharsets.UTF_8));
  }

  private void writeDecompResults(Path path, Map<String, DecompInfo> all) throws IOException {
    try (BufferedWriter w = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
      w.write("{\"results\":["); boolean first = true;
      for (Map.Entry<String, DecompInfo> e : all.entrySet()) {
        if (!first) w.write(","); first = false;
        DecompInfo d = e.getValue();
        w.write("{\"phase\":\"" + json(e.getKey().substring(0, e.getKey().indexOf(':'))) +
          "\",\"entry\":\"" + json(d.entry) + "\",\"name\":\"" + json(d.name) +
          "\",\"status\":\"" + json(d.status) + "\",\"completed\":" + d.completed +
          ",\"warning_count\":" + d.warningCount + ",\"error\":\"" + json(d.error) +
          "\",\"c_file\":\"" + json(d.cFile) + "\"}");
      }
      w.write("]}\n");
    }
  }

  private void setPlate(Address a, String text) {
    currentProgram.getListing().setComment(a, CommentType.PLATE, text);
  }

  private static int countWarnings(String c) {
    int count = 0, p = 0;
    while ((p = c.indexOf("WARNING", p)) >= 0) { count++; p += 7; }
    return count;
  }
  private static String nonempty(String a, String b) { return a != null && !a.isEmpty() ? a : (b == null ? "" : b); }
  private static String bytesHex(byte[] bytes) {
    StringBuilder b = new StringBuilder();
    for (byte v : bytes) b.append(String.format(Locale.ROOT, "%02x", v & 0xff));
    return b.toString();
  }
  private static String hex(Address a) { return "0x" + Long.toHexString(a.getOffset()); }
  private static String stringArray(List<String> items) {
    StringBuilder b = new StringBuilder("[");
    for (int i = 0; i < items.size(); i++) { if (i > 0) b.append(","); b.append("\"").append(json(items.get(i))).append("\""); }
    return b.append("]").toString();
  }
  private static String json(String s) {
    if (s == null) return "";
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '"') b.append("\\\"");
      else if (c == '\\') b.append("\\\\");
      else if (c == '\n') b.append("\\n");
      else if (c == '\r') b.append("\\r");
      else if (c == '\t') b.append("\\t");
      else if (c < 0x20) b.append(String.format(Locale.ROOT, "\\u%04x", (int)c));
      else b.append(c);
    }
    return b.toString();
  }
}
