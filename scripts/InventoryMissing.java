import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.math.BigInteger;
import java.util.*;

/** Read-only inventory of reference candidates that have no repository-confirmed status yet. */
public class InventoryMissing extends GhidraScript {
  private static final class Target {
    final String mode, name;
    final Address address;
    Target(String m, Address a, String n) { mode = m; address = a; name = n; }
  }
  private static final class Record {
    final Target target;
    String category;
    Record(Target t) { target = t; }
  }

  @Override public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 2)
      throw new IllegalArgumentException("usage: InventoryMissing.java <targets.tsv> <output.json>");
    List<Target> targets = readTargets(Paths.get(args[0]));
    Path output = Paths.get(args[1]);
    Path parent = output.toAbsolutePath().getParent();
    if (parent != null) Files.createDirectories(parent);

    List<String> entries = functionEntries();
    List<Record> records = new ArrayList<Record>();
    Map<String, Integer> counts = new TreeMap<String, Integer>();
    try (BufferedWriter w = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
      w.write("{\"program\":{\"name\":\"" + json(currentProgram.getName()) +
        "\",\"language\":\"" + json(currentProgram.getLanguageID().toString()) +
        "\",\"compiler\":\"" + json(currentProgram.getCompiler()) +
        "\",\"function_count\":" + entries.size() + "},");
      w.write("\"function_entries\":" + stringArray(entries) + ",\"targets\":[");
      for (int i = 0; i < targets.size(); i++) {
        monitor.checkCancelled();
        Record r = inspect(targets.get(i));
        records.add(r);
        Integer n = counts.get(r.category);
        counts.put(r.category, n == null ? 1 : n + 1);
        if (i > 0) w.write(",");
        w.write(recordJson(r));
        println("INVENTORY " + hex(r.target.address) + " " + r.category);
      }
      w.write("],\"counts\":{");
      boolean first = true;
      for (Map.Entry<String, Integer> e : counts.entrySet()) {
        if (!first) w.write(","); first = false;
        w.write("\"" + json(e.getKey()) + "\":" + e.getValue());
      }
      w.write("},\"target_count\":" + records.size() + "}\n");
    }
  }

  private List<Target> readTargets(Path path) throws IOException {
    List<Target> targets = new ArrayList<Target>();
    Set<String> seen = new HashSet<String>();
    int lineNo = 0;
    for (String raw : Files.readAllLines(path, StandardCharsets.UTF_8)) {
      lineNo++;
      String line = raw.trim();
      if (line.isEmpty() || line.startsWith("#")) continue;
      String[] f = line.split("\\t", -1);
      if (f.length != 3 || f[0].trim().isEmpty() || f[1].trim().isEmpty() || f[2].trim().isEmpty())
        throw new IOException("invalid TSV row " + lineNo + ": expected mode<TAB>hex_address<TAB>repo_name");
      Address a;
      try { a = toAddr(f[1].trim()); }
      catch (Exception e) { throw new IOException("invalid address at TSV row " + lineNo + ": " + f[1], e); }
      if (!seen.add(a.toString())) throw new IOException("duplicate target address at TSV row " + lineNo + ": " + a);
      targets.add(new Target(f[0].trim(), a, f[2].trim()));
    }
    return targets;
  }

  private List<String> functionEntries() {
    List<String> entries = new ArrayList<String>();
    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
    while (it.hasNext()) entries.add(hex(it.next().getEntryPoint()));
    Collections.sort(entries);
    return entries;
  }

  private Record inspect(Target t) throws Exception {
    Record r = new Record(t);
    FunctionManager fm = currentProgram.getFunctionManager();
    Listing listing = currentProgram.getListing();
    Function exact = fm.getFunctionAt(t.address);
    Function owner = fm.getFunctionContaining(t.address);
    Instruction at = listing.getInstructionAt(t.address);
    Instruction containing = listing.getInstructionContaining(t.address);
    Data dataAt = listing.getDefinedDataAt(t.address);
    Data dataContaining = listing.getDefinedDataContaining(t.address);
    MemoryBlock block = currentProgram.getMemory().getBlock(t.address);

    if (exact != null) r.category = "exact_function";
    else if (containing != null && !containing.getAddress().equals(t.address)) r.category = "mid_instruction";
    else if (at != null && owner != null) r.category = "instruction_in_existing_function";
    else if (at != null) r.category = "decoded_entry_unowned";
    else if (dataAt != null || dataContaining != null) r.category = "defined_data";
    else if (block == null) r.category = "outside_memory";
    else if (!block.isInitialized()) r.category = "uninitialized_memory";
    else if (!block.isExecute()) r.category = "non_executable_memory";
    else r.category = "undefined_executable";
    return r;
  }

  private String recordJson(Record r) throws Exception {
    Target t = r.target;
    Function exact = currentProgram.getFunctionManager().getFunctionAt(t.address);
    Function owner = currentProgram.getFunctionManager().getFunctionContaining(t.address);
    Instruction at = currentProgram.getListing().getInstructionAt(t.address);
    Instruction containing = currentProgram.getListing().getInstructionContaining(t.address);
    Data dataAt = currentProgram.getListing().getDefinedDataAt(t.address);
    Data dataContaining = currentProgram.getListing().getDefinedDataContaining(t.address);
    MemoryBlock block = currentProgram.getMemory().getBlock(t.address);
    Register tmodeReg = currentProgram.getProgramContext().getRegister("TMode");
    BigInteger tmode = tmodeReg == null ? null :
      currentProgram.getProgramContext().getValue(tmodeReg, t.address, false);

    return "{\"mode\":\"" + json(t.mode) + "\",\"address\":\"" + hex(t.address) +
      "\",\"repo_name\":\"" + json(t.name) + "\",\"category\":\"" + json(r.category) +
      "\",\"exact_function\":" + functionJson(exact) +
      ",\"containing_function\":" + functionJson(owner) +
      ",\"instruction_at\":" + instructionJson(at) +
      ",\"instruction_containing\":" + instructionJson(containing) +
      ",\"defined_data_at\":" + dataJson(dataAt) +
      ",\"defined_data_containing\":" + dataJson(dataContaining) +
      ",\"tmode\":" + (tmode == null ? "null" : "\"" + tmode.toString(16) + "\"") +
      ",\"memory_block\":" + blockJson(block, t.address) +
      ",\"entry_bytes\":" + bytesJson(t.address, block, 16) +
      ",\"references_even\":" + referencesJson(t.address) +
      ",\"references_odd\":" + referencesJson(t.address.add(1)) + "}";
  }

  private String functionJson(Function f) {
    if (f == null) return "null";
    StringBuilder ranges = new StringBuilder("[");
    boolean first = true;
    for (AddressRange range : f.getBody().getAddressRanges()) {
      if (!first) ranges.append(","); first = false;
      ranges.append("{\"start\":\"").append(hex(range.getMinAddress()))
        .append("\",\"end\":\"").append(hex(range.getMaxAddress())).append("\"}");
    }
    return "{\"entry\":\"" + hex(f.getEntryPoint()) + "\",\"name\":\"" + json(f.getName()) +
      "\",\"external\":" + f.isExternal() + ",\"thunk\":" + f.isThunk() +
      ",\"body_ranges\":" + ranges.append("]") + "}";
  }

  private String instructionJson(Instruction i) throws MemoryAccessException {
    if (i == null) return "null";
    byte[] bytes = new byte[i.getLength()];
    currentProgram.getMemory().getBytes(i.getAddress(), bytes);
    List<String> flows = new ArrayList<String>();
    for (Address a : i.getFlows()) flows.add(hex(a));
    Collections.sort(flows);
    Address fall = i.getFallThrough();
    return "{\"start\":\"" + hex(i.getMinAddress()) + "\",\"end\":\"" + hex(i.getMaxAddress()) +
      "\",\"length\":" + i.getLength() +
      ",\"bytes\":\"" + bytesHex(bytes) + "\",\"text\":\"" + json(i.toString()) +
      "\",\"flow_type\":\"" + json(i.getFlowType().toString()) + "\",\"flows\":" + stringArray(flows) +
      ",\"fallthrough\":" + (fall == null ? "null" : "\"" + hex(fall) + "\"") + "}";
  }

  private String dataJson(Data d) {
    if (d == null) return "null";
    return "{\"start\":\"" + hex(d.getMinAddress()) + "\",\"end\":\"" + hex(d.getMaxAddress()) +
      "\",\"length\":" + d.getLength() + ",\"datatype\":\"" + json(d.getDataType().getName()) +
      "\",\"value\":\"" + json(d.getDefaultValueRepresentation()) + "\"}";
  }

  private String blockJson(MemoryBlock b, Address a) {
    if (b == null) return "null";
    return "{\"name\":\"" + json(b.getName()) + "\",\"start\":\"" + hex(b.getStart()) +
      "\",\"end\":\"" + hex(b.getEnd()) + "\",\"initialized\":" + b.isInitialized() +
      ",\"execute\":" + b.isExecute() + ",\"loaded\":" + b.isLoaded() +
      ",\"contains_entry\":" + (a.compareTo(b.getStart()) >= 0 && a.compareTo(b.getEnd()) <= 0) + "}";
  }

  private String bytesJson(Address a, MemoryBlock b, int wanted) {
    if (b == null || !b.isInitialized()) return "null";
    long available = b.getEnd().subtract(a) + 1;
    int count = (int)Math.max(0, Math.min((long)wanted, available));
    byte[] bytes = new byte[count];
    try {
      int actual = currentProgram.getMemory().getBytes(a, bytes);
      if (actual != count) return "{\"hex\":\"" + bytesHex(Arrays.copyOf(bytes, actual)) + "\",\"length\":" + actual + "}";
      return "{\"hex\":\"" + bytesHex(bytes) + "\",\"length\":" + count + "}";
    } catch (Exception e) {
      return "{\"hex\":null,\"length\":0,\"error\":\"" + json(e.getClass().getSimpleName() + ": " + e.getMessage()) + "\"}";
    }
  }

  private String referencesJson(Address target) {
    List<String> refs = new ArrayList<String>();
    ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(target);
    while (it.hasNext()) {
      Reference ref = it.next();
      Address source = ref.getFromAddress();
      Function owner = currentProgram.getFunctionManager().getFunctionContaining(source);
      refs.add("{\"source\":\"" + hex(source) + "\",\"kind\":\"" +
        json(ref.getReferenceType().toString()) + "\",\"operand_index\":" + ref.getOperandIndex() +
        ",\"source_function\":" + functionOwnerJson(owner) + "}");
    }
    return arrayOfJson(refs);
  }

  private String functionOwnerJson(Function f) {
    if (f == null) return "null";
    return "{\"entry\":\"" + hex(f.getEntryPoint()) + "\",\"name\":\"" + json(f.getName()) + "\"}";
  }

  private static String arrayOfJson(List<String> objects) {
    StringBuilder b = new StringBuilder("[");
    for (int i = 0; i < objects.size(); i++) { if (i > 0) b.append(","); b.append(objects.get(i)); }
    return b.append("]").toString();
  }

  private static String stringArray(List<String> values) {
    List<String> quoted = new ArrayList<String>();
    for (String v : values) quoted.add("\"" + json(v) + "\"");
    return arrayOfJson(quoted);
  }

  private static String bytesHex(byte[] bytes) {
    StringBuilder b = new StringBuilder();
    for (byte value : bytes) b.append(String.format(Locale.ROOT, "%02x", value & 0xff));
    return b.toString();
  }

  private static String hex(Address a) { return "0x" + Long.toHexString(a.getOffset()); }

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
