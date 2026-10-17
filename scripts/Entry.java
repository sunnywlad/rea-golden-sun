import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.*;

public class Entry extends GhidraScript {
  public void run() throws Exception {
    Instruction i = getInstructionAt(toAddr(0x8000000L));
    println("E insn@0 = " + i);
    Address a = toAddr(0x80000c0L);
    for (int k = 0; k < 12; k++) { Instruction x = getInstructionAt(a); if (x == null) { println("E " + a + " none"); break; } println("E " + a + " " + x); a = x.getNext() != null ? x.getNext().getAddress() : a.add(4); }
    Function f = getFunctionContaining(toAddr(0x80000c0L));
    println("E fn@c0 = " + f + (f != null ? " size=" + f.getBody().getNumAddresses() : ""));
    if (f != null) {
      DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
      DecompileResults r = di.decompileFunction(f, 60, monitor);
      println("E decomp ok=" + r.decompileCompleted());
      if (r.getDecompiledFunction() != null) for (String l : r.getDecompiledFunction().getC().split("\n")) println("E| " + l);
    }
  }
}
