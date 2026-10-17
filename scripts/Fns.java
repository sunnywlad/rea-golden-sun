import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
public class Fns extends GhidraScript {
  public void run() throws Exception {
    int n = 0; long thumb = 0, arm = 0;
    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
      if (n++ < 5) println("F " + f.getEntryPoint() + " " + f.getName() + " size=" + f.getBody().getNumAddresses());
    }
    Instruction i = getInstructionAfter(toAddr(0x8000000L));
    println("F first insn " + i.getAddress() + " " + i);
    for (int k = 0; k < 8 && i != null; k++, i = i.getNext()) println("F  " + i.getAddress() + " " + i);
  }
}
