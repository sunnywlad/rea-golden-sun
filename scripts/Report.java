import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.util.DefinedDataIterator;

public class Report extends GhidraScript {
  public void run() throws Exception {
    println("REPORT format=" + currentProgram.getExecutableFormat() + " lang=" + currentProgram.getLanguageID());
    for (MemoryBlock b : currentProgram.getMemory().getBlocks())
      println("REPORT block " + b.getName() + " " + b.getStart() + "-" + b.getEnd() + " init=" + b.isInitialized());
    println("REPORT functions=" + currentProgram.getFunctionManager().getFunctionCount());
    println("REPORT instructions=" + currentProgram.getListing().getNumInstructions());
    println("REPORT definedData=" + currentProgram.getListing().getNumDefinedData());
    int n = 0;
    for (Data d : currentProgram.getListing().getDefinedData(true)) { if (!d.getDataType().getName().toLowerCase().contains("string")) continue; if (n++ < 15) println("REPORT str " + d.getAddress() + " " + d.getDefaultValueRepresentation()); }
    println("REPORT strings=" + n);
    println("REPORT entry=" + currentProgram.getSymbolTable().getExternalEntryPointIterator().hasNext());
    Function f = getFunctionAt(toAddr(0x8000000L));
    println("REPORT fn@08000000=" + f);
  }
}
