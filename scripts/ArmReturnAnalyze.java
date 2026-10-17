import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.ArmAnalyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import java.nio.file.*;
import java.util.*;

/** Run the installed ARM constant propagation analyzer on approved existing function bodies. */
public class ArmReturnAnalyze extends GhidraScript {
  @Override public void run() throws Exception {
    AddressSet bodies=new AddressSet();
    List<Long> entries=new ArrayList<>();
    String[] args=getScriptArgs();
    if(args.length>1)throw new IllegalArgumentException("ArmReturnAnalyze.java [targets.tsv]");
    if(args.length==0)for(long a:new long[]{0x080c9c9cL,0x080d5274L,0x080d8988L,0x080d9adcL})entries.add(a);
    else for(String line:Files.readAllLines(Paths.get(args[0]))) {
      if(!line.isBlank()&&!line.startsWith("#"))entries.add(Long.decode(line.split("\\t")[0]));
    }
    if(entries.isEmpty())throw new IllegalArgumentException("empty approved target list");
    for(long a:entries) {
      Function f=getFunctionAt(toAddr(a));if(f==null)throw new IllegalStateException("missing wrapper");
      bodies.add(f.getBody());
    }
    ArmAnalyzer analyzer=new ArmAnalyzer();
    if(!analyzer.canAnalyze(currentProgram))throw new IllegalStateException("ARM analyzer unavailable");
    MessageLog log=new MessageLog();
    boolean result=analyzer.added(currentProgram,bodies,monitor,log);
    println("ARM_TARGETED result="+result+" log="+log);
  }
}
