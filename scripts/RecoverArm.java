import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Bounded ARM-entry recovery; run on a disposable project copy and audit before promotion. */
public class RecoverArm extends GhidraScript {
  private final TreeSet<Address> boundaries = new TreeSet<>();
  @Override public void run() throws Exception {
    String[] args=getScriptArgs();
    if(args.length!=3)throw new IllegalArgumentException("RecoverArm.java expected 3 args, got "+Arrays.toString(args));
    readBoundaries(Paths.get(args[1]));Path out=Paths.get(args[2]);Files.createDirectories(out);
    for(String line:Files.readAllLines(Paths.get(args[0]),StandardCharsets.UTF_8)) {
      if(line.isBlank()||line.startsWith("#"))continue;String[] f=line.trim().split("\\t",-1);
      if(f.length<2||f.length>3)throw new IOException("invalid target row: "+line);
      Address manualEnd=f.length==3?toAddr(f[2]):null;
      try {recover(toAddr(f[0]),f[1],manualEnd,out);}
      catch(Exception e) {println("RECOVER_ARM_ERROR "+f[0]+" "+f[1]+" "+e.getClass().getSimpleName()+": "+e.getMessage());}
    }
  }
  private void readBoundaries(Path path)throws IOException {
    for(String line:Files.readAllLines(path,StandardCharsets.UTF_8))if(!line.isBlank()&&!line.startsWith("#"))
      boundaries.add(toAddr(line.trim().split("\\t",-1)[0]));
    if(boundaries.isEmpty())throw new IOException("empty boundaries");
  }
  private void recover(Address entry,String name,Address manualEnd,Path out)throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();Listing listing=currentProgram.getListing();
    if((entry.getOffset()&3)!=0)throw new IllegalStateException("unaligned ARM entry "+entry);
    if(fm.getFunctionAt(entry)!=null)throw new IllegalStateException("function already exists "+entry);
    Instruction preexisting=listing.getInstructionContaining(entry);
    if(fm.getFunctionContaining(entry)!=null||listing.getDefinedDataContaining(entry)!=null||
       (preexisting!=null&&!preexisting.getAddress().equals(entry)))
      throw new IllegalStateException("defined code/data overlaps ARM entry "+entry);
    Address end=currentProgram.getMemory().getBlock(entry).getEnd(),next=boundaries.higher(entry);
    FunctionIterator fi=fm.getFunctions(entry,true);
    while(fi.hasNext()){Address a=fi.next().getEntryPoint();if(a.compareTo(entry)>0&&(next==null||a.compareTo(next)<0))next=a;}
    if(next!=null&&next.subtract(1).compareTo(end)<0)end=next.subtract(1);
    if(manualEnd!=null&&(manualEnd.compareTo(entry)<0||manualEnd.compareTo(end)>0||((manualEnd.getOffset()-entry.getOffset()+1)&3)!=0))
      throw new IllegalArgumentException("invalid manual ARM body range "+entry+".."+manualEnd);
    AddressSet bounded=new AddressSet(entry,end);
    Register tm=currentProgram.getProgramContext().getRegister("TMode");
    if(tm==null)throw new IllegalStateException("missing TMode");
    if(preexisting==null)
      currentProgram.getProgramContext().setValue(tm,entry,entry,BigInteger.ZERO);
    if(manualEnd!=null) {
      for(Address a=entry;a.compareTo(manualEnd)<=0;a=a.add(4)) {
        Instruction old=listing.getInstructionAt(a);
        if(old!=null) {
          byte[] memoryBytes=new byte[4];
          currentProgram.getMemory().getBytes(a,memoryBytes);
          if(old.getLength()!=4||!Arrays.equals(old.getBytes(),memoryBytes))
            throw new IllegalStateException("conflicting manual ARM code unit at "+a);
        }
        if(old==null) {
          currentProgram.getProgramContext().setValue(tm,a,a,BigInteger.ZERO);
          DisassembleCommand cmd=new DisassembleCommand(a,new AddressSet(a,a.add(3)),true);
          cmd.setInitialContext(new RegisterValue(tm,BigInteger.ZERO));cmd.enableCodeAnalysis(false);
          if(!cmd.applyTo(currentProgram,monitor))throw new IllegalStateException("planned ARM instruction failed at "+a+": "+cmd.getStatusMsg());
        }
        Instruction decoded=listing.getInstructionAt(a);
        if(decoded==null||decoded.getLength()!=4||!"0".equals(currentProgram.getProgramContext().getValue(tm,a,false).toString()))
          throw new IllegalStateException("manual ARM decode mismatch at "+a);
      }
    } else if(preexisting==null) {
      DisassembleCommand cmd=new DisassembleCommand(entry,bounded,true);
      cmd.setInitialContext(new RegisterValue(tm,BigInteger.ZERO));cmd.enableCodeAnalysis(false);
      if(!cmd.applyTo(currentProgram,monitor)||listing.getInstructionAt(entry)==null)
        throw new IllegalStateException("ARM disassembly failed at "+entry+": "+cmd.getStatusMsg());
    } else if(preexisting.getLength()!=4||!"0".equals(currentProgram.getProgramContext().getValue(tm,entry,false).toString()))
      throw new IllegalStateException("predecoded entry is not a four-byte ARM instruction "+entry);
    AddressSetView body=manualEnd==null?CreateFunctionCmd.getFunctionBody(currentProgram,entry,false,monitor):new AddressSet(entry,manualEnd);
    AddressSet accepted=new AddressSet(body).intersect(bounded);
    if(accepted.isEmpty()||!accepted.contains(entry))throw new IllegalStateException("empty ARM body "+entry);
    AddressSet outside=new AddressSet(body);outside.delete(bounded);
    if(!outside.isEmpty())throw new IllegalStateException("ARM flow crossed boundary at "+outside.getMinAddress());
    Iterator<Function> overlaps=fm.getFunctionsOverlapping(accepted);
    if(overlaps.hasNext())throw new IllegalStateException("ARM body overlaps "+overlaps.next().getName());
    Function fn=fm.createFunction(name,entry,accepted,SourceType.USER_DEFINED);
    if(fn==null)throw new IllegalStateException("cannot create ARM function "+entry);
    writeAsm(out.resolve(String.format(Locale.ROOT,"%08x_%s.asm",entry.getOffset(),name)),fn);
    DecompInterface di=new DecompInterface();
    try {di.openProgram(currentProgram);DecompileResults d=di.decompileFunction(fn,30,monitor);
      if(d!=null&&d.getDecompiledFunction()!=null)Files.writeString(out.resolve(String.format(Locale.ROOT,"%08x_%s.c",entry.getOffset(),name)),d.getDecompiledFunction().getC());
      println("RECOVER_ARM "+entry+" "+name+" body="+fn.getBody().getNumAddresses()+" decompiled="+(d!=null&&d.decompileCompleted()));
    } finally {di.dispose();}
  }
  private void writeAsm(Path p,Function f)throws IOException {
    try(BufferedWriter w=Files.newBufferedWriter(p,StandardCharsets.UTF_8)) {
      InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
      while(it.hasNext()){Instruction i=it.next();w.write("0x"+Long.toHexString(i.getAddress().getOffset())+"  "+i+"\n");}
    }
  }
}
