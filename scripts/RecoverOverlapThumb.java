import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Recover source-proven Thumb functions whose exact code bytes were undefined data. */
public class RecoverOverlapThumb extends GhidraScript {
  private final TreeSet<Address> boundaries=new TreeSet<>();
  public void run() throws Exception {
    String[] args=getScriptArgs(); if(args.length!=3)throw new IllegalArgumentException("targets.tsv boundaries.tsv output.tsv");
    readBoundaries(Paths.get(args[1])); Path out=Paths.get(args[2]);if(out.getParent()!=null)Files.createDirectories(out.getParent());
    List<String> result=new ArrayList<>();
    for(String raw:Files.readAllLines(Paths.get(args[0]),StandardCharsets.UTF_8)) {
      if(raw.isBlank()||raw.startsWith("#"))continue;String[] f=raw.split("\\t");
      if(f.length!=3)throw new IllegalArgumentException("target needs address, name, code ranges: "+raw);
      Address start=toAddr(f[0]);String name=f[1];List<AddressRange> ranges=new ArrayList<>();
      for(String part:f[2].split(";")){String[] ends=part.split("-",-1);if(ends.length!=2)throw new IllegalArgumentException("invalid code range "+part);Address lo=toAddr(ends[0]),hi=toAddr(ends[1]);if(lo.compareTo(hi)>0||((hi.getOffset()-lo.getOffset()+1)&1)!=0)throw new IllegalArgumentException("invalid Thumb range "+part);ranges.add(new AddressRangeImpl(lo,hi));}
      if(ranges.isEmpty()||!ranges.get(0).getMinAddress().equals(start))throw new IllegalArgumentException("first range must start at entry");
      Address end=ranges.get(ranges.size()-1).getMaxAddress();
      if(fm().getFunctionAt(start)!=null||fm().getFunctionContaining(start)!=null)throw new IllegalStateException("function overlap at "+start);
      Address next=boundaries.higher(start); if(next==null||end.compareTo(next)>=0)throw new IllegalStateException("body exceeds source boundary: "+start+".."+end);
      if(((end.getOffset()-start.getOffset()+1)&1)!=0)throw new IllegalStateException("unaligned Thumb body size");
      Listing listing=currentProgram.getListing();
      for(AddressRange range:ranges)for(Address a=range.getMinAddress();a.compareTo(range.getMaxAddress())<=0;a=a.add(2)) {
        Instruction i=listing.getInstructionContaining(a);Data d=listing.getDefinedDataContaining(a);
        if(i!=null&&(!i.getAddress().equals(a)||i.getLength()!=2))throw new IllegalStateException("conflicting instruction "+i);
        if(d!=null&&!d.getDataType().getName().startsWith("undefined"))throw new IllegalStateException("refusing to clear typed data "+d.getAddress()+" "+d.getDataType());
      }
      Register tm=currentProgram.getProgramContext().getRegister("TMode");
      for(AddressRange range:ranges)for(Address a=range.getMinAddress();a.compareTo(range.getMaxAddress())<=0;a=a.add(2)) {
        Instruction old=listing.getInstructionAt(a);
        if(old==null) {
          listing.clearCodeUnits(a,a.add(1),false);
          currentProgram.getProgramContext().setValue(tm,a,a,BigInteger.ONE);
          ArmDisassembleCommand cmd=new ArmDisassembleCommand(a,new AddressSet(a,a.add(1)),true);cmd.enableCodeAnalysis(false);
          if(!cmd.applyTo(currentProgram,monitor))throw new IllegalStateException("decode failed "+a+" "+cmd.getStatusMsg());
        }
        Instruction now=listing.getInstructionAt(a);
        if(now==null||now.getLength()!=2||!BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(tm,a,false)))throw new IllegalStateException("decode/mode mismatch "+a);
      }
      AddressSet body=new AddressSet();for(AddressRange range:ranges)body.add(range);
      Function fn=fm().createFunction(name,start,body,SourceType.USER_DEFINED);if(fn==null)throw new IllegalStateException("function creation failed "+start);
      result.add(start+"\t"+name+"\t"+fn.getBody().getNumAddresses());println("RECOVER_OVERLAP_THUMB "+start+" "+name+" bytes="+fn.getBody().getNumAddresses());
    }
    Files.write(out,result,StandardCharsets.UTF_8);
  }
  private FunctionManager fm(){return currentProgram.getFunctionManager();}
  private void readBoundaries(Path p)throws Exception {for(String s:Files.readAllLines(p))if(!s.isBlank()&&!s.startsWith("#"))boundaries.add(toAddr(s.split("\\t")[0]));}
}
