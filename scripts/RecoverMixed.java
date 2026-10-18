import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Source-bounded mode-segment recovery for explicitly mapped ARM/Thumb mixed functions. */
public class RecoverMixed extends GhidraScript {
  private static final class Seg {String mode;Address lo,hi;Seg(String m,Address a,Address b){mode=m;lo=a;hi=b;}}
  public void run() throws Exception {
    String[] args=getScriptArgs();if(args.length!=2)throw new IllegalArgumentException("targets.tsv output.tsv");
    Path output=Paths.get(args[1]);if(output.getParent()!=null)Files.createDirectories(output.getParent());List<String> report=new ArrayList<>();
    for(String raw:Files.readAllLines(Paths.get(args[0]),StandardCharsets.UTF_8)) {
      if(raw.isBlank()||raw.startsWith("#"))continue;String[] f=raw.split("\\t");if(f.length!=3)throw new IllegalArgumentException("address/name/segments required: "+raw);
      Address entry=toAddr(f[0]);String name=f[1];List<Seg> segs=new ArrayList<>();
      for(String part:f[2].split(";")){String[] p=part.split(",");if(p.length!=3||!(p[0].equals("A")||p[0].equals("T")))throw new IllegalArgumentException("bad mode segment "+part);Address lo=toAddr(p[1]),hi=toAddr(p[2]);int step=p[0].equals("A")?4:2;if(lo.compareTo(hi)>0||((hi.getOffset()-lo.getOffset()+1)%step)!=0||(lo.getOffset()&(step-1))!=0)throw new IllegalArgumentException("unaligned segment "+part);segs.add(new Seg(p[0],lo,hi));}
      if(segs.isEmpty()||!segs.get(0).lo.equals(entry)||fm().getFunctionAt(entry)!=null||fm().getFunctionContaining(entry)!=null)throw new IllegalStateException("invalid entry/function conflict "+entry);
      Listing listing=currentProgram.getListing();Register tm=currentProgram.getProgramContext().getRegister("TMode");AddressSet body=new AddressSet();
      for(Seg s:segs){body.add(s.lo,s.hi);int step=s.mode.equals("A")?4:2;BigInteger mode=s.mode.equals("A")?BigInteger.ZERO:BigInteger.ONE;
        for(Address a=s.lo;a.compareTo(s.hi)<=0;a=a.add(step)){
          Instruction old=listing.getInstructionContaining(a);Data d=listing.getDefinedDataContaining(a);
          if(old!=null&&(!old.getAddress().equals(a)||old.getLength()!=step))throw new IllegalStateException("instruction overlap at "+a+": "+old);
          if(d!=null&&!d.getDataType().getName().startsWith("undefined"))throw new IllegalStateException("refusing typed data at "+a+": "+d.getDataType());
        }
      }
      for(Seg s:segs){int step=s.mode.equals("A")?4:2;BigInteger mode=s.mode.equals("A")?BigInteger.ZERO:BigInteger.ONE;
        for(Address a=s.lo;a.compareTo(s.hi)<=0;a=a.add(step)){
          if(listing.getInstructionAt(a)==null){listing.clearCodeUnits(a,a.add(step-1),false);currentProgram.getProgramContext().setValue(tm,a,a,mode);
            boolean ok;if(s.mode.equals("A")){DisassembleCommand cmd=new DisassembleCommand(a,new AddressSet(a,a.add(step-1)),true);cmd.setInitialContext(new RegisterValue(tm,mode));cmd.enableCodeAnalysis(false);ok=cmd.applyTo(currentProgram,monitor);}
            else{ArmDisassembleCommand cmd=new ArmDisassembleCommand(a,new AddressSet(a,a.add(step-1)),true);cmd.enableCodeAnalysis(false);ok=cmd.applyTo(currentProgram,monitor);}
            if(!ok)throw new IllegalStateException("decode failed at "+a);
          }
          Instruction i=listing.getInstructionAt(a);if(i==null||i.getLength()!=step||!mode.equals(currentProgram.getProgramContext().getValue(tm,a,false)))throw new IllegalStateException("mode/decode mismatch at "+a+" expected "+s.mode);
        }
      }
      Function fn=fm().createFunction(name,entry,body,SourceType.USER_DEFINED);if(fn==null)throw new IllegalStateException("function creation failed at "+entry);
      report.add(entry+"\t"+name+"\t"+body.getNumAddresses());println("RECOVER_MIXED "+entry+" "+name+" bytes="+body.getNumAddresses()+" segments="+segs.size());
    }
    Files.write(output,report,StandardCharsets.UTF_8);
  }
  private FunctionManager fm(){return currentProgram.getFunctionManager();}
}
