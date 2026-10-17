import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Recover reference-confirmed ARM CFG on a COPY; no bytes, modes, or data are cleared. */
public class Func9bb8Flow extends GhidraScript {
  private static final Gson JSON = new GsonBuilder().serializeNulls().setPrettyPrinting().create();
  private static final long ENTRY = 0x08009bb8L, BRANCH = 0x08009cd8L, TABLE = 0x08009cdcL;
  private static final long[][] CODE = {
    {0x08009bb8L,0x08009bd3L}, {0x08009bd8L,0x08009c8bL},
    {0x08009c90L,0x08009cdbL}, {0x08009cfcL,0x08009d8fL}
  };
  private static final long[][] DATA = {
    {0x08009bd4L,0x08009bd7L}, // unreachable NOP, preserved too
    {0x08009c8cL,0x08009c8fL}, {0x08009cdcL,0x08009cfbL},
    {0x08009d90L,0x08009e7bL}
  };
  private static final long[] EXPECTED = {
    0x08009bc0L,0x08009d00L,0x08009d00L,0x08009d00L,
    0x08009d00L,0x08009d00L,0x08009d00L,0x08009cacL,
    0x08009cacL,0x08009cfcL,0x08009cfcL,0x08009cfcL,
    0x08009cfcL,0x08009c90L,0x08009ca4L,0x08009c9cL
  };

  @Override public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 2 || !(args[0].equals("inspect") || args[0].equals("repair")))
      throw new IllegalArgumentException("Func9bb8Flow.java <inspect|repair> <output-directory>");
    Path out = Paths.get(args[1]); Files.createDirectories(out);
    Function f = currentProgram.getFunctionManager().getFunctionAt(toAddr(ENTRY));
    if (f == null) throw new IllegalStateException("missing Func_9bb8");
    Map<String,Object> before = snapshot(); write(out.resolve("before.json"), before);
    write(out.resolve("before_decompile.json"), decompile(f, out.resolve("before.c")));
    ArrayList<Address> unique = new ArrayList<Address>();
    List<Map<String,Object>> cases = new ArrayList<Map<String,Object>>();
    for (int i=0;i<16;i++) {
      Address slot=toAddr(TABLE+2*i);
      short offset=currentProgram.getMemory().getShort(slot);
      Address target=toAddr(BRANCH+8+offset);
      if (target.getOffset()!=EXPECTED[i]) throw new IllegalStateException("table mismatch at case "+i);
      if (!unique.contains(target)) unique.add(target);
      cases.add(map("case",i,"slot",hex(slot),"signed_offset",(int)offset,"target",hex(target)));
    }
    write(out.resolve("table.json"), cases);
    if (args[0].equals("repair")) {
      AddressSet allowed=set(CODE);
      Listing listing=currentProgram.getListing();
      // Reject collisions or a wrong pre-existing mode, rather than overwrite either.
      for (long[] range:CODE) for(long n=range[0];n<=range[1];n+=4) {
        Address a=toAddr(n); Instruction ins=listing.getInstructionContaining(a);
        Data data=listing.getDefinedDataContaining(a);
        Function owner=currentProgram.getFunctionManager().getFunctionContaining(a);
        if (data!=null || (ins!=null && (!ins.getAddress().equals(a)||ins.getLength()!=4)) ||
            (owner!=null && !owner.equals(f)) || !"0".equals(tmode(a)))
          throw new IllegalStateException("code/data/owner/mode collision at "+a);
      }
      // Restrict disassembly to independently established code intervals. No automatic analysis.
      for(long[] range:CODE) for(long n=range[0];n<=range[1];n+=4) {
        Address a=toAddr(n);
        if (listing.getInstructionAt(a)!=null) continue;
        DisassembleCommand cmd=new DisassembleCommand(a,allowed,true);
        cmd.enableCodeAnalysis(false);
        if (!cmd.applyTo(currentProgram,monitor) || listing.getInstructionAt(a)==null)
          throw new IllegalStateException("disassembly failed at "+a+": "+cmd.getStatusMsg());
      }
      Instruction branch=listing.getInstructionAt(toAddr(BRANCH));
      for(Address target:unique) {
        boolean found=false;
        for(Reference r:branch.getReferencesFrom())
          if(r.getToAddress().equals(target)&&r.getReferenceType().isJump()) found=true;
        if(!found) branch.addOperandReference(0,target,RefType.COMPUTED_JUMP,SourceType.USER_DEFINED);
      }
      // This is the same supported mechanism as Ghidra's bundled SwitchOverride.java.
      new JumpTable(toAddr(BRANCH),unique,true,0).writeOverride(f);
      CreateFunctionCmd.fixupFunctionBody(currentProgram,f,monitor);
      if(!new AddressSet(f.getBody()).equals(allowed))
        throw new IllegalStateException("recovered CFG differs from reference code ranges: "+f.getBody());
      listing.setComment(toAddr(BRANCH),CommentType.EOL,
        "Guided recovery: 16 signed halfwords at 08009cdc, targets = 08009ce0 + offset. " +
        "Finite targets justified by gsret/goldensun rom_92b8.s; inputs outside 0..15 unvalidated.");
      listing.setComment(toAddr(ENTRY),CommentType.PLATE,
        "ROM storage of code copied to allocated RAM via DMA3 by Func_aa0c, Func_c880 and Func_c62c. " +
        "PC-relative cache/buffer at 08009d90/08009d9c are writable only in that relocated copy. " +
        "This function models ROM CFG, not a reconstructed runtime instance.");
    }
    Map<String,Object> after=snapshot(); write(out.resolve("after.json"),after);
    write(out.resolve("after_decompile.json"),decompile(f,out.resolve("after.c")));
    List<Object> asm=new ArrayList<Object>();
    InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(it.hasNext()) asm.add(instruction(it.next()));
    write(out.resolve("instructions.json"),asm);
    Map<String,Object> checks=new LinkedHashMap<String,Object>();
    for(String key:new String[]{"memory","other_functions","preserved_units","tmode"})
      checks.put(key+"_unchanged",before.get(key).equals(after.get(key)));
    checks.put("function_count_unchanged",before.get("function_count").equals(after.get("function_count")));
    checks.put("body_matches_reference_code",new AddressSet(f.getBody()).equals(set(CODE)));
    checks.put("target_body_bytes",f.getBody().getNumAddresses());
    write(out.resolve("checks.json"),checks);
    for(String key:new String[]{"memory_unchanged","other_functions_unchanged","preserved_units_unchanged","tmode_unchanged","function_count_unchanged"})
      if(!Boolean.TRUE.equals(checks.get(key))) throw new IllegalStateException("invariant failed: "+key);
    println("FUNC9BB8 "+args[0]+" body="+f.getBody().getNumAddresses()+" checks="+JSON.toJson(checks));
  }

  private Map<String,Object> snapshot() throws Exception {
    List<Object> others=new ArrayList<Object>(); int count=0;
    FunctionIterator fi=currentProgram.getFunctionManager().getFunctions(true);
    while(fi.hasNext()) {
      Function f=fi.next(); count++;
      if(f.getEntryPoint().getOffset()!=ENTRY)
        others.add(map("entry",hex(f.getEntryPoint()),"name",f.getName(),"body",ranges(f.getBody())));
    }
    List<Object> memory=new ArrayList<Object>(); byte[] buf=new byte[65536];
    for(MemoryBlock b:currentProgram.getMemory().getBlocks()) {
      String hash=null;
      if(b.isInitialized()) {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        for(Address p=b.getStart();p.compareTo(b.getEnd())<=0;) {
          int n=(int)Math.min(buf.length,b.getEnd().subtract(p)+1);
          int got=currentProgram.getMemory().getBytes(p,buf,0,n);
          if(got!=n) throw new IllegalStateException("short memory read");
          digest.update(buf,0,n);p=p.add(n);
        }
        hash=HexFormat.of().formatHex(digest.digest());
      }
      memory.add(map("name",b.getName(),"start",hex(b.getStart()),"end",hex(b.getEnd()),
        "read",b.isRead(),"write",b.isWrite(),"execute",b.isExecute(),"sha256",hash));
    }
    List<Object> units=new ArrayList<Object>();
    for(long[] range:DATA) for(long n=range[0];n<=range[1];n++) {
      CodeUnit cu=currentProgram.getListing().getCodeUnitContaining(toAddr(n));
      units.add(map("at",hex(toAddr(n)),"start",hex(cu.getMinAddress()),"end",hex(cu.getMaxAddress()),
        "type",cu instanceof Instruction?"instruction":"data","text",cu.toString()));
    }
    List<Object> modes=new ArrayList<Object>();
    for(long n=ENTRY;n<0x08009e7cL;n++) modes.add(tmode(toAddr(n)));
    Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(ENTRY));
    List<Object> listing=new ArrayList<Object>();
    InstructionIterator ii=currentProgram.getListing().getInstructions(new AddressSet(toAddr(ENTRY),toAddr(0x08009e7bL)),true);
    while(ii.hasNext()) listing.add(instruction(ii.next()));
    List<Object> symbols=new ArrayList<Object>();
    SymbolIterator si=currentProgram.getSymbolTable().getAllSymbols(true);
    while(si.hasNext()) { Symbol s=si.next(); if(s.getAddress().isMemoryAddress() && s.getAddress().getOffset()>=ENTRY && s.getAddress().getOffset()<0x08009e7cL)
      symbols.add(map("at",hex(s.getAddress()),"name",s.getName(true),"source",s.getSource().toString())); }
    return map("function_count",count,"other_functions",others,"memory",memory,
      "preserved_units",units,"tmode",modes,"body",ranges(f.getBody()),"body_bytes",f.getBody().getNumAddresses(),
      "instructions",listing,"symbols",symbols,"annotations",map(
        "entry_plate",currentProgram.getListing().getComment(CommentType.PLATE,toAddr(ENTRY)),
        "dispatch_eol",currentProgram.getListing().getComment(CommentType.EOL,toAddr(BRANCH))));
  }

  private Map<String,Object> instruction(Instruction ins) {
    List<Object> refs=new ArrayList<Object>();
    for(Reference r:ins.getReferencesFrom()) refs.add(map("to",hex(r.getToAddress()),"type",r.getReferenceType().toString(),"source",r.getSource().toString(),"operand",r.getOperandIndex()));
    List<String> flows=new ArrayList<String>();for(Address a:ins.getFlows())flows.add(hex(a));
    return map("at",hex(ins.getAddress()),"length",ins.getLength(),"text",ins.toString(),
      "flow_type",ins.getFlowType().toString(),"flows",flows,"references",refs,
      "fallthrough",ins.getFallThrough()==null?null:hex(ins.getFallThrough()));
  }

  private Map<String,Object> decompile(Function f,Path path) throws Exception {
    DecompInterface di=new DecompInterface();
    try {
      if(!di.openProgram(currentProgram))throw new IllegalStateException(di.getLastMessage());
      DecompileResults d=di.decompileFunction(f,45,monitor);
      String c=d.getDecompiledFunction()==null?"":d.getDecompiledFunction().getC();
      Files.writeString(path,c,StandardCharsets.UTF_8);
      List<Object> tables=new ArrayList<Object>();
      if(d.getHighFunction()!=null)for(JumpTable t:d.getHighFunction().getJumpTables()) {
        List<String> cases=new ArrayList<String>();for(Address a:t.getCases())cases.add(hex(a));
        tables.add(map("branch",hex(t.getSwitchAddress()),"cases",cases,"labels",t.getLabelValues()));
      }
      return map("completed",d.decompileCompleted(),"error",d.getErrorMessage(),
        "warning_count",c.split("WARNING",-1).length-1,"jump_tables",tables,"c_file",path.getFileName().toString());
    } finally {di.dispose();}
  }
  private String tmode(Address a) {
    Register r=currentProgram.getProgramContext().getRegister("TMode");
    BigInteger v=currentProgram.getProgramContext().getValue(r,a,false);
    return v==null?"unset":v.toString();
  }
  private AddressSet set(long[][] intervals) {AddressSet s=new AddressSet();for(long[] r:intervals)s.add(toAddr(r[0]),toAddr(r[1]));return s;}
  private List<Object> ranges(AddressSetView body) {List<Object> r=new ArrayList<Object>();for(AddressRange a:body.getAddressRanges())r.add(map("start",hex(a.getMinAddress()),"end",hex(a.getMaxAddress())));return r;}
  private Map<String,Object> map(Object... pairs) {Map<String,Object> m=new LinkedHashMap<String,Object>();for(int i=0;i<pairs.length;i+=2)m.put((String)pairs[i],pairs[i+1]);return m;}
  private void write(Path p,Object data)throws Exception {Files.writeString(p,JSON.toJson(data)+"\n",StandardCharsets.UTF_8);}
  private String hex(Address a){return "0x"+Long.toHexString(a.getOffset());}
}
