import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Read-only audit of program invariants; target TSV is address<TAB>name. */
public class RecoveryAudit extends GhidraScript {
  private static final Gson JSON=new GsonBuilder().serializeNulls().setPrettyPrinting().create();
  @Override public void run() throws Exception {
    String[] args=getScriptArgs();
    if(args.length!=2)throw new IllegalArgumentException("RecoveryAudit.java targets.tsv output-directory");
    Path out=Paths.get(args[1]);Files.createDirectories(out);
    Map<String,Object> functions=new TreeMap<>(), insHashes=new TreeMap<>(), dataHashes=new TreeMap<>();
    List<Object> memory=new ArrayList<>();
    FunctionIterator fi=currentProgram.getFunctionManager().getFunctions(true);
    while(fi.hasNext()) {
      Function f=fi.next();functions.put(hex(f.getEntryPoint()),map("name",f.getName(),"body",ranges(f.getBody())));
    }
    MessageDigest digest=MessageDigest.getInstance("SHA-256");
    InstructionIterator ii=currentProgram.getListing().getInstructions(true);
    while(ii.hasNext()) {
      monitor.checkCancelled();Instruction i=ii.next();
      insHashes.put(hex(i.getAddress()),hash(digest,JSON.toJson(instruction(i))));
    }
    DataIterator dd=currentProgram.getListing().getDefinedData(true);
    while(dd.hasNext()) {
      Data d=dd.next();dataHashes.put(hex(d.getAddress()),hash(digest,
        d.getLength()+":"+d.getDataType().getPathName()));
    }
    byte[] buffer=new byte[65536];
    for(MemoryBlock b:currentProgram.getMemory().getBlocks()) {
      String bytesHash=null;
      if(b.isInitialized()) {
        digest.reset();
        for(Address a=b.getStart();a.compareTo(b.getEnd())<=0;) {
          int n=(int)Math.min(buffer.length,b.getEnd().subtract(a)+1);
          if(currentProgram.getMemory().getBytes(a,buffer,0,n)!=n)throw new IllegalStateException("short read");
          digest.update(buffer,0,n);a=a.add(n);
        }
        bytesHash=HexFormat.of().formatHex(digest.digest());
      }
      memory.add(map("name",b.getName(),"start",hex(b.getStart()),"end",hex(b.getEnd()),
        "read",b.isRead(),"write",b.isWrite(),"execute",b.isExecute(),"sha256",bytesHash));
    }
    write(out.resolve("snapshot.json"),map("function_count",functions.size(),"functions",functions,
      "instructions",insHashes,"defined_data",dataHashes,"memory",memory));
    List<Object> targets=new ArrayList<>();
    DecompInterface di=new DecompInterface();
    try {
      if(!di.openProgram(currentProgram))throw new IllegalStateException(di.getLastMessage());
      for(String raw:Files.readAllLines(Paths.get(args[0]))) {
        if(raw.isBlank()||raw.startsWith("#"))continue;
        String[] fields=raw.split("\\t");Address a=toAddr(fields[0]);
        Function f=currentProgram.getFunctionManager().getFunctionAt(a);
        Map<String,Object> t=map("address",hex(a),"name",fields[1],"tmode",tmode(a),"exists",f!=null);
        if(f!=null) {
          t.put("body",ranges(f.getBody()));t.put("body_size",f.getBody().getNumAddresses());
          List<Object> instructions=new ArrayList<>();
          InstructionIterator iter=currentProgram.getListing().getInstructions(f.getBody(),true);
          while(iter.hasNext())instructions.add(instruction(iter.next()));
          t.put("instructions",instructions);
          DecompileResults d=di.decompileFunction(f,30,monitor);
          String c=d.getDecompiledFunction()==null?"":d.getDecompiledFunction().getC();
          Files.writeString(out.resolve(a.toString()+"_"+fields[1]+".c"),c,StandardCharsets.UTF_8);
          t.put("decompile_completed",d.decompileCompleted());t.put("decompile_error",d.getErrorMessage());
          t.put("warning_count",c.split("WARNING",-1).length-1);
        }
        targets.add(t);
      }
    }finally{di.dispose();}
    write(out.resolve("targets.json"),targets);
    println("AUDIT functions="+functions.size()+" instructions="+insHashes.size()+" defined_data="+dataHashes.size());
  }
  private Map<String,Object> instruction(Instruction i)throws Exception {
    List<String> flows=new ArrayList<>();for(Address a:i.getFlows())flows.add(hex(a));Collections.sort(flows);
    List<String> refs=new ArrayList<>();for(Reference r:i.getReferencesFrom())refs.add(
      hex(r.getToAddress())+":"+r.getReferenceType()+":"+r.getOperandIndex()+":"+r.getSource());Collections.sort(refs);
    return map("address",hex(i.getAddress()),"length",i.getLength(),"text",i.toString(),
      "bytes",HexFormat.of().formatHex(i.getBytes()),"tmode",tmode(i.getAddress()),
      "flow_type",i.getFlowType().toString(),"flows",flows,"references",refs,
      "fallthrough",i.getFallThrough()==null?null:hex(i.getFallThrough()));
  }
  private String tmode(Address a) {
    Register r=currentProgram.getProgramContext().getRegister("TMode");
    BigInteger v=currentProgram.getProgramContext().getValue(r,a,false);return v==null?"unset":v.toString();
  }
  private List<Object> ranges(AddressSetView b) {List<Object> out=new ArrayList<>();for(AddressRange r:b.getAddressRanges())out.add(map("start",hex(r.getMinAddress()),"end",hex(r.getMaxAddress())));return out;}
  private String hash(MessageDigest d,String s){d.reset();return HexFormat.of().formatHex(d.digest(s.getBytes(StandardCharsets.UTF_8)));}
  private Map<String,Object> map(Object... pairs){Map<String,Object> m=new LinkedHashMap<>();for(int i=0;i<pairs.length;i+=2)m.put((String)pairs[i],pairs[i+1]);return m;}
  private void write(Path p,Object d)throws Exception{Files.writeString(p,JSON.toJson(d)+"\n",StandardCharsets.UTF_8);}
  private String hex(Address a){return "0x"+Long.toHexString(a.getOffset());}
}
