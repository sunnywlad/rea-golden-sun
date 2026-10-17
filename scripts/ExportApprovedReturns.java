import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

/** Read-only extraction of automatically recognized, source-confirmed Thumb returns. */
public class ExportApprovedReturns extends GhidraScript {
  private static final Pattern RETURN=Pattern.compile("bx\\s+(r[0-7])");
  @Override public void run() throws Exception {
    String[] args=getScriptArgs();
    if(args.length!=2)throw new IllegalArgumentException("ExportApprovedReturns.java plan.json output.json");
    byte[] planBytes=Files.readAllBytes(Paths.get(args[0]));
    JsonObject plan=JsonParser.parseString(new String(planBytes,java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
    JsonArray returns=new JsonArray();Set<String> entries=new HashSet<>(),addresses=new HashSet<>();
    int targetCount=0;
    for(JsonElement element:plan.getAsJsonArray("targets")) {
      monitor.checkCancelled();JsonObject row=element.getAsJsonObject();
      Address entry=toAddr(row.get("address").getAsString());
      require(entries.add(entry.toString()),"duplicate target "+entry);
      Function f=getFunctionAt(entry);require(f!=null,"missing target "+entry);
      require(f.getName().equals(row.get("name").getAsString()),"target name mismatch "+entry);
      AddressSet expectedBody=expectedBody(row,entry);
      require(new AddressSet(f.getBody()).equals(expectedBody),"body mismatch "+entry);
      require(f.getBody().getNumAddresses()==row.get("code_bytes").getAsLong(),"body size mismatch "+entry);
      JsonArray instructions=row.getAsJsonArray("instructions");Address cursor=entry;AddressSet planned=new AddressSet();
      for(int n=0;n<instructions.size();n++) {
        JsonObject source=instructions.get(n).getAsJsonObject();
        Address a=toAddr(source.get("address").getAsString());
        require((row.has("body_ranges")?a.compareTo(cursor)>=0:a.equals(cursor))&&addresses.add(a.toString()),"out-of-order/duplicate instruction "+a);
        Instruction ins=getInstructionAt(a);require(ins!=null,"missing instruction "+a);
        require(ins.getLength()==source.get("length").getAsInt(),"instruction length mismatch "+a);
        require(hexBytes(ins.getBytes()).equals(source.get("bytes").getAsString()),"instruction bytes mismatch "+a);
        require(tmode(a).equals("1"),"not Thumb "+a);cursor=a.add(ins.getLength());planned.add(a,cursor.subtract(1));
        if(ins.getFlowOverride()==FlowOverride.NONE)continue;
        require(ins.getFlowOverride()==FlowOverride.RETURN,"unapproved override "+a+": "+ins.getFlowOverride());
        require(n>0,"return lacks preceding pop "+a);
        checkReturn(source,instructions.get(n-1).getAsJsonObject(),ins);
        List<String> raw=pcode(ins,false),effective=pcode(ins,true);
        require(ins.getPcode(false).length>0&&ins.getPcode(false)[ins.getPcode(false).length-1].getOpcode()==PcodeOp.BRANCHIND,
          "return raw P-code is not BRANCHIND "+a);
        require(returnPcode(raw).equals(effective),"return P-code changes beyond final operation "+a);
        JsonObject evidence=new JsonObject();
        evidence.addProperty("address",hex(a));evidence.addProperty("entry",hex(entry));
        evidence.addProperty("override","RETURN");evidence.addProperty("bytes",hexBytes(ins.getBytes()));
        evidence.addProperty("tmode",tmode(a));
        evidence.add("raw_pcode",new Gson().toJsonTree(raw));evidence.add("effective_pcode",new Gson().toJsonTree(effective));
        returns.add(evidence);
      }
      require(planned.equals(expectedBody),"incomplete instruction coverage "+entry);
      int instructionCount=0;InstructionIterator bodyInstructions=currentProgram.getListing().getInstructions(f.getBody(),true);
      while(bodyInstructions.hasNext()){bodyInstructions.next();instructionCount++;}
      require(instructionCount==instructions.size(),"unplanned target instruction "+entry);
      targetCount++;
    }
    JsonObject output=new JsonObject();output.addProperty("schema","approved-thumb-returns-v1");
    output.addProperty("plan_sha256",hexBytes(MessageDigest.getInstance("SHA-256").digest(planBytes)));
    output.addProperty("targets",targetCount);output.add("returns",returns);
    Path path=Paths.get(args[1]);if(path.getParent()!=null)Files.createDirectories(path.getParent());
    Files.writeString(path,new GsonBuilder().setPrettyPrinting().create().toJson(output)+"\n");
    println("APPROVED_RETURN_EXPORT targets="+targetCount+" returns="+returns.size());
  }
  private AddressSet expectedBody(JsonObject row,Address entry) {
    Address end=toAddr(row.get("code_end").getAsString());AddressSet result=new AddressSet();
    if(row.has("body_ranges")) {
      require(row.has("layout")&&"thumb-inline-v1".equals(row.get("layout").getAsString()),"unrecognized body layout");
      for(JsonElement item:row.getAsJsonArray("body_ranges")){JsonObject r=item.getAsJsonObject();Address start=toAddr(r.get("start").getAsString()),stop=toAddr(r.get("end").getAsString());require(start.compareTo(entry)>=0&&stop.compareTo(start)>=0&&stop.compareTo(end)<=0,"invalid body range");result.add(start,stop);}
    } else result.add(entry,end);
    require(!result.isEmpty()&&result.getMinAddress().equals(entry)&&result.getMaxAddress().equals(end),"invalid body limits");return result;
  }
  private void checkReturn(JsonObject source,JsonObject previous,Instruction ins)throws Exception {
    Matcher m=RETURN.matcher(source.get("source").getAsString().trim());
    require(m.matches(),"override is not a source BX low register "+ins.getAddress());
    String reg=m.group(1);int r=reg.charAt(1)-'0';
    require(previous.get("source").getAsString().trim().matches("pop\\s+\\{"+reg+"\\}"),"source pop/BX mismatch "+ins.getAddress());
    Address popAddress=toAddr(previous.get("address").getAsString());Instruction pop=getInstructionAt(popAddress);
    require(pop!=null&&pop.getLength()==2&&popAddress.add(2).equals(ins.getAddress())&&tmode(popAddress).equals("1"),"pop not adjacent Thumb "+ins.getAddress());
    require(ins.getLength()==2&&hexBytes(pop.getBytes()).equals(word(0xbc00|(1<<r)))&&
      hexBytes(ins.getBytes()).equals(word(0x4700|(r<<3))),"pop/BX opcode mismatch "+ins.getAddress());
  }
  private List<String> pcode(Instruction i,boolean overrides){List<String> result=new ArrayList<>();for(PcodeOp op:i.getPcode(overrides))result.add(op.toString());return result;}
  private List<String> returnPcode(List<String> raw){List<String> result=new ArrayList<>(raw);require(!result.isEmpty(),"empty P-code");int n=result.size()-1;require(result.get(n).contains("BRANCHIND"),"missing raw branch");result.set(n,result.get(n).replace("BRANCHIND","RETURN"));return result;}
  private String tmode(Address a){Register r=currentProgram.getProgramContext().getRegister("TMode");require(r!=null,"missing TMode");BigInteger v=currentProgram.getProgramContext().getValue(r,a,false);return v==null?"unset":v.toString();}
  private String word(int value){return HexFormat.of().formatHex(new byte[]{(byte)value,(byte)(value>>>8)});}
  private String hexBytes(byte[] b){return HexFormat.of().formatHex(b);}
  private String hex(Address a){return "0x"+Long.toHexString(a.getOffset());}
  private void require(boolean condition,String message){if(!condition)throw new IllegalStateException(message);}
}
