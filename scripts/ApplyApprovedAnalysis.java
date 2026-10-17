import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

/** Apply only reviewed return overrides and trailing-pool definitions; never run analysis or clear code/data. */
public class ApplyApprovedAnalysis extends GhidraScript {
  private static final Pattern RETURN=Pattern.compile("bx\\s+(r[0-7])");
  @Override public void run() throws Exception {
    String[] args=getScriptArgs();
    if(args.length!=2)throw new IllegalArgumentException("ApplyApprovedAnalysis.java plan.json approved-returns.json");
    byte[] planBytes=Files.readAllBytes(Paths.get(args[0]));
    JsonObject plan=JsonParser.parseString(new String(planBytes,java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
    JsonObject evidence=JsonParser.parseString(Files.readString(Paths.get(args[1]))).getAsJsonObject();
    require("approved-thumb-returns-v1".equals(evidence.get("schema").getAsString()),"unsupported evidence schema");
    require(hexBytes(MessageDigest.getInstance("SHA-256").digest(planBytes)).equals(evidence.get("plan_sha256").getAsString()),"evidence belongs to another plan");
    Map<String,JsonObject> sources=new HashMap<>(),previous=new HashMap<>();
    Map<String,Address> owners=new HashMap<>();Map<Address,Long> slots=new TreeMap<>();
    Set<String> entries=new HashSet<>();
    // Complete preflight before ANY mutation, including every pool value and overlap.
    for(JsonElement element:plan.getAsJsonArray("targets")) {
      monitor.checkCancelled();JsonObject row=element.getAsJsonObject();Address entry=toAddr(row.get("address").getAsString());
      require(entries.add(entry.toString()),"duplicate target "+entry);
      Function f=getFunctionAt(entry);require(f!=null,"missing target "+entry);
      require(f.getName().equals(row.get("name").getAsString()),"target name mismatch "+entry);
      Address end=toAddr(row.get("code_end").getAsString()),boundary=toAddr(row.get("next_boundary").getAsString());
      AddressSet expectedBody=expectedBody(row,entry);
      require(new AddressSet(f.getBody()).equals(expectedBody)&&f.getBody().getNumAddresses()==row.get("code_bytes").getAsLong(),"body mismatch "+entry);
      JsonArray instructions=row.getAsJsonArray("instructions");Address cursor=entry;JsonObject prev=null;AddressSet planned=new AddressSet();
      for(JsonElement item:instructions) {
        JsonObject source=item.getAsJsonObject();Address a=toAddr(source.get("address").getAsString());Instruction ins=getInstructionAt(a);
        require((row.has("body_ranges")?a.compareTo(cursor)>=0:a.equals(cursor))&&!sources.containsKey(hex(a)),"out-of-order/duplicate instruction "+a);
        require(ins!=null&&ins.getLength()==source.get("length").getAsInt()&&hexBytes(ins.getBytes()).equals(source.get("bytes").getAsString()),"instruction mismatch "+a);
        require(tmode(a).equals("1"),"not Thumb "+a);
        sources.put(hex(a),source);owners.put(hex(a),entry);if(prev!=null)previous.put(hex(a),prev);
        cursor=a.add(ins.getLength());planned.add(a,cursor.subtract(1));prev=source;
      }
      require(planned.equals(expectedBody),"incomplete instruction coverage "+entry);
      if(row.has("literals"))for(JsonElement item:row.getAsJsonArray("literals")) {
        JsonObject literal=item.getAsJsonObject();Address a=toAddr(literal.get("address").getAsString());long value=number(literal.get("value"));
        require(literal.get("size").getAsInt()==4&&(a.getOffset()&3)==0&&a.compareTo(entry)>=0&&a.add(3).compareTo(boundary)<0&&!expectedBody.intersects(new AddressSet(a,a.add(3))),"invalid literal slot "+a);
        require(row.has("body_ranges")||a.compareTo(end)>0,"internal pool without approved layout "+a);
        require(value>=0&&value<=0xffffffffL,"literal value outside uint32 "+a);
        require(!slots.containsKey(a)||slots.get(a).longValue()==value,"conflicting literal values "+a);slots.put(a,value);
      }
    }
    List<Address> newData=new ArrayList<>();
    for(Map.Entry<Address,Long> slot:slots.entrySet()) {
      Address a=slot.getKey();require(Integer.toUnsignedLong(currentProgram.getMemory().getInt(a))==slot.getValue(),"literal value mismatch "+a);
      boolean defined=false;
      for(int n=0;n<4;n++) {
        require(currentProgram.getListing().getInstructionContaining(a.add(n))==null,"literal overlaps instruction "+a);
        if(currentProgram.getListing().getDefinedDataContaining(a.add(n))!=null)defined=true;
      }
      if(!defined)newData.add(a); // Any existing data, including partial coverage, is retained as-is.
    }
    Map<Address,JsonObject> approved=new TreeMap<>();
    for(JsonElement element:evidence.getAsJsonArray("returns")) {
      JsonObject row=element.getAsJsonObject();Address a=toAddr(row.get("address").getAsString());String key=hex(a);
      require(!approved.containsKey(a)&&sources.containsKey(key),"duplicate/out-of-plan return "+a);
      require(owners.get(key).equals(toAddr(row.get("entry").getAsString())),"wrong return owner "+a);
      require("RETURN".equals(row.get("override").getAsString())&&"1".equals(row.get("tmode").getAsString()),"unapproved override/mode "+a);
      Instruction ins=getInstructionAt(a);require(hexBytes(ins.getBytes()).equals(row.get("bytes").getAsString())&&tmode(a).equals("1"),"evidence bytes/mode mismatch "+a);
      require(ins.getFlowOverride()==FlowOverride.NONE||ins.getFlowOverride()==FlowOverride.RETURN,"existing different override "+a);
      checkReturn(sources.get(key),previous.get(key),ins);
      List<String> raw=pcode(ins,false),effective=strings(row.getAsJsonArray("effective_pcode"));
      require(raw.equals(strings(row.getAsJsonArray("raw_pcode"))),"raw P-code mismatch "+a);
      PcodeOp[] rawOps=ins.getPcode(false);require(rawOps.length>0&&rawOps[rawOps.length-1].getOpcode()==PcodeOp.BRANCHIND,"raw return is not BRANCHIND "+a);
      require(returnPcode(raw).equals(effective),"unapproved effective P-code "+a);
      if(ins.getFlowOverride()==FlowOverride.RETURN)require(pcode(ins,true).equals(effective),"existing return P-code mismatch "+a);
      approved.put(a,row);
    }
    // An idempotent rerun may already contain these approved overrides, and no others.
    for(String key:sources.keySet()) {
      Instruction i=getInstructionAt(toAddr(key));
      require(i.getFlowOverride()==FlowOverride.NONE||(i.getFlowOverride()==FlowOverride.RETURN&&approved.containsKey(i.getAddress())),"override outside approved evidence "+key);
    }
    Map<String,List<String>> functionsBefore=functions();Map<Address,String> dataBefore=data();
    int applied=0,existing=0;
    for(Address a:approved.keySet()) {
      monitor.checkCancelled();Instruction ins=getInstructionAt(a);
      if(ins.getFlowOverride()==FlowOverride.RETURN)existing++;
      else {ins.setFlowOverride(FlowOverride.RETURN);applied++;}
      require(pcode(ins,true).equals(strings(approved.get(a).getAsJsonArray("effective_pcode"))),"applied P-code mismatch "+a);
    }
    for(Address a:newData) {
      monitor.checkCancelled();currentProgram.getListing().createData(a,Undefined4DataType.dataType,4);
    }
    require(functionsBefore.equals(functions()),"function signatures/names/bodies changed");
    Map<Address,String> after=data();
    for(Map.Entry<Address,String> row:dataBefore.entrySet())require(row.getValue().equals(after.get(row.getKey())),"old defined data changed "+row.getKey());
    Set<Address> added=new HashSet<>(after.keySet());added.removeAll(dataBefore.keySet());
    require(added.equals(new HashSet<>(newData)),"unexpected new data units");
    for(Address a:newData) {Data d=currentProgram.getListing().getDefinedDataAt(a);require(d!=null&&d.getLength()==4&&d.getDataType().getPathName().equals(Undefined4DataType.dataType.getPathName()),"wrong new literal data "+a);}
    for(Map.Entry<Address,Long> slot:slots.entrySet())require(Integer.toUnsignedLong(currentProgram.getMemory().getInt(slot.getKey()))==slot.getValue(),"literal bytes changed");
    println("APPLY_APPROVED returns_applied="+applied+" returns_preexisting="+existing+" literal_units_created="+newData.size()+" literal_slots_preserved="+(slots.size()-newData.size()));
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
    Matcher m=RETURN.matcher(source.get("source").getAsString().trim());require(m.matches()&&previous!=null,"return lacks source pop/BX "+ins.getAddress());
    String reg=m.group(1);int r=reg.charAt(1)-'0';
    require(previous.get("source").getAsString().trim().matches("pop\\s+\\{"+reg+"\\}"),"source pop/BX mismatch "+ins.getAddress());
    Address a=toAddr(previous.get("address").getAsString());Instruction pop=getInstructionAt(a);
    require(pop!=null&&pop.getLength()==2&&a.add(2).equals(ins.getAddress())&&tmode(a).equals("1"),"pop not adjacent Thumb "+ins.getAddress());
    require(ins.getLength()==2&&hexBytes(pop.getBytes()).equals(word(0xbc00|(1<<r)))&&hexBytes(ins.getBytes()).equals(word(0x4700|(r<<3))),"pop/BX opcode mismatch "+ins.getAddress());
  }
  private Map<String,List<String>> functions(){Map<String,List<String>> result=new TreeMap<>();FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);while(it.hasNext()){Function f=it.next();result.put(hex(f.getEntryPoint()),Arrays.asList(f.getName(),new AddressSet(f.getBody()).toString(),f.getSignature().toString(),f.getSignatureSource().toString(),String.valueOf(f.getCallingConventionName()),String.valueOf(f.getStackPurgeSize())));}return result;}
  private Map<Address,String> data(){Map<Address,String> result=new TreeMap<>();DataIterator it=currentProgram.getListing().getDefinedData(true);while(it.hasNext()){Data d=it.next();result.put(d.getAddress(),d.getLength()+":"+d.getDataType().getPathName());}return result;}
  private long number(JsonElement e){String s=e.getAsString();return s.startsWith("0x")?Long.parseUnsignedLong(s.substring(2),16):Long.parseLong(s);}
  private List<String> strings(JsonArray values){List<String> result=new ArrayList<>();for(JsonElement value:values)result.add(value.getAsString());return result;}
  private List<String> pcode(Instruction i,boolean overrides){List<String> result=new ArrayList<>();for(PcodeOp op:i.getPcode(overrides))result.add(op.toString());return result;}
  private List<String> returnPcode(List<String> raw){List<String> result=new ArrayList<>(raw);require(!result.isEmpty(),"empty P-code");int n=result.size()-1;require(result.get(n).contains("BRANCHIND"),"missing raw branch");result.set(n,result.get(n).replace("BRANCHIND","RETURN"));return result;}
  private String tmode(Address a){Register r=currentProgram.getProgramContext().getRegister("TMode");require(r!=null,"missing TMode");BigInteger v=currentProgram.getProgramContext().getValue(r,a,false);return v==null?"unset":v.toString();}
  private String word(int value){return hexBytes(new byte[]{(byte)value,(byte)(value>>>8)});}
  private String hexBytes(byte[] b){return HexFormat.of().formatHex(b);}
  private String hex(Address a){return "0x"+Long.toHexString(a.getOffset());}
  private void require(boolean condition,String message){if(!condition)throw new IllegalStateException(message);}
}
