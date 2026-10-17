import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.util.*;

/** Read-only evidence for approved literal-pool slots, independent of function-body exports. */
public class LiteralAudit extends GhidraScript {
  @Override public void run() throws Exception {
    String[] args=getScriptArgs();
    if(args.length!=2)throw new IllegalArgumentException("LiteralAudit.java plan.json output.json");
    JsonObject plan=JsonParser.parseString(Files.readString(Paths.get(args[0]))).getAsJsonObject();
    TreeSet<Address> slots=new TreeSet<>();
    for(JsonElement element:plan.getAsJsonArray("targets")) {
      JsonObject t=element.getAsJsonObject();if(!t.has("literals"))continue;
      for(JsonElement lit:t.getAsJsonArray("literals"))slots.add(toAddr(lit.getAsJsonObject().get("address").getAsString()));
    }
    List<Object> evidence=new ArrayList<>();
    for(Address a:slots) {
      boolean instruction=false;
      for(int i=0;i<4;i++)if(currentProgram.getListing().getInstructionContaining(a.add(i))!=null)instruction=true;
      Data data=currentProgram.getListing().getDefinedDataContaining(a);
      Map<String,Object> d=null;
      if(data!=null) {
        d=new LinkedHashMap<>();d.put("start",hex(data.getMinAddress()));d.put("end",hex(data.getMaxAddress()));
        d.put("length",data.getLength());d.put("type",data.getDataType().getPathName());
      }
      byte[] bytes=new byte[4];currentProgram.getMemory().getBytes(a,bytes);
      Map<String,Object> row=new LinkedHashMap<>();row.put("address",hex(a));
      row.put("value",Integer.toUnsignedLong(currentProgram.getMemory().getInt(a)));
      row.put("bytes",HexFormat.of().formatHex(bytes));row.put("instruction_overlap",instruction);
      row.put("data_unit",d);evidence.add(row);
    }
    Path output=Paths.get(args[1]);Files.createDirectories(output.getParent());
    Files.writeString(output,new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(evidence)+"\n");
    println("LITERAL_AUDIT slots="+slots.size());
  }
  private String hex(Address a){return "0x"+Long.toHexString(a.getOffset());}
}
