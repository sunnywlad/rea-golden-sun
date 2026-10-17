import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.util.*;

/** Read-only effective/raw p-code and prototype evidence for the four return probes. */
public class ReturnEvidence extends GhidraScript {
  @Override public void run() throws Exception {
    if(getScriptArgs().length!=1)throw new IllegalArgumentException("ReturnEvidence.java output.json");
    List<Object> rows=new ArrayList<>();
    for(long entry:new long[]{0x080c9c9cL,0x080d5274L,0x080d8988L,0x080d9adcL}) {
      Function f=getFunctionAt(toAddr(entry));Instruction ret=getInstructionAt(toAddr(entry+10));
      List<String> raw=new ArrayList<>(),effective=new ArrayList<>();
      for(PcodeOp op:ret.getPcode(false))raw.add(op.toString());
      for(PcodeOp op:ret.getPcode(true))effective.add(op.toString());
      Map<String,Object> row=new LinkedHashMap<>();row.put("entry",f.getEntryPoint().toString());
      row.put("signature",f.getSignature().toString());row.put("signature_source",f.getSignatureSource().toString());
      row.put("calling_convention",f.getCallingConventionName());row.put("stack_purge",f.getStackPurgeSize());
      row.put("return_address",ret.getAddress().toString());row.put("flow_type",ret.getFlowType().toString());
      row.put("override",ret.getFlowOverride().toString());row.put("raw_pcode",raw);row.put("effective_pcode",effective);
      row.put("comment",currentProgram.getListing().getComment(CommentType.EOL,ret.getAddress()));rows.add(row);
    }
    Path out=Paths.get(getScriptArgs()[0]);Files.createDirectories(out.getParent());
    Files.writeString(out,new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(rows)+"\n");
  }
}
