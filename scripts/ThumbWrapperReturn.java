import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import java.util.*;

/** Guided return-flow experiment, only for four exact push-LR/call/pop-r0 wrappers. */
public class ThumbWrapperReturn extends GhidraScript {
  private static final long[] ENTRIES={0x080c9c9cL,0x080d5274L,0x080d8988L,0x080d9adcL};
  private static final long[] CALLEES={0x080c9ca8L,0x080d52c8L,0x080d89acL,0x080d9ae8L};
  private static final int[] CONSTANTS={1,1,4,3};
  @Override public void run() throws Exception {
    if(getScriptArgs().length!=0)throw new IllegalArgumentException("ThumbWrapperReturn.java takes no arguments");
    List<Instruction> returns=new ArrayList<>();
    for(int n=0;n<ENTRIES.length;n++) {
      Address a=toAddr(ENTRIES[n]);
      Function f=currentProgram.getFunctionManager().getFunctionAt(a);
      if(f==null||f.getBody().getNumAddressRanges()!=1||f.getBody().getNumAddresses()!=12||
          !f.getBody().getMinAddress().equals(a)||!f.getBody().getMaxAddress().equals(a.add(11)))
        throw new IllegalStateException("unexpected wrapper body at "+a);
      Instruction push=getInstructionAt(a),mov=getInstructionAt(a.add(2)),call=getInstructionAt(a.add(4)),
        pop=getInstructionAt(a.add(8)),ret=getInstructionAt(a.add(10));
      if(push==null||mov==null||call==null||pop==null||ret==null||
          !HexFormat.of().formatHex(push.getBytes()).equals("00b5")||
          !HexFormat.of().formatHex(mov.getBytes()).equals(String.format("%02x21",CONSTANTS[n]))||
          call.getLength()!=4||!call.getFlowType().isCall()||call.getFlows().length!=1||
          call.getFlows()[0].getOffset()!=CALLEES[n]||
          !HexFormat.of().formatHex(pop.getBytes()).equals("01bc")||
          !HexFormat.of().formatHex(ret.getBytes()).equals("0047")||
          (ret.getFlowOverride()!=FlowOverride.NONE&&ret.getFlowOverride()!=FlowOverride.RETURN))
        throw new IllegalStateException("unexpected wrapper instruction sequence at "+a);
      returns.add(ret);
    }
    // No intervening stack write or branch: pop r0 restores exactly the LR saved at entry.
    for(Instruction ret:returns) {
      ret.setFlowOverride(FlowOverride.RETURN);
      currentProgram.getListing().setComment(ret.getAddress(),CommentType.EOL,
        "Guided RETURN override: exact push {lr}; movs r1,#constant; bl callee; pop {r0}; bx r0. " +
        "Restores saved LR with balanced wrapper stack; no inferred jump table.");
      println("RETURN_OVERRIDE "+ret.getAddress()+" flow="+ret.getFlowType());
    }
  }
}
