"""Verify scoped ARM-analysis deltas and persistence without claiming C prototype correctness."""
import argparse
import json
import re
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("before","after","reopened","output"):
        parser.add_argument(name,type=Path)
    args=parser.parse_args()
    load=lambda p:json.loads(p.read_text())
    before=load(args.before/"snapshot.json")
    after=load(args.after/"snapshot.json")
    reopened=load(args.reopened/"snapshot.json")
    for field in ("function_count","functions","memory","defined_data"):
        assert before[field]==after[field],field
    assert set(before["instructions"])==set(after["instructions"])
    global_changes={a for a,v in before["instructions"].items() if v!=after["instructions"][a]}
    targets_before=load(args.before/"targets.json")
    targets_after=load(args.after/"targets.json")
    assert after==reopened
    assert targets_after==load(args.reopened/"targets.json")
    assert len(targets_before)==len(targets_after)
    target_changes=set()
    suspicious=[]
    wide_suspicious=[]
    for b,a in zip(targets_before,targets_after):
        for field in ("address","name","tmode","exists","body","body_size"):
            assert b[field]==a[field],(b["name"],field)
        assert len(b["instructions"])==len(a["instructions"])
        for old,new in zip(b["instructions"],a["instructions"]):
            if old==new:
                continue
            assert old["flow_type"]=="COMPUTED_JUMP" and new["flow_type"]=="TERMINATOR"
            assert {k:v for k,v in old.items() if k!="flow_type"}=={k:v for k,v in new.items() if k!="flow_type"}
            target_changes.add(old["address"])
        assert a["decompile_completed"] and a["warning_count"]==0
        filename=f'{int(a["address"],16):08x}_{a["name"]}.c'
        c=(args.after/filename).read_bytes()
        assert c==(args.reopened/filename).read_bytes()
        if b"CONCAT44(unaff_lr," in c:
            suspicious.append(a["name"])
        if b"unaff_lr" in c and re.search(rb"(?:undefined8|longlong)\s+Func_",c):
            wide_suspicious.append(a["name"])
    assert target_changes==global_changes,(target_changes,global_changes)
    result=dict(verified=True,functions=after["function_count"],target_functions=len(targets_after),
                changed_return_instructions=len(global_changes),changed_addresses=sorted(global_changes),
                warnings_before=sum(t["warning_count"] for t in targets_before),
                warnings_after=0,memory_data_bodies_and_other_instructions_unchanged=True,
                reopened_state_and_c_identical=True,
                concat44_lr_return_type_suspects=suspicious,
                wide_lr_return_type_suspects=wide_suspicious,
                caveat="Automatic return recognition validated; source return widths/prototypes not established")
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("changed_addresses","concat44_lr_return_type_suspects")},indent=2))


if __name__=="__main__":
    main()
