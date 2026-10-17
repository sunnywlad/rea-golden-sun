"""Check recovery audits against approved source instructions and after reopening."""
import argparse
import json
from pathlib import Path
import re


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for argument in ("plan","before","after","reopened","output"):
        parser.add_argument(argument,type=Path)
    args=parser.parse_args()
    load=lambda path:json.loads(path.read_text())
    plan=load(args.plan)["targets"]
    before=load(args.before/"snapshot.json")
    after=load(args.after/"snapshot.json")
    reopened=load(args.reopened/"snapshot.json")
    wanted={r["address"] for r in plan}
    added=set(after["functions"])-set(before["functions"])
    assert added==wanted,dict(unexpected=sorted(added-wanted),missing=sorted(wanted-added))
    assert before["memory"]==after["memory"]
    for address,digest in before["defined_data"].items():
        assert after["defined_data"].get(address)==digest,("old data changed",address)
    added_data=set(after["defined_data"])-set(before["defined_data"])
    literals={lit["address"]:lit for row in plan for lit in row.get("literals",[])}
    assert added_data<=set(literals),("new data outside approved literal slots",sorted(added_data-set(literals)))
    if literals:
        literal_rows=load(args.after/"literals.json")
        assert literal_rows==load(args.reopened/"literals.json"),"literal evidence differs after reopening"
        literal_actual={row["address"]:row for row in literal_rows}
        assert set(literal_actual)==set(literals)
        for address,expected in literals.items():
            actual=literal_actual[address]
            value=int(expected["value"],0) if isinstance(expected["value"],str) else expected["value"]
            assert not actual["instruction_overlap"] and actual["value"]==value
            assert actual["bytes"]==value.to_bytes(4,"little").hex()
            if address in added_data:
                unit=actual["data_unit"]
                assert unit and unit["start"]==address and unit["length"]==4
                assert int(unit["end"],16)==int(address,16)+3
    for address,function in before["functions"].items():
        assert after["functions"][address]==function,("old function changed",address)
    for address,digest in before["instructions"].items():
        assert after["instructions"][address]==digest,("old instruction changed",address)
    expected_ins={i["address"] for row in plan for i in row["instructions"]}
    new_ins=set(after["instructions"])-set(before["instructions"])
    assert new_ins==expected_ins,dict(unexpected_instructions=sorted(new_ins-expected_ins),missing=sorted(expected_ins-new_ins))
    assert after==reopened,"saved program differs after reopening"
    targets=load(args.after/"targets.json")
    assert targets==load(args.reopened/"targets.json"),"target export differs after reopening"
    exported={t["address"]:t for t in targets}
    checks=[]
    for row in plan:
        actual=exported[row["address"]]
        assert actual["exists"] and actual["tmode"]=="1"
        assert actual["body_size"]==row["code_bytes"]
        expected_body=row.get("body_ranges",[dict(start=row["address"],end=row["code_end"])])
        assert actual["body"]==expected_body,(row["name"],actual["body"],expected_body)
        assert actual["decompile_completed"]
        instructions=actual["instructions"]
        assert len(instructions)==len(row["instructions"])
        for expected,ins in zip(row["instructions"],instructions):
            for field in ("address","length","bytes"):
                assert expected[field]==ins[field],(row["name"],field,expected,ins)
            assert ins["tmode"]=="1"
            source=expected["source"]
            mnemonic=source.split()[0]
            if mnemonic in ("b","bl","beq","bne","bgt","bge","blt","ble","bhi","bls","bcs","bcc","bmi","bpl","bvs","bvc"):
                label=source.split()[-1]
                target=row.get("branch_targets",{}).get(expected["address"],row["labels"].get(label))
                if target is None:
                    match=re.fullmatch(r"Func_([0-9a-fA-F]+)",label)
                    assert match,("unresolved branch label",row["name"],source)
                    target=hex(0x08000000+int(match[1],16))
                assert target in ins["flows"],(row["name"],source,ins["flows"])
        filename=f'{int(row["address"],16):08x}_{row["name"]}.c'
        assert (args.after/filename).read_bytes()==(args.reopened/filename).read_bytes()
        checks.append(dict(name=row["name"],body_bytes=actual["body_size"],
                           instructions=len(instructions),warnings=actual["warning_count"]))
    result=dict(verified=True,created=len(added),before_functions=before["function_count"],
                after_functions=after["function_count"],added_instructions=len(new_ins),
                memory_unchanged=True,old_functions_instructions_and_data_unchanged=True,
                new_code_matches_source_addresses_lengths_bytes=True,reopened_state_and_c_identical=True,
                approved_literal_slots=len(literals),new_literal_data_units=len(added_data),
                targets=checks,caveat="guided recovery; source control flow verified, C semantic equivalence not established")
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
