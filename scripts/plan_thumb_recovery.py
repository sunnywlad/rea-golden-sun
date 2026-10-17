"""Select reference-confirmed Thumb code with explicit instruction addresses, no literal pools."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def parse_function(root, row, boundary, rom):
    definition, = row["definitions"]
    path = root / "repo" / definition["path"]
    lines = path.read_text().splitlines()
    cursor = int(row["address"], 16)
    instructions, labels = [], {}
    for number in range(definition["line"], len(lines)):
        line = lines[number].split("@", 1)[0].strip()
        if not line:
            continue
        if line.startswith(".func_end"):
            break
        if line.endswith(":"):
            labels[line[:-1]] = hex(cursor)
            continue
        if line.startswith(".") or "=" in line:
            raise ValueError("directive, literal or macro: " + line)
        if re.search(r"\bpc\b", line) and not line.startswith("pop"):
            raise ValueError("explicit PC operation: " + line)
        mnemonic = line.split()[0]
        length = 4 if mnemonic == "bl" else 2
        if mnemonic in ("blx", "swi"):
            raise ValueError("interworking/system instruction")
        if cursor + length > boundary:
            raise ValueError("source extends beyond next function boundary")
        instructions.append(dict(address=hex(cursor), length=length, source=line,
                                 line=number + 1, bytes=rom[cursor-0x08000000:cursor-0x08000000+length].hex()))
        cursor += length
    if not instructions:
        raise ValueError("no instructions")
    return dict(name=row["name"], address=row["address"], mode="thumb",
                source=definition["path"], definition_line=definition["line"],
                next_boundary=hex(boundary), code_end=hex(cursor-1),
                code_bytes=cursor-int(row["address"],16), labels=labels,
                instructions=instructions)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline",type=Path)
    parser.add_argument("output",type=Path)
    parser.add_argument("--names",nargs="+")
    parser.add_argument("--max-code-bytes",type=int)
    parser.add_argument("--resolved-branches-and-returns",action="store_true")
    parser.add_argument("--aliases",type=Path,help="ROM-verified veneer addresses from resolve_thumb_aliases.py")
    args=parser.parse_args()
    work=Path(__file__).resolve().parents[1]/"work"
    baseline=json.loads(args.baseline.read_text())
    aliases=json.loads(args.aliases.read_text())["aliases"] if args.aliases else {}
    existing=set(baseline.get("function_entries",baseline.get("functions",{})))
    rows=json.loads((work/"remaining_reference.json").read_text())["entries"]
    boundaries=sorted(int(line.split()[0],16) for line in (work/"repo_function_boundaries.tsv").read_text().splitlines())
    following=dict(zip(boundaries,boundaries[1:]))
    rom=(work/"rom/Golden Sun (USA, Europe).gba").read_bytes()
    assert hashlib.sha1(rom).hexdigest()=="5c4695205413df7db52b9a184815a07783999971"
    plans,skipped=[],[]
    for row in rows:
        if row["address"] in existing or row["category"]!="undefined_executable" or "runtime_address" in row or row["mode"]!="thumb":
            continue
        if args.names and row["name"] not in args.names:
            continue
        try:
            candidate=parse_function(work,row,following[int(row["address"],16)],rom)
            if args.max_code_bytes and candidate["code_bytes"]>args.max_code_bytes:
                raise ValueError("exceeds approved maximum size")
            if args.resolved_branches_and_returns:
                previous=""
                candidate["branch_targets"]={}
                candidate["alias_evidence"]={}
                for ins in candidate["instructions"]:
                    statement=ins["source"]
                    mnemonic=statement.split()[0]
                    if mnemonic=="bx":
                        register=statement.split()[-1]
                        pop=re.fullmatch(r"pop\s+\{(r\d+)\}",previous)
                        if register!="lr" and not (pop and pop[1]==register):
                            raise ValueError("indirect branch without simple saved-register return")
                    elif mnemonic.startswith("b") and mnemonic!="bic":
                        label=statement.split()[-1]
                        if label in candidate["labels"]:
                            target=candidate["labels"][label]
                        elif re.fullmatch(r"Func_[0-9a-fA-F]+",label):
                            target=hex(0x08000000+int(label.removeprefix("Func_"),16))
                        elif label in aliases:
                            target=aliases[label]["address"]
                            candidate["alias_evidence"][label]=aliases[label]
                        else:
                            raise ValueError("unresolved direct branch/call target: "+label)
                        candidate["branch_targets"][ins["address"]]=target
                    previous=statement
            plans.append(candidate)
        except (ValueError,KeyError) as error:
            skipped.append(dict(name=row["name"],reason=str(error)))
    if args.names:
        absent=set(args.names)-{row["name"] for row in plans}
        if absent:
            raise ValueError(f"requested candidates excluded: {absent}, details: {skipped}")
    plans.sort(key=lambda r:int(r["address"],16))
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/"plan.json").write_text(json.dumps(dict(baseline=str(args.baseline),targets=plans,skipped=skipped),indent=2)+"\n")
    (args.output/"targets.tsv").write_text("".join(f'{r["address"]}\t{r["name"]}\n' for r in plans))
    print(json.dumps(dict(selected=len(plans),skipped=len(skipped),source_code_bytes=sum(r["code_bytes"] for r in plans))))


if __name__=="__main__":
    main()
