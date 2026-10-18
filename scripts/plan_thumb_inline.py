"""Plan Thumb functions with explicitly delimited inline pools, without Ghidra mutations.

Accept only .word, .align 2,0 and literal-pool flush directives. Every declared
word must be read by a ROM-decoded literal LDR. All code must be reachable without
fallthrough into data or padding. No computed branches except simple returns.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from plan_thumb_literals import (ROM_BASE, ROM_SHA1, CONDITIONS, MNEMONICS, SYMBOL,
    FUNCTION, Excluded, Symbols, branch_target, clean, sign)


def ranges(instructions):
    result = []
    for row in instructions:
        start = int(row["address"], 16)
        end = start + row["length"] - 1
        if result and int(result[-1]["end"], 16) + 1 == start:
            result[-1]["end"] = hex(end)
        else:
            result.append(dict(start=hex(start), end=hex(end)))
    return result


def validate_cfg(candidate, symbols):
    instructions = sorted(candidate["instructions"], key=lambda i: int(i["address"], 16))
    computed_addresses = {int(row["instruction"], 16) for row in candidate["computed_branches"]}
    padding_addresses = {a for row in candidate["padding"]
        for a in range(int(row["start"], 16), int(row["end"], 16) + 1, 2)}
    nops = []
    for ins in instructions:
        mnemonic = ins["source"].split()[0]
        terminates = mnemonic == "b" or int(ins["address"], 16) in computed_addresses or \
            (mnemonic == "bx" and "call_via_register" not in ins)
        next_address = int(ins["address"], 16) + ins["length"]
        if not terminates and next_address in padding_addresses:
            nops.append(dict(address=hex(next_address), length=2, bytes="0000",
                source="movs r0, r0", line=ins["line"], executed_alignment_nop=True))
            padding_addresses.remove(next_address)
    instructions.extend(nops)
    instructions.sort(key=lambda i: int(i["address"], 16))
    candidate["instructions"] = instructions
    candidate["body_ranges"] = ranges(instructions)
    candidate["code_bytes"] = sum(i["length"] for i in instructions)
    candidate["code_end"] = max((int(i["address"], 16) + i["length"] - 1 for i in instructions))
    candidate["code_end"] = hex(candidate["code_end"])
    by_address = {int(i["address"], 16): n for n, i in enumerate(instructions)}
    computed = {int(row["instruction"], 16): row for row in candidate["computed_branches"]}
    edges = {}
    verified_tail_calls = []
    for n, ins in enumerate(instructions):
        statement = ins["source"]
        mnemonic = statement.split()[0]
        address = int(ins["address"], 16)
        opcode, = struct.unpack("<H", bytes.fromhex(ins["bytes"])[:2])
        successors, fallthrough = [], True
        if mnemonic == "swi":
            match = re.fullmatch(r"swi\s+(0[xX][0-9a-fA-F]+|[0-9]+)",statement)
            immediate = int(match[1],0) if match else -1
            if not 0 <= immediate <= 255 or opcode != (0xdf00|immediate):
                raise Excluded("SWI immediate/opcode mismatch")
        elif mnemonic == "bx":
            register = statement.split()[-1]
            r = 14 if register == "lr" else int(register[1:]) if re.fullmatch(r"r[0-9]+", register) else -1
            if not 0 <= r <= 14 or opcode != (0x4700 | r << 3):
                raise Excluded("BX opcode/register mismatch")
            if "call_via_register" in ins:
                if register != ins["call_via_register"] or n == 0 or \
                        instructions[n-1]["source"] != "mov r12, pc" or \
                        instructions[n-1].get("call_via_move_for") != hex(address):
                    raise Excluded("computed call does not match the verified .call_via expansion")
                move_opcode, = struct.unpack("<H", bytes.fromhex(instructions[n-1]["bytes"]))
                if move_opcode != 0x46fc:
                    raise Excluded(".call_via link-address opcode mismatch")
            elif register != "lr":
                adjacent_pop = n > 0 and int(instructions[n-1]["address"],16)+instructions[n-1]["length"] == address and re.fullmatch(r"pop\s+\{"+re.escape(register)+r"\}", instructions[n-1]["source"])
                literal_tail = False
                if register == "r3" and n > 0:
                    prev = instructions[n-1]
                    load = re.fullmatch(r"ldr\s+r3\s*,\s*(?:=\s*)?(.+)", prev["source"])
                    evidence = next((lit for lit in candidate["literals"] if lit["instruction"] == prev["address"]), None)
                    literal_tail = bool(load and evidence and int(evidence["value"],16) == 0x03007001 and
                                        candidate.get("literal_word_expressions", {}).get(evidence["address"]) == "iwram_7001" and
                                        int(prev["address"],16)+prev["length"] == address)
                if adjacent_pop:
                    fallthrough = False
                elif literal_tail:
                    verified_tail_calls.append(dict(instruction=ins["address"],target="0x3007000",
                        target_pointer="0x3007001",kind="source-verified IWRAM tail transfer"))
                    fallthrough = False
                else:
                    raise Excluded("computed branch without adjacent source pop/BX or verified IWRAM tail target")
            else:
                fallthrough = False
        elif mnemonic == "mov" and re.fullmatch(r"mov\s+pc\s*,\s*r3", statement):
            dispatch = computed.get(address)
            if opcode != 0x469f or dispatch is None:
                raise Excluded("unproven computed PC branch at " + ins["address"])
            for target in dispatch["targets"]:
                destination = int(target["address"], 16)
                if destination not in by_address:
                    raise Excluded("computed branch target is not a planned instruction")
                successors.append(by_address[destination])
            fallthrough = False
        elif mnemonic in ("b", "bl") or mnemonic in CONDITIONS:
            label = statement.split()[-1]
            try:
                target = branch_target(label, candidate, symbols)
            except Excluded:
                if mnemonic != "bl" or label not in candidate.get("external_return_labels", {}):
                    raise
                target = int(candidate["external_return_labels"][label], 16)
            if mnemonic == "bl":
                second, = struct.unpack("<H", bytes.fromhex(ins["bytes"])[2:])
                if opcode & 0xf800 != 0xf000 or second & 0xf800 != 0xf800:
                    raise Excluded("BL opcode mismatch")
                actual = address + 4 + sign(((opcode & 0x7ff)<<12)|((second & 0x7ff)<<1), 23)
            elif mnemonic == "b":
                if opcode & 0xf800 != 0xe000:
                    raise Excluded("B opcode mismatch")
                actual = address + 4 + sign((opcode & 0x7ff)<<1, 12)
            else:
                if opcode >> 8 != (0xd0 | CONDITIONS[mnemonic]):
                    raise Excluded("conditional branch opcode mismatch")
                actual = address + 4 + sign((opcode & 0xff)<<1, 9)
            if actual != target:
                raise Excluded("branch ROM/source mismatch at " + ins["address"])
            candidate["branch_targets"][ins["address"]] = hex(target)
            if mnemonic == "bl" and target in by_address:
                successors.append(by_address[target])
            elif mnemonic != "bl":
                if target in by_address:
                    successors.append(by_address[target])
                elif label in candidate["labels"]:
                    raise Excluded("local branch enters data/padding")
            if mnemonic == "b":
                fallthrough = False
        elif mnemonic == "pop" and re.search(r"\bpc\b", statement):
            raise Excluded("POP PC not supported by this planner")
        if fallthrough:
            next_address = address + ins["length"]
            if next_address not in by_address:
                raise Excluded("fallthrough enters data/padding or leaves source at " + ins["address"])
            successors.append(by_address[next_address])
        edges[n] = successors
    reached, pending = set(), [0]
    while pending:
        n = pending.pop()
        if n not in reached:
            reached.add(n)
            pending.extend(edges[n])
    if len(reached) != len(instructions):
        missing = next(i["address"] for n, i in enumerate(instructions) if n not in reached)
        raise Excluded("unreachable source instruction: " + missing)
    candidate["cfg_evidence"] = dict(all_instructions_reachable=True,
        no_fallthrough_into_data_or_padding=True, returning_calls_assumed=True,
        call_via_expansion_verified=True, executed_alignment_fill_decoded_as_nop=True,
        computed_pc_dispatches_verified=len(candidate["computed_branches"]))
    candidate["verified_tail_calls"] = verified_tail_calls


def computed_dispatches(instructions, labels, declared_words, declared_expressions):
    by_address = {int(i["address"], 16): n for n, i in enumerate(instructions)}
    result, used_words = [], set()
    for n, ins in enumerate(instructions):
        if not re.fullmatch(r"mov\s+pc\s*,\s*r3", ins["source"]):
            continue
        if n < 3:
            raise Excluded("computed PC branch lacks the reviewed table-load idiom")
        prefix = [item["source"] for item in instructions[n-3:n-1]]
        bases = [re.fullmatch(r"ldr\s+(r[0-7])\s*,\s*=\s*(\.L[0-9a-fA-F]+)", item) for item in prefix]
        shifts = [re.fullmatch(r"lsl\s+r3\s*,\s*(?:(r[0-7])\s*,\s*)?#?2", item) for item in prefix]
        base = next((item for item in bases if item), None)
        shifted = next((item for item in shifts if item), None)
        table_load = instructions[n-1]["source"]
        loaded = re.fullmatch(r"ldr\s+r3\s*,\s*\[r3\s*,\s*(r[0-7])\s*\]", table_load)
        if not base or not shifted or not loaded or base[1] != loaded[1]:
            raise Excluded("computed PC branch lacks the reviewed table-load idiom")
        table_label = base[2]
        if table_label not in labels:
            raise Excluded("computed branch table label is not local")
        table_address = int(labels[table_label], 16)
        table_rows = []
        cursor = table_address
        while cursor in declared_words:
            expression = declared_expressions[cursor].strip()
            target_label = re.fullmatch(r"\.L[0-9a-fA-F]+", expression)
            if not target_label or expression not in labels:
                raise Excluded("computed branch table contains an unproven local target")
            target_address = int(labels[expression], 16)
            if target_address not in by_address:
                raise Excluded("computed branch table target is not a code instruction")
            if declared_words[cursor] != target_address:
                raise Excluded("computed branch table value differs from its local target")
            table_rows.append(dict(address=hex(cursor), target=expression, value=hex(target_address)))
            used_words.add(cursor)
            cursor += 4
        if not table_rows:
            raise Excluded("computed branch table has no explicit words")
        index_register = shifted[1] or "r3"
        branch_index = n - 3
        bound_matches = []
        for cmp_index in range(max(0, branch_index-12), branch_index):
            compare = re.fullmatch(r"cmp\s+(r[0-7])\s*,\s*#(0[xX][0-9a-fA-F]+|[0-9]+)",
                                   instructions[cmp_index]["source"])
            if not compare or compare[1] != index_register:
                continue
            maximum = int(compare[2], 0)
            for guard_index in range(cmp_index+1, min(branch_index, cmp_index+4)):
                guard = instructions[guard_index]["source"].split()
                if len(guard) != 2 or guard[0] not in ("bhi", "bls"):
                    continue
                label = guard[1]
                if label not in labels or maximum + 1 != len(table_rows):
                    continue
                target = int(labels[label], 16)
                if guard[0] == "bls" and target > int(ins["address"], 16):
                    continue
                if guard[0] == "bhi" and target == table_address:
                    continue
                bound_matches.append(dict(compare=instructions[cmp_index]["address"],
                    guard=instructions[guard_index]["address"],condition=guard[0],label=label,
                    index_register=index_register,maximum=maximum))
        if len(bound_matches) != 1:
            raise Excluded("computed branch table length lacks one matching bounds guard")
        result.append(dict(instruction=ins["address"],table=table_label,
            table_address=hex(table_address),index_register=index_register,
            bound=bound_matches[0],entries=table_rows,
            targets=[dict(label=row["target"],address=row["value"]) for row in table_rows]))
    return result, used_words


def parse_function(work, row, boundary, rom, symbols):
    definition, = row["definitions"]
    source = definition["path"]
    lines = (work / "repo" / source).read_text().splitlines()
    header = FUNCTION.fullmatch(clean(lines[definition["line"]-1]))
    if not header or not header[1].startswith("thumb") or header[2] != row["name"]:
        raise Excluded("header does not establish requested Thumb entry")
    cursor = start = int(row["address"], 16)
    instructions, labels, literals, pending, explicit = [], {}, [], [], []
    literal_words, declared_words, declared_expressions, padding = {}, {}, {}, []
    call_via_calls = []
    ended = False

    def verify_call_via_macro():
        macro_lines = [re.sub(r"\s+", " ", line.split("@", 1)[0].strip())
                       for line in (work / "repo/include/macros.inc").read_text().splitlines()]
        try:
            macro_start = macro_lines.index(".macro .call_via reg")
            macro_end = macro_lines.index(".endm", macro_start + 1)
        except ValueError as error:
            raise Excluded(".call_via macro definition is missing") from error
        if macro_lines[macro_start:macro_end+1] != [".macro .call_via reg", ".align 2, 0",
                                                    "mov r12, pc", "bx \\reg", ".endm"]:
            raise Excluded(".call_via macro no longer matches the reviewed expansion")

    def read(address, size):
        if address < start or address + size > boundary:
            raise Excluded("source layout extends outside function storage window")
        return rom[address-ROM_BASE:address-ROM_BASE+size]

    def align():
        nonlocal cursor
        aligned = (cursor+3)&~3
        if aligned != cursor:
            raw = read(cursor, aligned-cursor)
            if raw != bytes(aligned-cursor):
                raise Excluded("alignment does not contain expected zero fill")
            padding.append(dict(start=hex(cursor), end=hex(aligned-1)))
            cursor = aligned

    def flush(always_align):
        nonlocal cursor
        if not pending and not always_align:
            return
        align()
        if not pending:
            return
        slots = sorted({int(lit["address"],16) for lit in pending})
        if slots != list(range(cursor, cursor+4*len(slots), 4)):
            raise Excluded("pending pseudo-loads do not describe exactly the next pool")
        for lit in pending:
            address = int(lit["address"],16)
            value = int(lit["value"],16)
            if address in literal_words and literal_words[address] != value:
                raise Excluded("conflicting pool words")
            literal_words[address] = value
        cursor += 4*len(slots)
        pending.clear()

    for n in range(definition["line"],len(lines)):
        line = clean(lines[n])
        if not line:
            continue
        if line.startswith(".func_end"):
            if line.split() != [".func_end",row["name"]]:
                raise Excluded("mismatched function end")
            flush(True)
            ended = True
            break
        if re.fullmatch(SYMBOL+":",line):
            label = line[:-1]
            if label in labels:
                raise Excluded("duplicate label")
            anchor = re.fullmatch(r"\.L([0-9a-fA-F]+)",label)
            if anchor and ROM_BASE+int(anchor[1],16) != cursor:
                raise Excluded("local address label disagrees with computed layout: " + label)
            labels[label] = hex(cursor)
            continue
        if line == ".pool_aligned":
            flush(True)
            continue
        if line == ".pool":
            flush(False)
            continue
        call_via = re.fullmatch(r"\.call_via\s+(r(?:[0-9]|1[0-2])|sp|lr)", line)
        if call_via:
            verify_call_via_macro()
            register = call_via[1]
            align()
            move_address = cursor
            move_raw = read(cursor, 2)
            move_opcode, = struct.unpack("<H", move_raw)
            if move_opcode != 0x46fc:
                raise Excluded(".call_via MOV r12,pc bytes disagree with the macro")
            instructions.append(dict(address=hex(cursor), length=2, bytes=move_raw.hex(),
                source="mov r12, pc", line=n+1, call_via_move_for=hex(cursor+2)))
            cursor += 2
            bx_address = cursor
            bx_raw = read(cursor, 2)
            bx_opcode, = struct.unpack("<H", bx_raw)
            register_number = 13 if register == "sp" else 14 if register == "lr" else int(register[1:])
            if bx_opcode != (0x4700 | register_number << 3):
                raise Excluded(".call_via BX bytes disagree with the macro register")
            instructions.append(dict(address=hex(cursor), length=2, bytes=bx_raw.hex(),
                source="bx " + register, line=n+1, call_via_register=register))
            call_via_calls.append(dict(move=hex(move_address), bx=hex(bx_address), register=register,
                contract="verified .call_via macro sets r12 to the continuation before branching"))
            cursor += 2
            continue
        if re.fullmatch(r"\.align\s+2\s*,\s*0",line):
            align()
            continue
        word = re.fullmatch(r"\.word\s+(.+)",line)
        if word:
            if cursor % 4:
                raise Excluded("unaligned explicit word")
            value, evidence = symbols.expression(word[1], source)
            if read(cursor,4) != value.to_bytes(4,"little"):
                raise Excluded("explicit word differs from ROM")
            if cursor in declared_words and declared_words[cursor] != value:
                raise Excluded("conflicting explicit word declarations")
            declared_words[cursor] = value
            declared_expressions[cursor] = word[1].strip()
            cursor += 4
            continue
        if line.startswith(".") or re.search(r"\b(?:pc|r15)\b",line):
            if not re.fullmatch(r"mov\s+pc\s*,\s*r3", line):
                raise Excluded("unsupported directive/macro or explicit PC: " + line)
        mnemonic = line.split()[0]
        if mnemonic not in MNEMONICS | {"swi"}:
            raise Excluded("unsupported instruction: " + mnemonic)
        length = 4 if mnemonic == "bl" else 2
        raw = read(cursor,length)
        ins = dict(address=hex(cursor),length=length,bytes=raw.hex(),source=line,line=n+1)
        instructions.append(ins)
        pseudo = re.fullmatch(r"ldr\s+(r[0-7])\s*,\s*=(.+)",line)
        direct = re.fullmatch(r"ldr\s+(r[0-7])\s*,\s*("+SYMBOL+")",line)
        opcode, = struct.unpack("<H",raw[:2])
        if "=" in line and not pseudo:
            raise Excluded("unsupported pseudo instruction")
        if pseudo or direct:
            register = (pseudo or direct)[1]
            if opcode & 0xf800 != 0x4800 or (opcode>>8)&7 != int(register[1:]):
                raise Excluded("literal load opcode/register mismatch")
            slot = ((cursor+4)&~3)+4*(opcode&0xff)
            value, = struct.unpack("<I",read(slot,4))
            lit = dict(instruction=hex(cursor),address=hex(slot),size=4,value=hex(value),register=register,source_line=n+1)
            if pseudo:
                expected,evidence = symbols.expression(pseudo[2],source)
                if value != expected:
                    raise Excluded("pseudo expression differs from ROM")
                lit.update(expression=pseudo[2],symbol_evidence=evidence,source_kind="pseudo")
                pending.append(lit)
            else:
                lit.update(expression=direct[2],symbol_evidence=[],source_kind="explicit_label")
                explicit.append(lit)
            literals.append(lit)
        elif opcode & 0xf800 == 0x4800:
            raise Excluded("unexplained encoded literal LDR")
        cursor += length
    if not ended or not instructions:
        raise Excluded("missing end or code")
    if not literals and not any(i["source"].split()[0]=="swi" for i in instructions):
        raise Excluded("no literal loads or supported system instruction")
    external_return_labels = {}
    for line_no, raw in enumerate(lines):
        match = re.fullmatch(r"\.(L[0-9a-fA-F]+):", clean(raw))
        if not match:
            continue
        following_line = next((re.sub(r"\s+", " ", clean(item)) for item in lines[line_no+1:] if clean(item)), "")
        if following_line == "bx r3":
            address = 0x08000000 + int(match[1][1:], 16)
            if rom[address-ROM_BASE:address-ROM_BASE+2] != b"\x18\x47":
                raise Excluded("external returning label source/opcode mismatch: " + match[0])
            external_return_labels["." + match[1]] = hex(address)
    for lit in explicit:
        if labels.get(lit["expression"]) != lit["address"]:
            raise Excluded("explicit LDR label does not match encoded pool address")
    computed_branches, table_words = computed_dispatches(instructions, labels,
        declared_words, declared_expressions)
    literal_addresses = {int(lit["address"],16) for lit in literals}
    explicit_literal_addresses = {int(lit["address"],16) for lit in explicit}
    if set(declared_words) != explicit_literal_addresses | table_words:
        raise Excluded("word declaration unused by a demonstrated literal load or dispatch table")
    words = dict(declared_words)
    for address,value in literal_words.items():
        if address in words and words[address] != value:
            raise Excluded("literal pool conflicts with explicit word")
        words[address] = value
    if not literal_addresses <= set(words):
        raise Excluded("literal load has no source/ROM-confirmed pool word")
    code_bytes = {a for i in instructions for a in range(int(i["address"],16),int(i["address"],16)+i["length"])}
    for address,value in words.items():
        if any(a in code_bytes for a in range(address,address+4)):
            raise Excluded("literal overlaps code")
        if read(address,4) != value.to_bytes(4,"little"):
            raise Excluded("pool value changed")
    candidate = dict(name=row["name"],address=row["address"],mode="thumb",source=source,
        definition_line=definition["line"],layout="thumb-inline-v1",next_boundary=hex(boundary),
        code_end=hex(max(code_bytes)),source_end=hex(cursor-1),code_bytes=len(code_bytes),
        body_ranges=ranges(instructions),instructions=instructions,labels=labels,literals=literals,
        padding=padding,branch_targets={},alias_evidence={},call_via_calls=call_via_calls,
        computed_branches=computed_branches,external_return_labels=external_return_labels,
        literal_word_expressions={hex(a):expr for a,expr in declared_expressions.items()})
    validate_cfg(candidate,symbols)
    return candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline",type=Path)
    parser.add_argument("output",type=Path)
    parser.add_argument("--aliases",type=Path,required=True)
    parser.add_argument("--names",nargs="+")
    args = parser.parse_args()
    work = Path(__file__).resolve().parents[1]/"work"
    rom = (work/"rom/Golden Sun (USA, Europe).gba").read_bytes()
    if hashlib.sha1(rom).hexdigest() != ROM_SHA1:
        raise ValueError("unexpected ROM")
    state = json.loads(args.baseline.read_text())
    existing = set(state.get("function_entries",state.get("functions",{})))
    symbols = Symbols(work,rom,json.loads(args.aliases.read_text())["aliases"])
    boundaries = sorted(int(s.split()[0],16) for s in (work/"repo_function_boundaries.tsv").read_text().splitlines() if s.strip() and not s.startswith("#"))
    following = dict(zip(boundaries,boundaries[1:]))
    targets,skipped = [],[]
    for row in json.loads((work/"remaining_reference.json").read_text())["entries"]:
        if row["address"] in existing or row["mode"] != "thumb" or row["category"] != "undefined_executable" or "runtime_address" in row:
            continue
        if args.names and row["name"] not in args.names:
            continue
        try:
            targets.append(parse_function(work,row,following[int(row["address"],16)],rom,symbols))
        except (Excluded,ValueError,KeyError) as error:
            skipped.append(dict(name=row["name"],address=row["address"],reason=str(error)))
    targets.sort(key=lambda row:int(row["address"],16))
    sources = [args.baseline,args.aliases,Path(__file__),Path(__file__).with_name("plan_thumb_literals.py"),work/"remaining_reference.json",work/"repo_function_boundaries.tsv"]
    sources += [work/"repo"/p for p in ("wram.sym","include/gba.inc","include/macros.inc")]
    sources += [work/"repo"/name for name in sorted({r["source"] for r in targets})]
    symbolic_sources = {proof["source"] for row in targets for lit in row["literals"]
        for proof in lit["symbol_evidence"] if "source" in proof}
    sources += [work/"repo"/name for name in sorted(symbolic_sources)]
    result = dict(baseline=str(args.baseline),targets=targets,skipped=skipped,
        provenance=dict(rom_sha1=ROM_SHA1,source_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}))
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/"plan.json").write_text(json.dumps(result,indent=2)+"\n")
    (args.output/"targets.tsv").write_text("".join(f'{r["address"]}\t{r["name"]}\n' for r in targets))
    stats = dict(selected=len(targets),skipped=len(skipped),instructions=sum(len(r["instructions"]) for r in targets),
        code_bytes=sum(r["code_bytes"] for r in targets),pool_words=len({l["address"] for r in targets for l in r["literals"]}))
    (args.output/"summary.json").write_text(json.dumps(stats,indent=2)+"\n")
    print(json.dumps(stats))
    if args.names and set(args.names) != {r["name"] for r in targets}:
        raise ValueError("requested candidates excluded; see skipped entries")


if __name__ == "__main__":
    main()
