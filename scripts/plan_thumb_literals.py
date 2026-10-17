"""Plan conservative Thumb recovery with ROM-verified trailing literal pools.

No Ghidra access. Only a .func_end-generated pool is accepted; internal data,
alignment, mode switches, macros, and optimized pseudo-loads are excluded.
Literal values are hexadecimal uint32 strings. Reachability is a syntactic
intraprocedural CFG check, with returning calls assumed to preserve SP.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import struct


ROM_BASE = 0x08000000
ROM_SHA1 = "5c4695205413df7db52b9a184815a07783999971"
CONDITIONS = dict(zip(("beq", "bne", "bcs", "bcc", "bmi", "bpl", "bvs", "bvc",
                       "bhi", "bls", "bge", "blt", "bgt", "ble"), range(14)))
MNEMONICS = set("adc add and asr bic cmn cmp eor ldmia ldr ldrb ldrh ldrsb ldrsh "
                "lsl lsr mov mul mvn neg nop orr pop push ror sbc stmia str strb "
                "strh sub tst b bl bx".split()) | set(CONDITIONS)
SYMBOL = r"(?:\.L[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_]*)"
TOKEN = re.compile(r"\s*(0[xX][0-9a-fA-F]+|[0-9]+|" + SYMBOL + r"|<<|>>|[()+\-|&*])")
FUNCTION = re.compile(r"\s*\.(thumb_func_start(?:_noalign)?|arm_func_start)\s+(Func_[0-9a-fA-F]+)\s*$")


class Excluded(ValueError):
    pass


def clean(line):
    return line.split("@", 1)[0].strip()


def sign(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def runtime_address(offset, source):
    if source == "rom_c0/src/rom_770.s" and 0x770 <= offset < 0x1b70:
        return 0x03000000 + offset - 0x770
    return ROM_BASE + offset


def expression_value(expression, lookup):
    """Whitelist tokens and AST nodes; never evaluate Python code."""
    position, tokens, symbols = 0, [], {}
    expression = expression.strip()
    if len(expression) > 2048:
        raise Excluded("expression too long")
    while position < len(expression):
        match = TOKEN.match(expression, position)
        if not match:
            raise Excluded("unsupported expression syntax: " + expression)
        token = match[1]
        if re.fullmatch(SYMBOL, token):
            key = "symbol_" + str(len(symbols))
            symbols[key] = token
            token = key
        tokens.append(token)
        position = match.end()
        if len(tokens) > 100:
            raise Excluded("expression too complex")
    try:
        tree = ast.parse(" ".join(tokens), mode="eval")
    except (SyntaxError, ValueError) as error:
        raise Excluded("invalid expression: " + expression) from error

    def visit(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            value = node.value
        elif isinstance(node, ast.Name) and node.id in symbols:
            value = lookup(symbols[node.id])
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            operand = visit(node.operand)
            value = operand if isinstance(node.op, ast.UAdd) else -operand
        elif isinstance(node, ast.BinOp):
            left, right = visit(node.left), visit(node.right)
            if isinstance(node.op, ast.Add):
                value = left + right
            elif isinstance(node.op, ast.Sub):
                value = left - right
            elif isinstance(node.op, ast.Mult):
                value = left * right
            elif isinstance(node.op, ast.BitOr):
                value = left | right
            elif isinstance(node.op, ast.BitAnd):
                value = left & right
            elif isinstance(node.op, (ast.LShift, ast.RShift)) and 0 <= right <= 63:
                value = left << right if isinstance(node.op, ast.LShift) else left >> right
            else:
                raise Excluded("unsupported expression operator: " + expression)
        else:
            raise Excluded("unsupported expression AST: " + expression)
        if value.bit_length() > 128:
            raise Excluded("expression exceeds arithmetic limit")
        return value

    return visit(tree.body)


class Symbols:
    def __init__(self, work, rom, aliases):
        self.work, self.rom, self.aliases = work, rom, aliases
        self.definitions, self.locals, self.constants = {}, {}, {}
        for relative in ("wram.sym", "include/gba.inc"):
            for number, raw in enumerate((work / "repo" / relative).read_text().splitlines(), 1):
                line = clean(raw)
                match = re.fullmatch(r"([A-Za-z_]\w*)\s*=\s*(.*?)\s*;", line)
                if not match:
                    match = re.fullmatch(r"\.set\s+([A-Za-z_]\w*)\s*,\s*(.+)", line)
                if match:
                    self.constants.setdefault(match[1], []).append(
                        dict(expression=match[2], source=relative, line=number))
        for path in sorted((work / "repo").glob("*/src/*.s")):
            relative = str(path.relative_to(work / "repo"))
            for number, raw in enumerate(path.read_text().splitlines(), 1):
                line = clean(raw)
                match = FUNCTION.fullmatch(line)
                if match:
                    self.definitions.setdefault(match[2], []).append(dict(
                        source=relative, line=number, kind="function",
                        mode="thumb" if match[1].startswith("thumb") else "arm"))
                else:
                    label = re.fullmatch(r"((?:Data_|Label_|Exports_)[0-9a-fA-F]+|\.L[0-9a-fA-F]+):", line)
                    incdata = re.match(r"\.incdata\s+((?:Data_|Label_)[0-9a-fA-F]+)\s*,", line)
                    if label or incdata:
                        name = (label or incdata)[1]
                        entry = dict(source=relative, line=number, kind="label")
                        table = self.locals if name.startswith(".") else self.definitions
                        table.setdefault((relative, name) if name.startswith(".") else name, []).append(entry)

    def resolve(self, name, source, evidence, visiting=()):
        if name in visiting:
            raise Excluded("cyclic symbol expression: " + name)
        if name in self.constants:
            rows = self.constants[name]
            if len(rows) != 1:
                raise Excluded("ambiguous constant: " + name)
            row = rows[0]
            value = expression_value(row["expression"], lambda symbol: self.resolve(
                symbol, source, evidence, visiting + (name,)))
            proof = dict(symbol=name, value=hex(value & 0xffffffff), kind="constant", **row)
        elif name in self.aliases:
            row = self.aliases[name]
            address = int(row["address"], 16)
            raw = bytes.fromhex(row["bytes"])
            if address % 4 or address < ROM_BASE or self.rom[address-ROM_BASE:address-ROM_BASE+len(raw)] != raw:
                raise Excluded("alias bytes no longer match ROM: " + name)
            if row.get("kind") == "thumb_call_via":
                register = row["register_number"]
                expected_name = "_call_via_" + (f"r{register}" if register < 13 else {13: "sp", 14: "lr"}.get(register, "invalid"))
                if not 0 <= register <= 14 or name != expected_name or len(raw) != 4 or struct.unpack("<HH", raw) != (0x4700 | register << 3, 0x46c0):
                    raise Excluded("invalid call_via encoding: " + name)
            else:
                register = int(row["register"][1:])
                if not 0 <= register <= 7 or len(raw) != 8 or struct.unpack("<HHI", raw) != (
                        0x4800 | register << 8, 0x4700 | register << 3, int(row["target_pointer"], 16)):
                    raise Excluded("invalid alias encoding: " + name)
            value = address | 1
            proof = dict(symbol=name, value=hex(value), kind="thumb_alias", alias=row)
        else:
            rows = self.locals.get((source, name), []) if name.startswith(".") else self.definitions.get(name, [])
            if len(rows) != 1:
                raise Excluded(("ambiguous" if rows else "unknown") + " symbol: " + name)
            row = rows[0]
            match = re.fullmatch(r"(?:Func_|Data_|Label_|Exports_|\.L)([0-9a-fA-F]+)", name)
            if not match:
                raise Excluded("symbol lacks demonstrated address convention: " + name)
            offset = int(match[1], 16)
            address = runtime_address(offset, row["source"])
            value = address | (1 if row.get("mode") == "thumb" else 0)
            proof = dict(symbol=name, value=hex(value), storage_address=hex(ROM_BASE+offset),
                         address_role="IWRAM runtime" if address < ROM_BASE else "ROM", **row)
            if name.startswith("Exports_"):
                # A table base is an even data address, although its first element is Thumb code.
                # Bind the suffix convention to the already ROM-verified first export stub.
                if row["source"] != f"rom_{match[1]}/src/exports.s":
                    raise Excluded("exports table source path mismatch: " + name)
                tail = [clean(s) for s in (self.work/"repo"/row["source"]).read_text().splitlines()[row["line"]:] if clean(s)]
                first = re.fullmatch(r"\.export_func\s+(Func_[0-9a-fA-F]+)",tail[0]) if tail else None
                if not first:
                    raise Excluded("exports label does not directly precede a verified stub")
                first_pointer = self.resolve("_"+first[1],source,evidence,visiting+(name,))
                if first_pointer != (address|1):
                    raise Excluded("exports table differs from verified first stub address")
                proof["kind"] = "exports_table"
                proof["first_stub"] = "_"+first[1]
        if proof not in evidence:
            evidence.append(proof)
        return value

    def expression(self, expression, source):
        evidence = []
        value = expression_value(expression, lambda name: self.resolve(name, source, evidence))
        return value & 0xffffffff, evidence


def branch_target(label, candidate, symbols):
    if label in candidate["labels"]:
        return int(candidate["labels"][label], 16)
    evidence = []
    pointer = symbols.resolve(label, candidate["source"], evidence)
    if not pointer & 1 or not any(e["kind"] in ("function", "thumb_alias") for e in evidence):
        raise Excluded("direct Thumb branch does not target a demonstrated Thumb entry: " + label)
    if label in symbols.aliases:
        candidate["alias_evidence"][label] = symbols.aliases[label]
    return pointer & ~1


def parse_function(work, row, boundary, rom, symbols):
    if len(row["definitions"]) != 1:
        raise Excluded("ambiguous function definition")
    definition = row["definitions"][0]
    source = definition["path"]
    lines = (work / "repo" / source).read_text().splitlines()
    header = FUNCTION.fullmatch(clean(lines[definition["line"]-1]))
    if not header or not header[1].startswith("thumb") or header[2] != row["name"]:
        raise Excluded("definition does not establish the requested Thumb entry")
    start = cursor = int(row["address"], 16)
    instructions, labels, loads = [], {}, []
    terminated = False
    for number in range(definition["line"], len(lines)):
        line = clean(lines[number])
        if not line:
            continue
        if line.startswith(".func_end"):
            if line.split() != [".func_end", row["name"]]:
                raise Excluded("mismatched function end")
            terminated = True
            break
        if re.fullmatch(SYMBOL + ":", line):
            name = line[:-1]
            if name in labels:
                raise Excluded("duplicate label: " + name)
            labels[name] = hex(cursor)
            continue
        if line.startswith("."):
            raise Excluded("internal directive or macro: " + line)
        if re.search(r"\b(?:pc|r15)\b", line):
            raise Excluded("explicit PC operation: " + line)
        mnemonic = line.split()[0]
        if mnemonic not in MNEMONICS:
            raise Excluded("instruction outside demonstrated Thumb-1 set: " + mnemonic)
        literal = re.fullmatch(r"ldr\s+(r[0-7])\s*,\s*=(.+)", line)
        if "=" in line and not literal:
            raise Excluded("unsupported pseudo-load: " + line)
        length = 4 if mnemonic == "bl" else 2
        if cursor + length > boundary:
            raise Excluded("source code exceeds next function boundary")
        raw = rom[cursor-ROM_BASE:cursor-ROM_BASE+length]
        if len(raw) != length:
            raise Excluded("instruction outside pinned ROM")
        opcode, = struct.unpack("<H", raw[:2])
        if opcode & 0xf800 == 0x4800 and not literal:
            raise Excluded("encoded literal LDR without supported pseudo-load declaration")
        instruction = dict(address=hex(cursor), length=length, source=line,
                           line=number+1, bytes=raw.hex())
        instructions.append(instruction)
        if literal:
            loads.append((instruction, literal[1], literal[2].strip()))
        cursor += length
    if not terminated:
        raise Excluded("no matching .func_end")
    if not loads:
        raise Excluded("no literal pseudo-load")
    candidate = dict(name=row["name"], address=row["address"], mode="thumb", source=source,
                     definition_line=definition["line"], next_boundary=hex(boundary),
                     code_end=hex(cursor-1), code_bytes=cursor-start, labels=labels,
                     instructions=instructions, branch_targets={}, alias_evidence={}, literals=[])
    for instruction, register, expression in loads:
        address = int(instruction["address"], 16)
        opcode, = struct.unpack("<H", bytes.fromhex(instruction["bytes"]))
        if opcode & 0xf800 != 0x4800 or (opcode >> 8) & 7 != int(register[1:]):
            raise Excluded("pseudo-load is not the expected literal LDR (possibly optimized): " + instruction["address"])
        slot = ((address + 4) & ~3) + 4 * (opcode & 0xff)
        if slot % 4 or slot < cursor or slot + 4 > boundary or slot + 4 > ROM_BASE + len(rom):
            raise Excluded("literal word is not wholly in the trailing pool: " + hex(slot))
        value, evidence = symbols.expression(expression, source)
        actual, = struct.unpack_from("<I", rom, slot-ROM_BASE)
        if actual != value:
            raise Excluded("literal expression/ROM mismatch at " + hex(slot) +
                           ": " + expression + " resolves to " + hex(value) + ", ROM=" + hex(actual))
        candidate["literals"].append(dict(instruction=instruction["address"], address=hex(slot),
            size=4, value=hex(value), expression=expression, register=register,
            source_line=instruction["line"], symbol_evidence=evidence))
        for entry in evidence:
            if entry["kind"] == "thumb_alias":
                candidate["alias_evidence"][entry["symbol"]] = entry["alias"]
    validate_flow(candidate, symbols)
    return candidate


def validate_flow(candidate, symbols):
    instructions = candidate["instructions"]
    by_address = {int(i["address"], 16): n for n, i in enumerate(instructions)}
    edges = {}
    for number, ins in enumerate(instructions):
        statement = ins["source"]
        mnemonic = statement.split()[0]
        address = int(ins["address"], 16)
        raw = bytes.fromhex(ins["bytes"])
        opcode, = struct.unpack("<H", raw[:2])
        successors = []
        if mnemonic == "bx":
            register = statement.split()[-1]
            register_number = 14 if register == "lr" else int(register[1:]) if re.fullmatch(r"r[0-9]+", register) else -1
            previous = instructions[number-1]["source"] if number else ""
            if register != "lr" and not re.fullmatch(r"pop\s+\{"+re.escape(register)+r"\}", previous):
                raise Excluded("computed branch without a simple source return: " + statement)
            if not 0 <= register_number <= 14 or opcode != 0x4700 | register_number << 3:
                raise Excluded("BX opcode/register mismatch")
        elif mnemonic == "bl" or mnemonic == "b" or mnemonic in CONDITIONS:
            label = statement.split()[-1]
            target = branch_target(label, candidate, symbols)
            if mnemonic == "bl":
                second, = struct.unpack("<H", raw[2:])
                if opcode & 0xf800 != 0xf000 or second & 0xf800 != 0xf800:
                    raise Excluded("BL opcode mismatch")
                decoded = address + 4 + sign(((opcode & 0x7ff) << 12) | ((second & 0x7ff) << 1), 23)
            elif mnemonic == "b":
                if opcode & 0xf800 != 0xe000:
                    raise Excluded("B opcode mismatch")
                decoded = address + 4 + sign((opcode & 0x7ff) << 1, 12)
            else:
                if opcode >> 8 != 0xd0 | CONDITIONS[mnemonic]:
                    raise Excluded("conditional branch opcode mismatch")
                decoded = address + 4 + sign((opcode & 0xff) << 1, 9)
            if decoded != target:
                raise Excluded("source branch/ROM mismatch at " + ins["address"])
            candidate["branch_targets"][ins["address"]] = hex(target)
            if mnemonic != "bl":
                if target in by_address:
                    successors.append(by_address[target])
                elif label in candidate["labels"]:
                    raise Excluded("branch reaches a non-instruction local label: " + label)
            if mnemonic != "b":
                successors.append(number+1)
        else:
            successors.append(number+1)
        if any(n >= len(instructions) for n in successors):
            raise Excluded("fallthrough enters trailing pool")
        edges[number] = successors
    reachable, pending = set(), [0]
    while pending:
        number = pending.pop()
        if number not in reachable:
            reachable.add(number)
            pending.extend(edges[number])
    if len(reachable) != len(instructions):
        missing = next(i["address"] for n, i in enumerate(instructions) if n not in reachable)
        raise Excluded("source instruction unreachable in syntactic CFG: " + missing)
    candidate["cfg_evidence"] = dict(all_instructions_reachable=True,
        returning_calls_assumed=True, return_recognition="bx lr or adjacent pop same register / bx register; source pattern only")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--aliases", type=Path)
    parser.add_argument("--names", nargs="+", help="require exactly these named candidates")
    parser.add_argument("--max-code-bytes", type=int, help="exclude source code larger than this limit")
    args = parser.parse_args()
    if args.max_code_bytes is not None and args.max_code_bytes <= 0:
        parser.error("--max-code-bytes must be positive")
    work = Path(__file__).resolve().parents[1] / "work"
    rom = (work / "rom/Golden Sun (USA, Europe).gba").read_bytes()
    if hashlib.sha1(rom).hexdigest() != ROM_SHA1:
        raise ValueError("unexpected ROM SHA1")
    baseline = json.loads(args.baseline.read_text())
    existing = set(baseline.get("function_entries", baseline.get("functions", {})))
    aliases = json.loads(args.aliases.read_text())["aliases"] if args.aliases else {}
    symbols = Symbols(work, rom, aliases)
    boundaries = sorted(int(line.split()[0], 16) for line in
        (work / "repo_function_boundaries.tsv").read_text().splitlines() if line.strip() and not line.startswith("#"))
    following = dict(zip(boundaries, boundaries[1:]))
    targets, skipped = [], []
    rows = json.loads((work / "remaining_reference.json").read_text())["entries"]
    for row in rows:
        if row["address"] in existing or row["category"] != "undefined_executable" or "runtime_address" in row or row["mode"] != "thumb":
            continue
        if args.names and row["name"] not in args.names:
            continue
        try:
            if int(row["address"], 16) not in following:
                raise Excluded("missing next reference boundary")
            candidate = parse_function(work, row, following[int(row["address"], 16)], rom, symbols)
            if args.max_code_bytes is not None and candidate["code_bytes"] > args.max_code_bytes:
                raise Excluded("exceeds approved maximum code size")
            targets.append(candidate)
        except Excluded as error:
            skipped.append(dict(name=row["name"], address=row["address"], reason=str(error)))
    targets.sort(key=lambda row: int(row["address"], 16))
    sources = [work / "repo" / p for p in ("wram.sym", "include/gba.inc", "include/macros.inc", "stage1.ld", "goldensun.ld")]
    sources += [args.baseline, work / "remaining_reference.json", work / "repo_function_boundaries.tsv"]
    sources += [work / "repo" / name for name in sorted({row["source"] for row in targets})]
    if args.aliases:
        sources.append(args.aliases)
    provenance = dict(rom_sha1=ROM_SHA1,
        source_sha256={str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
        address_convention="hexadecimal source symbol suffix; rom_c0/src/rom_770.s storage 770..1b70 remapped to 03000000",
        literal_value_format="uint32 hexadecimal; expression arithmetic reduced modulo 2**32 after evaluation",
        exclusions="internal directives/macros, unknown symbols, optimized pseudo-loads, nonliteral loads, unresolved/computed branches, unreachable source instructions")
    result = dict(baseline=str(args.baseline), targets=targets, skipped=skipped, provenance=provenance)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "plan.json").write_text(json.dumps(result, indent=2)+"\n")
    (args.output / "targets.tsv").write_text("".join(f'{row["address"]}\t{row["name"]}\n' for row in targets))
    stats = dict(selected=len(targets), skipped=len(skipped), source_code_bytes=sum(row["code_bytes"] for row in targets),
                 instructions=sum(len(row["instructions"]) for row in targets),
                 literal_loads=sum(len(row["literals"]) for row in targets),
                 unique_pool_words=len({literal["address"] for row in targets for literal in row["literals"]}))
    (args.output / "summary.json").write_text(json.dumps(stats, indent=2)+"\n")
    print(json.dumps(stats))
    if args.names:
        absent = set(args.names) - {row["name"] for row in targets}
        if absent:
            raise ValueError("requested candidates excluded or unavailable: " + str(sorted(absent)) +
                             "; see plan.json skipped entries")


if __name__ == "__main__":
    main()
