#!/usr/bin/env python3
"""Audit source definitions/references and ROM-vs-IWRAM address roles for missing entries."""
import argparse
import json
import re
from collections import Counter
from pathlib import Path

ROM_BASE = 0x08000000
IWRAM_BASE = 0x03000000
IWRAM_LMA_START = 0x770
IWRAM_LMA_END = 0x1B70
IWRAM_COPY_SIZE = IWRAM_LMA_END - IWRAM_LMA_START
START = re.compile(r"^\s*\.(arm_func_start|thumb_func_start(?:_noalign)?)\s+(\S+)")
SYMBOL_LINE = re.compile(r"(?<![A-Za-z0-9_])(?:%s)(?![A-Za-z0-9_])")

# These four Ghidra units are undefined2 data at Thumb entries. Record exact
# first-instruction encodings so a later cleanup can be limited to proven units.
DATA_PROBES = {
    "Func_6abc": {"instruction": "ldrb r0, [r0]", "bytes": "0078",
                  "copy": "Func_6ac0", "copy_lines": "rom_c0/src/rom_6878.s:264-285",
                  "halfword_read": "rom_c0/src/rom_6878.s:276",
                  "notes": "clears Thumb bit, copies halfwords from entry; parameter r2 is the destination"},
    "Func_6b84": {"instruction": "push {r4, lr}", "bytes": "10b5",
                  "copy": "Func_6ba8", "copy_lines": "rom_c0/src/rom_6878.s:396-418",
                  "halfword_read": "rom_c0/src/rom_6878.s:409",
                  "notes": "copies entry-to-Func_6ba8 code to stack, then calls copied code via r3 at line 431"},
    "Func_6c24": {"instruction": "push {r4, r5, lr}", "bytes": "30b5",
                  "copy": "Func_6c68", "copy_lines": "rom_c0/src/rom_6878.s:489-511",
                  "halfword_read": "rom_c0/src/rom_6878.s:502",
                  "notes": "copies entry-to-Func_6c68 code to stack, then calls copied code via r3 at line 523"},
    "Func_6f48": {"instruction": "mov r2, r0", "bytes": "021c",
                  "copy": "Func_6e24", "copy_lines": "rom_c0/src/rom_6878.s:694-715",
                  "halfword_read": "rom_c0/src/rom_6878.s:706",
                  "notes": "copies entry-to-Func_6f6c code to stack; Func_6f6c calls copied code via r1 at line 838"},
}


def load_entries(path):
    data = json.loads(Path(path).read_text())
    if "function_entries" in data:
        return {int(x, 16) for x in data["function_entries"]}
    state = data.get("state", {})
    if "function_entries" in state:
        return {int(x, 16) for x in state["function_entries"]}
    raise ValueError("input JSON has no function_entries array")


def source_index(repo, names):
    index = {name: {"definitions": [], "reference_paths": []} for name in names}
    symbols = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
    pattern = re.compile(SYMBOL_LINE.pattern % symbols)
    for path in sorted(Path(repo).rglob("*")):
        if path.suffix not in (".s", ".c", ".h") or "overlays" in path.parts:
            continue
        relative = str(path.relative_to(repo))
        for line_no, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            for match in pattern.finditer(line):
                name = match.group()
                item = {"path": relative, "line": line_no}
                start = START.match(line)
                if start and start.group(2) == name:
                    index[name]["definitions"].append(item)
                else:
                    index[name]["reference_paths"].append(item)
    return index


def read_repo_functions(path):
    functions = []
    for raw in Path(path).read_text().splitlines():
        match = re.fullmatch(r"(thumb|arm) Func_([0-9a-fA-F]+)", raw.strip())
        if match:
            mode, offset_text = match.groups()
            offset = int(offset_text, 16)
            functions.append({"mode": mode, "offset": offset,
                              "address": ROM_BASE + offset,
                              "name": "Func_" + offset_text.lower()})
    return functions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_funcs")
    parser.add_argument("entry_json", help="shared_verified/before.json or remaining_inventory.json")
    parser.add_argument("repo_dir")
    parser.add_argument("out_json")
    parser.add_argument("--runtime-inventory", help="optional inventory of derived IWRAM VMAs")
    args = parser.parse_args()

    inventory = json.loads(Path(args.entry_json).read_text())
    entries = load_entries(args.entry_json)
    runtime_inventory = (json.loads(Path(args.runtime_inventory).read_text())
                         if args.runtime_inventory else {})
    runtime_entries = load_entries(args.runtime_inventory) if args.runtime_inventory else entries
    runtime_targets = {r.get("repo_name"): r for r in runtime_inventory.get("targets", [])}
    missing = [f for f in read_repo_functions(args.repo_funcs) if f["address"] not in entries]
    src = source_index(args.repo_dir, {f["name"] for f in missing})

    targets = {row.get("repo_name"): row for row in inventory.get("targets", [])}
    rows = []
    for function in missing:
        name = function["name"]
        source = src[name]
        definition_paths = {d["path"] for d in source["definitions"]}
        copied = ("rom_c0/src/rom_770.s" in definition_paths and
                  IWRAM_LMA_START <= function["offset"] < IWRAM_LMA_END)
        target = targets.get(name, {})
        row = {"mode": function["mode"], "address": hex(function["address"]),
               "name": name, "category": target.get("category"),
               "tmode": target.get("tmode"),
               "inventory_evidence": {key: target.get(key) for key in
                   ("exact_function", "containing_function", "instruction_at",
                    "instruction_containing", "defined_data_at", "defined_data_containing",
                    "references_even", "references_odd", "entry_bytes") if key in target},
               **source}
        if copied:
            runtime = IWRAM_BASE + function["offset"] - IWRAM_LMA_START
            row.update({"address_role": "ROM load/storage address; linked runtime address is IWRAM",
                        "runtime_address": hex(runtime),
                        "runtime_function_entry_listed": runtime in runtime_entries,
                        "runtime_probe": runtime_targets.get(name),
                        "evidence": {"linker": "goldensun.ld:28-32; stage1.ld:26-28",
                                     "copy": "rom_c0/src/rom_2e00.s:241-246",
                                     "copy_bytes": hex(IWRAM_COPY_SIZE),
                                     "destination": "wram.sym:134 (iwram_0=0x03000000)",
                                     "source": "rom_c0/src/rom_770.s"}})
        else:
            row["address_role"] = "normal ROM-linked entry; no rom_770 VMA/LMA remap evidenced"

        if name in DATA_PROBES:
            probe = DATA_PROBES[name]
            expected_instruction, expected_hex = probe["instruction"], probe["bytes"]
            definition = next((d for d in source["definitions"]
                               if d["path"] == "rom_c0/src/rom_6878.s"), None)
            source_lines = (Path(args.repo_dir) / definition["path"]).read_text().splitlines() if definition else []
            first = ""
            first_line = None
            if definition:
                for line_no in range(definition["line"], len(source_lines)):
                    line = source_lines[line_no].split("@", 1)[0].strip()
                    if line.startswith(".thumb_func_start") or line.startswith(".arm_func_start"):
                        continue
                    if line and not line.startswith((".", "@")):
                        first = re.sub(r"\s+", " ", line)
                        first_line = line_no + 1
                        break
            entry_bytes = target.get("entry_bytes", {}).get("hex", "")
            actual_hex = entry_bytes[:4].lower()
            row["reference_warning"] = {
                "ghidra_unit": target.get("defined_data_at"),
                "source_path": definition["path"] if definition else None,
                "source_line": first_line,
                "source_instruction": first,
                "expected_instruction": expected_instruction,
                "expected_first_bytes": expected_hex,
                "inventory_first_bytes": actual_hex,
                "confirmed": first == expected_instruction and actual_hex == expected_hex,
                "also_code_as_data": True,
                "code_copy_evidence": {k: probe[k] for k in
                    ("copy", "copy_lines", "halfword_read", "notes")},
                "action": "preserve dual code/data semantics; only clear this exact code unit in a later recovery after rechecking the saved project",
            }
        rows.append(row)

    categories = Counter(t.get("category", "not_in_inventory") for t in inventory.get("targets", []))
    category_mode = Counter(f"{t.get('category', 'unknown')}/{t.get('mode', 'unknown')}"
                            for t in inventory.get("targets", []))
    inventory_targets = inventory.get("targets", [])
    relocated = [r for r in rows if "runtime_address" in r]
    result = {
        "inputs": {"repo_funcs": args.repo_funcs, "entry_json": args.entry_json,
                   "repo_dir": args.repo_dir, "runtime_inventory": args.runtime_inventory},
        "counts": {"missing": len(rows), "mode": dict(Counter(r["mode"] for r in rows)),
                   "inventory_categories": dict(categories),
                   "inventory_category_modes": dict(category_mode),
                   "even_reference_occurrences": sum(len(t.get("references_even", [])) for t in inventory_targets),
                   "odd_reference_occurrences": sum(len(t.get("references_odd", [])) for t in inventory_targets),
                   "targets_with_even_references": sum(bool(t.get("references_even")) for t in inventory_targets),
                   "targets_with_odd_references": sum(bool(t.get("references_odd")) for t in inventory_targets),
                   "targets_with_no_function_owner": sum(not t.get("exact_function") and not t.get("containing_function") for t in inventory_targets),
                   "targets_with_instruction_at_entry": sum(bool(t.get("instruction_at")) for t in inventory_targets),
                   "targets_mid_instruction": sum(
                       bool(t.get("instruction_containing")) and
                       int(t["instruction_containing"]["start"], 16) < int(t["address"], 16) <
                       int(t["instruction_containing"]["end"], 16) + 1 for t in inventory_targets),
                   "remaining_thumb_in_rom_770": sum(r["mode"] == "thumb" and
                       IWRAM_LMA_START <= int(r["address"], 16) - ROM_BASE < IWRAM_LMA_END and
                       "rom_c0/src/rom_770.s" in {d["path"] for d in r["definitions"]}
                       for r in rows),
                   "arm_rom_storage_offsets": sum(r["mode"] == "arm" and "runtime_address" in r for r in rows),
                   "thumb_rom_storage_offsets": sum(r["mode"] == "thumb" and "runtime_address" in r for r in rows),
                   "arm_runtime_function_entry_listed": sum(r["mode"] == "arm" and r["runtime_function_entry_listed"] for r in relocated),
                   "thumb_runtime_function_entry_listed": sum(r["mode"] == "thumb" and r["runtime_function_entry_listed"] for r in relocated),
                   "runtime_probes_non_executable_memory": sum(
                       (r.get("runtime_probe") or {}).get("category") == "non_executable_memory" for r in relocated),
                   "runtime_probes_exact_function": sum(
                       (r.get("runtime_probe") or {}).get("category") == "exact_function" for r in relocated),
                   "defined_data_probes": sum("reference_warning" in r for r in rows),
                   "defined_data_probes_confirmed": sum(r.get("reference_warning", {}).get("confirmed", False) for r in rows)},
        "linkage": {"rom_770_lma": "0x08000770", "rom_770_vma": "0x03000000",
                    "copy_size": hex(IWRAM_COPY_SIZE), "formula": "0x03000000 + (rom_offset - 0x770)"},
        "entries": rows,
    }
    out = Path(args.out_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["counts"], indent=2))


if __name__ == "__main__":
    main()
