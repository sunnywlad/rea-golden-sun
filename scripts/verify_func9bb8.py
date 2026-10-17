"""Verify saved CFG artifacts against assembly source and ROM, without opening Ghidra."""
import hashlib
import json
from pathlib import Path
import re
import struct


def verify(root):
    work = root / "work"

    def read(folder, name):
        return json.loads((work / folder / name).read_text())

    # Derive instruction addresses and table entries from the reference, independently
    # of the ranges hard-coded in the Ghidra recovery script.
    source = work / "repo/rom_9000/src/rom_92b8.s"
    active = False
    cursor = 0x08009BB8
    labels, instructions, table_expr = {}, {}, []
    for line in source.read_text().splitlines():
        line = line.split("@", 1)[0].strip()
        if line == ".arm_func_start Func_9bb8":
            active = True
            continue
        if not active or not line or line.startswith(".global"):
            continue
        if line.startswith(".func_end"):
            break
        if line.endswith(":"):
            labels[line[:-1]] = cursor
        elif line.startswith(".2byte"):
            table_expr.append((cursor, line.split(None, 1)[1]))
            cursor += 2
        elif line.startswith(".word"):
            cursor += 4
        elif line.startswith(".space"):
            cursor += int(line.split()[1], 0)
        elif line.startswith(".ssize"):
            pass
        else:
            if line.startswith("."):
                raise ValueError(f"unhandled directive: {line}")
            instructions[cursor] = line
            cursor += 4
    assert cursor == 0x08009E7C
    assert labels[".L9cdc"] == 0x08009CDC
    rom = (work / "rom/Golden Sun (USA, Europe).gba").read_bytes()
    assert hashlib.sha1(rom).hexdigest() == "5c4695205413df7db52b9a184815a07783999971"
    expected_cases = []
    for slot, expression in table_expr:
        match = re.fullmatch(r"(\.L\w+)\s*-\s*(\.L\w+)\s*-\s*4", expression)
        assert match, expression
        target, base = (labels[label] for label in match.groups())
        offset = struct.unpack_from("<h", rom, slot - 0x08000000)[0]
        assert offset == target - base - 4
        assert base + 4 + offset == target
        expected_cases.append(hex(target))
    assert len(expected_cases) == 16
    # The NOP between the computed branch and its first target is unreachable.
    expected_code = {a for a, ins in instructions.items() if ins != "nop"}

    initial = read("func9bb8_repair", "before.json")
    repaired = read("func9bb8_repair", "after.json")
    repeat_before = read("func9bb8_repeat", "before.json")
    repeat_after = read("func9bb8_repeat", "after.json")
    persisted = read("func9bb8_final", "after.json")
    baseline = read("decoded_recovery", "after.json")
    assert initial["function_count"] == persisted["function_count"] == 2164
    original_others = [dict(entry=f["entry"], name=f["name"], body=f["body_ranges"])
                       for f in baseline["functions"] if int(f["entry"], 16) != 0x08009BB8]
    assert initial["other_functions"] == original_others
    for state in (initial, repaired, repeat_before, repeat_after, persisted):
        for key in ("memory", "other_functions", "preserved_units", "tmode"):
            assert state[key] == initial[key], key
        for block in state["memory"]:
            key = f'{block["name"]}@{block["start"]}..{block["end"]}'
            assert block["sha256"] == baseline["initialized_memory_sha256"][key]
    assert repeat_after == persisted, "state changed across final close/reopen"
    for key in repeat_before:
        if key != "annotations":  # second run corrects one caller's name in the plate comment
            assert repeat_before[key] == repeat_after[key], key
    for state in (repaired, repeat_after, persisted):
        actual = {int(i["at"], 16) for i in state["instructions"]}
        # Unreachable NOP bytes are preserved without forcing them into instructions.
        assert actual == expected_code
        body = set()
        for r in state["body"]:
            body.update(range(int(r["start"], 16), int(r["end"], 16) + 1))
        expected_bytes = {a + k for a in expected_code for k in range(4)}
        assert body == expected_bytes and len(body) == state["body_bytes"] == 432
    original_ins = {i["at"]: i for i in initial["instructions"]}
    final_ins = {i["at"]: i for i in persisted["instructions"]}
    changed = [a for a, i in original_ins.items() if i != final_ins[a]]
    assert changed == ["0x8009cd8"]
    for key, value in original_ins[changed[0]].items():
        if key not in ("flows", "references"):
            assert final_ins[changed[0]][key] == value
    jumps = [r for r in final_ins[changed[0]]["references"] if r["type"] == "COMPUTED_JUMP"]
    assert {r["to"] for r in jumps} == set(expected_cases) and len(jumps) == 7
    final_decomp = read("func9bb8_final", "after_decompile.json")
    dispatch = {t["branch"]: t for t in final_decomp["jump_tables"]}
    assert final_decomp["completed"]
    assert dispatch["0x8009cd8"]["cases"] == expected_cases
    assert dispatch["0x8009cd8"]["labels"] == list(range(16))
    assert dispatch["0x8009bd0"]["labels"] == list(range(4))
    assert (work / "func9bb8_repeat/after.c").read_bytes() == (work / "func9bb8_final/after.c").read_bytes()
    result = dict(
        verified=True, function_count=2164, previous_body_bytes=220, body_bytes=432,
        instruction_count=len(expected_code), added_instruction_count=len(expected_code)-len(original_ins),
        jump_table_case_count=16, unique_jump_targets=7,
        changed_preexisting_instructions=changed, memory_matches_step13=True,
        other_functions_match_step13=True, data_units_and_tmode_preserved=True,
        reopened_state_identical=True, repeat_structurally_idempotent=True,
        annotation_correction="Func_c004 family -> Func_c62c on second run",
        caveats=["guided recovery", "C dispatch validated only for inputs 0..15",
                 "ROM storage CFG; runtime RAM instance not reconstructed or executed",
                 "manual switch override and overlapping globals warnings remain"],
    )
    destination = work / "func9bb8_final/verification.json"
    destination.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    verify(Path(__file__).resolve().parents[1])
