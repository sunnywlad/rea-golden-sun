#!/usr/bin/env python3
"""Compare pinned Alchemy sprite metadata/scripts with a private GS1 EN ROM.

Outputs counts, hashes and mismatches, never ROM payloads. Does not build either
reference, execute the game, or open Ghidra. Run from the project root.
"""
import csv
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    output = Path(sys.argv[1])
    rom = (root / "work/rom/Golden Sun (USA, Europe).gba").read_bytes()
    expected_sha1 = "5c4695205413df7db52b9a184815a07783999971"
    actual_sha1 = hashlib.sha1(rom).hexdigest()
    if actual_sha1 != expected_sha1:
        raise ValueError("ROM does not match the pinned GS1 English SHA1")
    repositories = {}
    for name, expected in (
        ("alchemy", "1517ff0750d988f570b6efcd06bf30d0f64c9d2a"),
        ("game-tools-collection", "ea0efd9b161fd39308e61ce180d409c7b11613cf"),
    ):
        repo = root / "external" / name
        commit = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
        ).strip()
        if commit != expected:
            raise ValueError(f"Unexpected revision for {name}: {commit}")
        if subprocess.check_output(
            ["git", "-C", str(repo), "status", "--porcelain"], text=True
        ).strip():
            raise ValueError(f"Reference working tree has changes: {name}")
        repositories[name] = commit

    inputs = {}

    def read_source(path):
        content = path.read_bytes()
        inputs[str(path.relative_to(root))] = hashlib.sha256(content).hexdigest()
        return content.decode()

    def read_rom(offset, size):
        if offset < 0 or offset + size > len(rom):
            raise ValueError(f"ROM range out of bounds: {offset:#x}, {size}")
        return rom[offset:offset + size]

    def dereference(offset):
        address = struct.unpack("<I", read_rom(offset, 4))[0]
        if not 0x08000000 <= address < 0x08000000 + len(rom):
            raise ValueError(f"Non-ROM pointer at {offset:#x}: {address:#x}")
        return address - 0x08000000

    for relative in (
        "external/alchemy/tools/ags-graphics/sprite.c",
        "external/alchemy/games/tbs/src/system/resource/metadata_get_record.c",
        "external/alchemy/games/common/include/system/metadata_lookup.h",
        "external/alchemy/games/common/include/field/animspr.h",
        "external/alchemy/games/tbs/src/field/field.c",
        "external/alchemy/games/tbs/src/graphics/render/decode.s",
        "external/game-tools-collection/src/lib/utils/parser.ts",
        "external/game-tools-collection/src/lib/utils/bytes.ts",
        "external/game-tools-collection/src/lib/utils/prototype.ts",
        "external/game-tools-collection/src/lib/templates/golden-sun/romEditor/template.ts",
    ):
        read_source(root / relative)

    table_offset = dereference(0x185020)
    if table_offset != 0x185024:
        raise ValueError("Unexpected getter table base")
    directory = root / "external/alchemy/games/tbs/src/graphics/sprite"
    rows = list(csv.DictReader(read_source(directory / "sprites.tsv").splitlines(),
                               delimiter="\t"))
    if len(rows) != 512:
        raise ValueError("Expected 512 metadata rows")
    fields = {
        "width": (0, "<B"), "height": (1, "<B"), "scale": (2, "<H"),
        "draw": (4, "<B"), "adjust_x": (6, "<b"), "adjust_y": (7, "<b"),
        "box_x": (8, "<B"), "box_y": (9, "<B"), "codec": (10, "<B"),
    }
    failures = []
    counts = {"records": len(rows), "scalar_fields_compared": 0,
              "animation_counts_compared": 0, "animation_slots_compared": 0,
              "animation_bytes_compared_with_repetition": 0,
              "null_pointer_checks": 0, "selectable_records": 0,
              "pointer_nullness_checks": 0,
              "nonzero_padding_byte11": 0}
    unique_scripts = set()
    for index, row in enumerate(rows):
        if row["sprite"] != f"SPR_{index:03d}":
            raise ValueError("Unexpected sprite row ordering")
        record_offset = table_offset + index * 20
        record = read_rom(record_offset, 20)
        counts["selectable_records"] += bool(record[0])
        counts["nonzero_padding_byte11"] += bool(record[11])
        for field, (offset, fmt) in fields.items():
            expected = int(row[field], 0)
            actual = struct.unpack_from(fmt, record, offset)[0]
            counts["scalar_fields_compared"] += 1
            if actual != expected:
                failures.append({"sprite": index, "field": field,
                                 "expected": expected, "actual": actual})

        for column, offset in (("frames", 12), ("animations", 16)):
            counts["pointer_nullness_checks"] += 1
            actual_null = struct.unpack_from("<I", record, offset)[0] == 0
            if actual_null != (row[column] == "-"):
                failures.append({"sprite": index, "field": column,
                                 "error": "pointer nullness differs"})
            if row[column] == "-":
                counts["null_pointer_checks"] += 1

        scripts = []
        if row["animations"] != "-":
            owner, separator, limit = row["animations"].partition(":")
            source = directory / (owner.lower() + ".tsv")
            aliases = None
            for line in read_source(source).splitlines():
                if not line.strip():
                    continue
                kind, value = line.split("\t", 1)
                if kind == "anim":
                    scripts.append(bytes.fromhex(value))
                elif kind == "animations":
                    if aliases is not None:
                        raise ValueError("Multiple animation index rows")
                    aliases = [int(token) for token in value.split()]
                elif kind not in ("list", "empty"):
                    raise ValueError(f"Unhandled TSV directive: {kind}")
            if aliases is not None:
                scripts = [scripts[alias] for alias in aliases]
            # sprite.c readBank/records: OWNER:N limits the animation count,
            # without advancing the pointer into the owner's animation table.
            if separator:
                scripts = scripts[:int(limit)]
        counts["animation_counts_compared"] += 1
        if len(scripts) != record[5]:
            failures.append({"sprite": index, "field": "animationCount",
                             "expected": len(scripts), "actual": record[5]})
            continue
        if not scripts:
            continue
        pointers = dereference(record_offset + 16)
        for slot, expected in enumerate(scripts):
            offset = dereference(pointers + slot * 4)
            actual = read_rom(offset, len(expected))
            counts["animation_slots_compared"] += 1
            counts["animation_bytes_compared_with_repetition"] += len(expected)
            unique_scripts.add((offset, len(expected)))
            if actual != expected:
                failures.append({"sprite": index, "animation": slot,
                                 "error": "script bytes differ"})
    counts["distinct_script_address_length_pairs"] = len(unique_scripts)
    result = {"rom_sha1": actual_sha1, "repositories": repositories,
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "table_pointer_location_file": "0x185020",
              "table_offset_file": hex(table_offset), "record_stride": 20,
              "counts": counts, "failures": failures,
              "source_sha256": inputs,
              "limits": ["No external build or C byte matching performed",
                         "Frame payloads and relocated pointer values not rebuilt",
                         "Comparison checks source bytes, not script semantics",
                         "No Ghidra or emulator execution"]}
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"counts": counts, "failures": len(failures)}))
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
