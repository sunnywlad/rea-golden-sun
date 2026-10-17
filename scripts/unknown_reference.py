#!/usr/bin/env python3
"""Cross-reference unresolved positive pointer targets with repo assembly labels."""
import argparse
import hashlib
import json
import re
import struct
from collections import Counter, defaultdict
from pathlib import Path

BASE = 0x08000000
LABEL = re.compile(r"^\s*([.$A-Za-z_][.$A-Za-z0-9_]*)\s*:")
OFFSET = re.compile(r"^(?:\.L|Func_|Data_|L)([0-9a-f]{3,8})(?:_|$)", re.I)
START = re.compile(r"^\s*\.(thumb_func_start(?:_noalign)?|arm_func_start)\s+(\S+)")
DATA_DIR = re.compile(r"^\s*\.(incrom|incdata)\s+(.*)")
DIRECTIVE = re.compile(r"^\s*\.(byte|hword|2byte|short|word|4byte|space)\s+(.*)")


def encoded_offset(name):
    match = OFFSET.match(name)
    return int(match.group(1), 16) if match else None


def integer(text):
    try:
        return int(text.strip(), 0)
    except ValueError:
        return None


def add_symbol(index, offset, kind, path, line, section, symbol):
    if offset is None:
        return
    category = "function_entry" if kind == "function" else (
        "data" if section.startswith((".rodata", ".data")) else "internal_code")
    index[BASE + offset].append({
        "classification": category, "path": str(path), "line": line,
        "section": section, "symbol": symbol,
    })


def collect(repo):
    index = defaultdict(list)
    ranges = []
    for path in sorted(Path(repo).rglob("*.s")):
        if "overlays" in path.parts:
            continue
        section = ".text"
        current_data = None
        for lineno, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
            line = raw.split("@", 1)[0].strip()
            section_match = re.match(r"\.section\s+([^,\s]+)", line)
            if section_match:
                section = section_match.group(1)
                current_data = None

            start_match = START.match(line)
            if start_match:
                symbol = start_match.group(2).strip()
                add_symbol(index, encoded_offset(symbol), "function", path, lineno, section, symbol)

            if line.startswith(".thumb_stub "):
                symbol = line.split(None, 1)[1].split(",", 1)[0].strip()
                add_symbol(index, encoded_offset(symbol), "function", path, lineno, section, symbol)

            label_match = LABEL.match(line)
            if label_match:
                label = label_match.group(1)
                off = encoded_offset(label)
                if off is not None:
                    add_symbol(index, off, "label", path, lineno, section, label)
                    if section.startswith((".rodata", ".data")):
                        current_data = off

            data_match = DATA_DIR.match(line)
            if data_match and section.startswith((".rodata", ".data")):
                kind, args = data_match.groups()
                fields = [x.strip() for x in args.split(",")]
                if kind == "incrom" and len(fields) >= 2:
                    begin, end = integer(fields[0]), integer(fields[1])
                elif kind == "incdata" and len(fields) >= 3:
                    begin, end = integer(fields[1]), integer(fields[2])
                else:
                    begin = end = None
                if begin is not None and end is not None and end > begin:
                    ranges.append({"start": begin, "end": end, "path": str(path),
                                   "line": lineno, "kind": kind, "section": section})
                    current_data = end
                continue

            directive = DIRECTIVE.match(line)
            if directive and current_data is not None and section.startswith((".rodata", ".data")):
                kind, args = directive.groups()
                width = {"byte": 1, "hword": 2, "2byte": 2, "short": 2,
                         "word": 4, "4byte": 4}.get(kind)
                if kind == "space":
                    size = integer(args)
                    if size is not None:
                        if current_data <= 0xFFFFFFFF:
                            ranges.append({"start": current_data, "end": current_data + size,
                                           "path": str(path), "line": lineno,
                                           "kind": "space", "section": section})
                            current_data += size
                    continue
                if width:
                    count = len([x for x in args.split(",") if x.strip()])
                    if count:
                        ranges.append({"start": current_data, "end": current_data + width * count,
                                       "path": str(path), "line": lineno,
                                       "kind": kind, "section": section})
                        current_data += width * count

    return index, ranges


def string_ranges(repo, rom_path):
    """Rebuild the generated string block layout from unpack_strings.c and ROM tables."""
    tool = Path(repo) / "tools/unpack_strings.c"
    source = tool.read_text()
    constants = {name: int(value, 0) for name, value in re.findall(
        r"^#define\s+(HUFFMAN_OFFSET|DATA_OFFSET|NUM_STRINGS)\s+(0x[0-9a-fA-F]+|[0-9]+)",
        source, re.M)}
    if set(constants) != {"HUFFMAN_OFFSET", "DATA_OFFSET", "NUM_STRINGS"}:
        raise ValueError(f"could not read string layout constants from {tool}")
    rom = Path(rom_path).read_bytes()
    ranges = []
    nfiles = (constants["NUM_STRINGS"] + 255) // 256
    table = constants["DATA_OFFSET"]
    for file_id in range(nfiles):
        data_ptr, lengths_ptr = struct.unpack_from("<II", rom, table + file_id * 8)
        data = data_ptr & 0xffffff
        lengths = lengths_ptr & 0xffffff
        count = min(256, constants["NUM_STRINGS"] - file_id * 256)
        lens = rom[lengths:lengths + count]
        if len(lens) != count or 255 in lens:
            raise ValueError(f"invalid string lengths table for chunk {file_id}")
        payload_end = data + sum(lens)
        if payload_end > lengths or lengths + count > len(rom):
            raise ValueError(f"invalid string chunk bounds for chunk {file_id}")
        ranges.append({"start": data, "end": payload_end, "classification": "generated_string_payload",
                       "chunk": file_id, "pointer_table": hex(table + file_id * 8),
                       "path": str(tool), "line": 233})
        ranges.append({"start": lengths, "end": lengths + count, "classification": "generated_string_lengths",
                       "chunk": file_id, "pointer_table": hex(table + file_id * 8 + 4),
                       "path": str(tool), "line": 234})
    digest = hashlib.sha1(rom).hexdigest()
    if ranges[-1]["end"] != constants["DATA_OFFSET"] - 1:
        raise ValueError("final string chunk does not end immediately before DATA_OFFSET")
    for index in range(len(ranges) - 1):
        if ranges[index]["end"] != ranges[index + 1]["start"]:
            raise ValueError(f"gap or overlap between generated string ranges {index} and {index + 1}")
    return ranges, digest, constants


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("validation_json")
    parser.add_argument("repo_dir")
    parser.add_argument("rom")
    parser.add_argument("out_tsv")
    args = parser.parse_args()
    validation = json.loads(Path(args.validation_json).read_text())
    unknown = [p for p in validation["positive_targets"] if p["classification"] == "unknown"]
    symbols, ranges = collect(args.repo_dir)
    strings, rom_sha1, string_constants = string_ranges(args.repo_dir, args.rom)
    if validation.get("rom_sha1") != rom_sha1:
        raise ValueError(f"ROM SHA1 mismatch: validation={validation.get('rom_sha1')} actual={rom_sha1}")
    out = []
    for row in unknown:
        target = int(row["address"], 16)
        offset = target - BASE
        query_address = target | 1
        query_offset = query_address - BASE
        evidence = list(symbols.get(target, []))
        evidence.extend({
            "classification": "data", "path": r["path"], "line": r["line"],
            "section": r["section"], "symbol": f"{r['kind']} [{r['start']:#x},{r['end']:#x})",
        } for r in ranges if r["start"] <= offset < r["end"])
        evidence.extend({
            "classification": r["classification"], "path": r["path"], "line": r["line"],
            "section": ".rodata (generated by tools/pack_strings.c; linked by stage1.ld:140)",
            "symbol": f"chunk {r['chunk']} [{r['start']:#x},{r['end']:#x}); pointer table {r['pointer_table']}",
        } for r in strings if r["start"] <= offset < r["end"])
        query_evidence = [{"classification": r["classification"], "path": r["path"],
                           "line": r["line"], "chunk": r["chunk"],
                           "range": f"[{r['start']:#x},{r['end']:#x})",
                           "pointer_table": r["pointer_table"]}
                          for r in strings if r["start"] <= query_offset < r["end"]]
        priority = {"function_entry": 0, "internal_code": 1, "generated_string_payload": 2,
                    "generated_string_lengths": 3, "data": 4}
        evidence.sort(key=lambda e: (priority.get(e["classification"], 9), e["path"], e["line"]))
        category = evidence[0]["classification"] if evidence else "unknown"
        qcategory = query_evidence[0]["classification"] if query_evidence else "outside_string_ranges"
        sources = [int(x, 16) - BASE for x in row["exact_pointer_sources"]]
        pointer_fields = Counter(
            "payload_pointer" if (string_constants["DATA_OFFSET"] <= s <
                string_constants["DATA_OFFSET"] + ((string_constants["NUM_STRINGS"] + 255) // 256) * 8)
                and (s - string_constants["DATA_OFFSET"]) % 8 == 0 else
            "lengths_pointer" if (string_constants["DATA_OFFSET"] <= s <
                string_constants["DATA_OFFSET"] + ((string_constants["NUM_STRINGS"] + 255) // 256) * 8)
                and (s - string_constants["DATA_OFFSET"]) % 8 == 4 else "outside_string_pointer_table"
            for s in sources)
        out.append({**row, "offset": hex(offset), "query_address": hex(query_address),
                    "classification": category, "evidence": evidence,
                    "data_confirmed": category in ("data", "generated_string_payload", "generated_string_lengths"),
                    "query_classification": qcategory, "query_evidence": query_evidence,
                    "exact_source_pointer_fields": dict(pointer_fields)})

    path = Path(args.out_tsv)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["address\tquery_address\tclassification\tquery_classification\tgenerated_range\txref_sources\texact_pointer_sources"]
    for row in sorted(out, key=lambda r: int(r["address"], 16)):
        evidence = row["evidence"][0] if row["evidence"] else {}
        lines.append("\t".join((row["address"], row["query_address"], row["classification"],
                                 row["query_classification"],
                                 str(evidence.get("symbol", "")),
                                 ",".join(row["xref_sources"]),
                                 ",".join(row["exact_pointer_sources"]))))
    path.write_text("\n".join(lines) + "\n")
    path.with_suffix(".json").write_text(json.dumps({
        "counts": dict(Counter(row["classification"] for row in out)),
        "query_address_counts": dict(Counter(row["query_classification"] for row in out)),
        "exact_source_pointer_fields": dict(sum((Counter(row["exact_source_pointer_fields"])
                                                  for row in out), Counter())),
        "string_layout": {"rom": str(Path(args.rom)), "rom_sha1": rom_sha1,
                          "constants": {k: hex(v) for k, v in string_constants.items()},
                          "pack_rule": "Makefile:110-115", "linked_at": "stage1.ld:140"},
        "targets": out,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
