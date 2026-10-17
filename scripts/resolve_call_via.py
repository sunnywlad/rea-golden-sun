"""Extend verified aliases with the unique ROM sequence emitted by lib/call_via.s."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("aliases", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    work = Path(__file__).resolve().parents[1] / "work"
    repo = work / "repo"
    source = repo / "lib/call_via.s"
    macros = repo / "include/macros.inc"
    linkage = repo / "stage1.ld"
    lines = [line.split("@", 1)[0].strip() for line in source.read_text().splitlines()]
    registers = re.findall(r"^call_via (r\d+|sp|lr)$", "\n".join(lines), re.M)
    expected_registers = [f"r{i}" for i in range(13)] + ["sp", "lr"]
    if registers != expected_registers:
        raise ValueError("unexpected source register sequence")
    template = "\n".join(lines[lines.index(".macro call_via register"):lines.index(".endm")+1])
    if template != ".macro call_via register\n.thumb_func_start _call_via_\\register\nbx\t\\register\nnop\n.func_end _call_via_\\register\n.endm":
        raise ValueError("call_via macro no longer matches reviewed BX/NOP template")
    if not re.search(r"\.macro \.thumb_func_start sym\s+\.align\s+2, 0", macros.read_text()):
        raise ValueError("Thumb entry alignment macro changed")
    if "lib/call_via.o(.text)" not in linkage.read_text():
        raise ValueError("call_via linkage missing")
    rom = (work / "rom/Golden Sun (USA, Europe).gba").read_bytes()
    if hashlib.sha1(rom).hexdigest() != "5c4695205413df7db52b9a184815a07783999971":
        raise ValueError("unexpected ROM")
    pattern = b"".join(struct.pack("<HH", 0x4700 | i << 3, 0x46c0) for i in range(15))
    hits = [i for i in range(0, len(rom)-len(pattern)+1, 4) if rom.startswith(pattern, i)]
    if len(hits) != 1:
        raise ValueError(f"expected unique aligned 15-stub ROM sequence, got {hits}")
    result = json.loads(args.aliases.read_text())
    for i, register in enumerate(registers):
        name = "_call_via_" + register
        if name in result["aliases"]:
            raise ValueError("alias already present: " + name)
        offset = hits[0] + 4*i
        result["aliases"][name] = dict(kind="thumb_call_via", address=hex(0x08000000+offset),
            register=register, register_number=i, bytes=rom[offset:offset+4].hex(),
            declaration="lib/call_via.s", line=next(n+1 for n,s in enumerate(lines) if s == "call_via " + register),
            address_proof="unique aligned full 15-stub BX/NOP sequence, macro order and ROM verified",
            target="runtime value in " + register)
    result["call_via_provenance"] = dict(sequence_start=hex(0x08000000+hits[0]), sequence_bytes=pattern.hex(),
        source_sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (source, macros, linkage, args.aliases)})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(dict(new_stubs=15, total_aliases=len(result["aliases"]), start=hex(0x08000000+hits[0]))))


if __name__ == "__main__":
    main()
