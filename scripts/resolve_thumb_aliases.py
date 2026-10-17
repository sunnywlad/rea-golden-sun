"""Resolve generated Thumb veneers from source declarations, verifying every stub in the ROM."""
import hashlib
import json
from pathlib import Path
import re
import struct


def main():
    work=Path(__file__).resolve().parents[1]/"work"
    rom=(work/"rom/Golden Sun (USA, Europe).gba").read_bytes()
    assert hashlib.sha1(rom).hexdigest()=="5c4695205413df7db52b9a184815a07783999971"
    modes={name:mode for mode,name in (line.split() for line in (work/"repo_funcs.txt").read_text().splitlines())}
    definitions={}
    for path in (work/"repo").glob("*/src/*.s"):
        for line in path.read_text().splitlines():
            m=re.match(r"\s*\.(thumb_func_start(?:_noalign)?|arm_func_start)\s+(Func_[0-9a-fA-F]+)",line)
            if m:
                definitions[m[2]]=str(path.relative_to(work/"repo"))
                modes[m[2]]="thumb" if m[1].startswith("thumb") else "arm"

    def pointer(name):
        offset=int(name.removeprefix("Func_"),16)
        if definitions[name]=="rom_c0/src/rom_770.s" and 0x770<=offset<0x1b70:
            address=0x03000000+offset-0x770
        else:
            address=0x08000000+offset
        return address | (1 if modes[name]=="thumb" else 0)

    aliases={}
    for path in sorted((work/"repo").glob("*/src/exports.s")):
        text=path.read_text()
        base=re.search(r"^Exports_([0-9a-fA-F]+):",text,re.M)
        if not base:
            raise ValueError(f"missing explicit exports base: {path}")
        offset=int(base[1],16)
        for line_no,line in enumerate(text.splitlines(),1):
            export=re.match(r"\s*\.export_func\s+(Func_[0-9a-fA-F]+)\s*$",line)
            if not export:
                continue
            target=export[1]
            expected=struct.pack("<HHI",0x4c00,0x4720,pointer(target))
            assert rom[offset:offset+8]==expected,(path,line_no,target,hex(offset))
            alias="_"+target
            assert alias not in aliases
            aliases[alias]=dict(address=hex(0x08000000+offset),target=target,
                               target_pointer=hex(pointer(target)),register="r4",bytes=expected.hex(),
                               declaration=str(path.relative_to(work/"repo")),line=line_no,
                               address_proof="exports block base + 8-byte macro layout, all bytes verified")
            offset+=8
    for path in sorted((work/"repo").glob("*/src/*.s")):
        for line_no,line in enumerate(path.read_text().splitlines(),1):
            stub=re.match(r"\s*\.thumb_stub\s+(\w+),\s*(Func_[0-9a-fA-F]+)(?:,\s*r([0-7]))?\s*$",line)
            if not stub:
                continue
            alias,target,register=stub.groups(); reg=int(register or "4")
            expected=struct.pack("<HHI",0x4800|(reg<<8),0x4700|(reg<<3),pointer(target))
            positions=[n for n in range(0,len(rom)-7,4) if rom[n:n+8]==expected]
            assert len(positions)==1,(alias,positions)
            assert alias not in aliases
            aliases[alias]=dict(address=hex(0x08000000+positions[0]),target=target,
                               target_pointer=hex(pointer(target)),register="r"+str(reg),bytes=expected.hex(),
                               declaration=str(path.relative_to(work/"repo")),line=line_no,
                               address_proof="unique aligned exact stub bytes in pinned ROM")
    output=work/"thumb_aliases.json"
    output.write_text(json.dumps(dict(aliases=aliases,macro_source="include/macros.inc (.thumb_stub, .export_func, .func_end)",
                                     linkage_source="stage1.ld; goldensun.ld; rom_c0/src/rom_770.s"),indent=2)+"\n")
    print(json.dumps(dict(aliases=len(aliases),explicit_runtime_stub=aliases.get("Func_af0_from_thumb"))))


if __name__=="__main__":
    main()
