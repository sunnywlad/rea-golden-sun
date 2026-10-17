#!/usr/bin/env python3
"""Verify generated string chunks against the ROM using the reference C tools."""
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo")
    parser.add_argument("rom")
    parser.add_argument("out")
    args = parser.parse_args()
    repo, rom_path, out = map(lambda p: Path(p).resolve(), (args.repo, args.rom, args.out))
    out.mkdir(parents=True, exist_ok=True)
    source = (repo / "tools/unpack_strings.c").read_text()
    constants = {k: int(v, 0) for k, v in re.findall(
        r"^#define\s+(DATA_OFFSET|NUM_STRINGS)\s+(0x[0-9a-fA-F]+|[0-9]+)", source, re.M)}
    for name in ("unpack_strings", "pack_strings"):
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", str(repo / f"tools/{name}.c"),
                        "-o", str(out / name)], check=True)
    decoded = out / "strings.txt"
    subprocess.run([str(out / "unpack_strings"), "-r", str(rom_path), "-o", str(decoded)], check=True)
    packed = out / "repacked"
    packed.mkdir(exist_ok=True)
    subprocess.run([str(out / "pack_strings"), "-i", str(decoded), "-o", str(packed)], check=True)
    rom = rom_path.read_bytes()
    count = decoded.read_bytes().count(b"\n")
    if count != constants["NUM_STRINGS"]:
        raise ValueError("Decoded string count differs from the reference constant")
    chunks = []
    for i in range((count + 255) // 256):
        data, lengths = struct.unpack_from("<II", rom, constants["DATA_OFFSET"] + i * 8)
        data, lengths = data & 0xffffff, lengths & 0xffffff
        payload = (packed / f"strings_{i:02d}.bin").read_bytes()
        sizes = (packed / f"strings_{i:02d}_lengths.bin").read_bytes()
        chunks.append({"chunk": i, "payload_start": hex(0x08000000 + data),
                       "lengths_start": hex(0x08000000 + lengths),
                       "payload_bytes": len(payload), "lengths_bytes": len(sizes),
                       "payload_equal": rom[data:data + len(payload)] == payload,
                       "lengths_equal": rom[lengths:lengths + len(sizes)] == sizes,
                       "payload_end_equals_lengths_start": data + len(payload) == lengths})
    result = {"rom_sha1": hashlib.sha1(rom).hexdigest(), "decoded_string_count": count, "chunks": chunks}
    (out / "roundtrip.json").write_text(json.dumps(result, indent=2) + "\n")
    if not all(c["payload_equal"] and c["lengths_equal"] for c in chunks):
        raise ValueError("At least one repacked chunk differs from the ROM")
    print(f"{count} strings; {len(chunks)} payloads and length tables match the ROM exactly")


if __name__ == "__main__":
    main()
