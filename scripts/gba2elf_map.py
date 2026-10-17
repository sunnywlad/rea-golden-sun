import struct
import sys

BASE = 0x08000000
OFFSET = 0x1000
# GBA RAM/IO regions as empty RW segments: (address, size)
REGIONS = [
    (0x02000000, 0x40000),  # EWRAM
    (0x03000000, 0x8000),   # IWRAM
    (0x04000000, 0x400),    # IO
    (0x05000000, 0x400),    # palette
    (0x06000000, 0x18000),  # VRAM
    (0x07000000, 0x400),    # OAM
]

rom = open(sys.argv[1], "rb").read()
nph = 1 + len(REGIONS)

ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
ehdr = ident + struct.pack(
    "<HHIIIIIHHHHHH",
    2, 40, 1, BASE, 52, 0, 0x05000000, 52, 32, nph, 0, 0, 0,
)
phdrs = struct.pack("<IIIIIIII", 1, OFFSET, BASE, BASE, len(rom), len(rom), 5, 0x1000)
for addr, size in REGIONS:
    phdrs += struct.pack("<IIIIIIII", 1, 0, addr, addr, 0, size, 6, 0x1000)

with open(sys.argv[2], "wb") as f:
    f.write(ehdr + phdrs)
    f.write(b"\0" * (OFFSET - 52 - 32 * nph))
    f.write(rom)
