import struct
import sys

BASE = 0x08000000
OFFSET = 0x1000

rom = open(sys.argv[1], "rb").read()

ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
ehdr = ident + struct.pack(
    "<HHIIIIIHHHHHH",
    2, 40, 1, BASE, 52, 0, 0x05000000, 52, 32, 1, 0, 0, 0,
)
phdr = struct.pack("<IIIIIIII", 1, OFFSET, BASE, BASE, len(rom), len(rom), 5, 0x1000)

with open(sys.argv[2], "wb") as f:
    f.write(ehdr + phdr)
    f.write(b"\0" * (OFFSET - 84))
    f.write(rom)
