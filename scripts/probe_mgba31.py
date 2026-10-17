"""Private local full-core exploration. Prints counts and registers only."""
import ctypes as C
import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / 'work/step31_private'
PRIVATE.mkdir(exist_ok=True, mode=0o700)
PRIVATE.chmod(0o700)

class Core:
    def __init__(self):
        self.lib = C.CDLL(str(ROOT / 'work/step31_tools/mgba31.so'))
        self.lib.start.argtypes = [C.c_char_p]
        self.lib.regget.argtypes = [C.c_char_p]
        self.lib.regset.argtypes = [C.c_char_p, C.c_uint]
        assert self.lib.start(str(ROOT / 'work/rom/Golden Sun (USA, Europe).gba').encode())
        assert self.lib.color_size() == 4
    def frames(self, n, keys=0): self.lib.frames(n, keys)
    def rd(self, a, width=4): return self.lib.rd(a, width) & ((1 << (8*width))-1)
    def wr(self, a, value, width=4): self.lib.wr(a, value, width)
    def reg(self, name, value=None):
        if value is None: return self.lib.regget(name.encode()) & 0xffffffff
        assert self.lib.regset(name.encode(), value)
    def dump(self, a, n):
        b = (C.c_ubyte*n)(); self.lib.dump(a, n, b); return bytes(b)
    def image(self):
        b = (C.c_ubyte*(240*160*4))(); self.lib.image(b); return bytes(b)
    def state(self):
        b = (C.c_ubyte*self.lib.state_size())(); assert self.lib.save(b); return bytes(b)
    def restore(self, data):
        b = (C.c_ubyte*len(data)).from_buffer_copy(data); assert self.lib.load(b)

def private_write(name, data):
    p = PRIVATE / name
    with os.fdopen(os.open(p, os.O_CREAT|os.O_TRUNC|os.O_WRONLY, 0o600), 'wb') as f:
        f.write(data)
    p.chmod(0o600)

if __name__ == '__main__':
    core = Core()
    for i in range(10):
        core.frames(60)
        print({'frame':(i+1)*60, 'pc':hex(core.reg('pc')), 'dispcnt':hex(core.rd(0x04000000,2)),
               'frame_sha256':hashlib.sha256(core.image()).hexdigest()}, flush=True)
    private_write('boot600.state', core.state())
    core.lib.stop()
