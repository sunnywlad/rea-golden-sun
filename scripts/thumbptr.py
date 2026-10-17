import re, struct, sys
from collections import Counter
rom = open(sys.argv[1], "rb").read()
words = Counter(struct.unpack("<%dI" % (len(rom) // 4), rom))
res = {"arm": [0, 0, 0], "thumb": [0, 0, 0]}  # total, even-ptr hit, odd-ptr hit
for l in open(sys.argv[2]):
    k, n = l.split()
    m = re.fullmatch(r"_?Func_([0-9a-f]+)", n)
    if not m: continue
    a = 0x08000000 + int(m.group(1), 16)
    r = res[k]; r[0] += 1
    if words[a]: r[1] += 1
    if words[a | 1]: r[2] += 1
for k, (t, e, o) in res.items():
    print(k, "total", t, "word == addr:", e, "word == addr|1:", o)
