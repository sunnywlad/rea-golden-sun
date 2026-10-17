import json, re, struct, sys
from collections import Counter
rom = open(sys.argv[1], "rb").read()
words = Counter(struct.unpack("<%dI" % (len(rom) // 4), rom))
rea = {int(p["address"], 16) for p in json.load(open(sys.argv[3]))["normalized_result"]
       if p["address"].startswith("0x") and not p["procedure"]["external"]}
miss = []
for l in open(sys.argv[2]):
    k, n = l.split()
    m = re.fullmatch(r"_?Func_([0-9a-f]+)", n)
    if m and k == "thumb":
        a = 0x08000000 + int(m.group(1), 16)
        if a not in rea: miss.append(a)
withptr = [a for a in miss if words[a | 1]]
print("missed thumb", len(miss), "| with an odd ROM pointer", len(withptr))
print([hex(a) for a in withptr[:10]])
