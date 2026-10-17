import json, re, sys
d = sys.argv[1]
rea = {}
for p in json.load(open(sys.argv[2]))["normalized_result"]:
    a = p["address"]
    if a.startswith("0x") and not p["procedure"]["external"]:
        rea[int(a, 16)] = p["value"]
repo = {}
for l in open(d + "/repo_funcs.txt"):
    k, n = l.split()
    m = re.fullmatch(r"_?Func_([0-9a-f]+)", n)
    if m: repo[0x08000000 + int(m.group(1), 16)] = (k, n)
R, G = set(rea), set(repo)
print("rea_internal", len(R), "repo_Func", len(G))
print("common", len(R & G), "missing_in_rea", len(G - R), "extra_in_rea", len(R - G))
print("recall %.1f%%  precision %.1f%%" % (100*len(R&G)/len(G), 100*len(R&G)/len(R)))
rng = lambda s: (min(s), max(s)) if s else None
print("rea range", [hex(x) for x in rng(R)], "repo range", [hex(x) for x in rng(G)])
miss = sorted(G - R); extra = sorted(R - G)
# bucket by 0x10000 region
from collections import Counter
cm = Counter(hex(a >> 16) for a in miss); ce = Counter(hex(a >> 16) for a in extra); cc = Counter(hex(a >> 16) for a in R & G)
print("buckets (addr>>16): common / missing / extra")
for b in sorted(set(cm)|set(ce)|set(cc), key=lambda s:int(s,16)): print(b, cc[b], cm[b], ce[b])
mode = Counter(repo[a][0] for a in miss); print("missing by mode", dict(mode))
modec = Counter(repo[a][0] for a in R & G); print("common by mode", dict(modec))
json.dump({"missing": [hex(a) for a in miss[:40]], "extra": [hex(a) for a in extra[:40]]}, open(d + "/cmp_samples.json", "w"))
