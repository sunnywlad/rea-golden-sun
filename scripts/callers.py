import re, sys, glob, json
root, target = sys.argv[1], sys.argv[2]
rea = {int(a, 16) for a in json.loads(sys.argv[3])}
callers = {}
for path in glob.glob(root + "/**/*.s", recursive=True):
    cur = None
    for line in open(path, errors="ignore"):
        m = re.match(r"\s*\.(?:arm|thumb)_func_start\s+(\S+)", line)
        if m: cur = m.group(1); continue
        if cur and re.match(r"\s+bl\s+%s\b" % re.escape(target), line):
            callers.setdefault(cur, 0); callers[cur] += 1
rom = {}; ovl = []
for n in callers:
    m = re.fullmatch(r"_?Func_([0-9a-f]+)", n)
    if m: rom[0x08000000 + int(m.group(1), 16)] = n
    else: ovl.append(n)
R, G = rea, set(rom)
print("repo: %d call sites in %d functions (%d ROM Func_, %d overlay/other)" % (sum(callers.values()), len(callers), len(rom), len(ovl)))
print("REA callers", len(R), "| common", len(R & G), "| only repo", len(G - R), "| only REA", len(R - G))
print("only repo:", sorted(hex(a) for a in G - R))
print("only REA:", sorted(hex(a) for a in R - G))
