import json, re, sys, glob
root, graph_f, procs_f, start = sys.argv[1:5]
# REA side: reachable set, thunks resolved to their targets
thunk = {}
for p in json.load(open(procs_f))["normalized_result"]:
    if p["procedure"]["thunk"] and p["procedure"]["thunk_target"]:
        thunk[int(p["address"], 16)] = int(str(p["procedure"]["thunk_target"]).split(":")[-1], 16)
norm = lambda a: thunk.get(a, a)
rea_nodes, rea_edges = set(), set()
for lvl in json.load(open(graph_f))["normalized_result"].values():
    for n in lvl:
        a = norm(int(n["address"], 16)); rea_nodes.add(a)
        for c in n["calls"]: rea_edges.add((a, norm(int(c, 16))))
# repo side: direct bl graph
funcs, cur = {}, None
for path in glob.glob(root + "/**/*.s", recursive=True):
    for line in open(path, errors="ignore"):
        m = re.match(r"\s*\.(?:arm|thumb)_func_start\s+(\S+)", line)
        if m: cur = m.group(1); funcs.setdefault(cur, set()); continue
        m = re.match(r"\s+bl\s+_?(Func_[0-9a-f]+)\b", line)
        if m and cur: funcs[cur].add(m.group(1))
addr = lambda n: 0x08000000 + int(n.split("_")[1], 16)
seen, todo = set(), [start]
while todo:
    n = todo.pop()
    if n in seen or n not in funcs: continue
    seen.add(n); todo.extend(funcs[n])
repo_nodes = {addr(n) for n in seen}
repo_edges = {(addr(n), addr(c)) for n in seen for c in funcs[n] if c in funcs}
print("nodes  REA", len(rea_nodes), "repo", len(repo_nodes), "common", len(rea_nodes & repo_nodes), "only REA", len(rea_nodes - repo_nodes), "only repo", len(repo_nodes - rea_nodes))
print("edges  REA", len(rea_edges), "repo", len(repo_edges), "common", len(rea_edges & repo_edges), "only REA", len(rea_edges - repo_edges), "only repo", len(repo_edges - rea_edges))
print("node recall %.1f%% precision %.1f%%" % (100*len(rea_nodes&repo_nodes)/len(repo_nodes), 100*len(rea_nodes&repo_nodes)/len(rea_nodes)))
print("only repo sample", sorted(hex(a) for a in repo_nodes - rea_nodes)[:8])
print("only REA sample", sorted(hex(a) for a in rea_nodes - repo_nodes)[:8])
