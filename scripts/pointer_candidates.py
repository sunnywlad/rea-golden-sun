#!/usr/bin/env python3
"""Scan odd GBA ROM pointers and summarize REA xrefs saved as MCP envelopes."""
import argparse
import hashlib
import json
import re
import struct
from collections import defaultdict
from pathlib import Path

BASE = 0x08000000
FUNC = re.compile(r"_?Func_([0-9a-f]+)")


def load_repo(path):
    funcs = {}
    for line in Path(path).read_text().splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        mode, name = fields
        match = FUNC.fullmatch(name)
        if match:
            funcs[BASE + int(match.group(1), 16)] = {"mode": mode, "name": name}
    return funcs


def load_rea(path):
    doc = json.loads(Path(path).read_text())
    return {
        int(p["address"], 16)
        for p in doc.get("normalized_result", [])
        if p.get("address", "").startswith("0x")
        and not p.get("procedure", {}).get("external", False)
    }


def scan(rom_path, repo_path, procs_path, out_path):
    rom = Path(rom_path).read_bytes()
    repo, rea = load_repo(repo_path), load_rea(procs_path)
    sources = defaultdict(list)
    end = BASE + len(rom)
    for offset in range(0, len(rom) - 3, 4):
        value = struct.unpack_from("<I", rom, offset)[0]
        if value & 1 and BASE <= (target := value & ~1) < end:
            sources[target].append(BASE + offset)

    candidates = []
    for target, refs in sorted(sources.items()):
        entry = repo.get(target)
        if entry:
            classification = "repo_" + entry["mode"]
        elif target in rea:
            classification = "rea_only"
        else:
            classification = "unknown"
        candidates.append({
            "address": hex(target),
            "pointer_value": hex(target | 1),
            "sources": [hex(a) for a in refs],
            "repo": entry,
            "classification": classification,
            "in_rea": target in rea,
            "missing": bool(entry and target not in rea),
        })
    output = {
        "rom_sha1": hashlib.sha1(rom).hexdigest(),
        "rom_size": len(rom),
        "repo_funcs": str(repo_path),
        "procs_sha256": hashlib.sha256(Path(procs_path).read_bytes()).hexdigest(),
        "missing_thumb_functions": [
            {"address": hex(a), "name": entry["name"]}
            for a, entry in sorted(repo.items())
            if entry["mode"] == "thumb" and a not in rea
        ],
        "candidates": candidates,
    }
    Path(out_path).write_text(json.dumps(output, indent=2) + "\n")


def evidence_status(value):
    """Decode MCP xrefs strictly; arbitrary nonempty content is not evidence."""
    if isinstance(value, dict) and value.get("isError"):
        return "error"

    evidence = value.get("structuredContent") if isinstance(value, dict) else None
    if isinstance(evidence, dict) and "normalized_result" in evidence:
        result = evidence["normalized_result"]
        return "positive" if isinstance(result, list) and result else (
            "negative" if isinstance(result, list) else "error")

    content = value.get("content") if isinstance(value, dict) else value
    if isinstance(content, list):
        texts = [part.get("text", "") for part in content
                 if isinstance(part, dict) and part.get("type") == "text"]
        if not texts:
            return "error"
        decoded = []
        for text in texts:
            try:
                decoded.append(json.loads(text))
            except (json.JSONDecodeError, TypeError):
                continue
        content = next((item for item in decoded
                        if isinstance(item, dict) and "normalized_result" in item), None)
    elif isinstance(content, str):
        try:
            content = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return "error"
    if isinstance(content, dict) and "normalized_result" in content:
        result = content["normalized_result"]
        return "positive" if isinstance(result, list) and result else (
            "negative" if isinstance(result, list) else "error")
    return "error"


def iter_envelopes(doc):
    if isinstance(doc, list):
        for item in doc:
            yield from iter_envelopes(item)
    elif isinstance(doc, dict):
        if "address" in doc and "result" in doc:
            yield doc
        else:
            for value in doc.values():
                yield from iter_envelopes(value)


def summarize(candidates_path, xrefs_path, out_path):
    doc = json.loads(Path(candidates_path).read_text())
    envelopes = list(iter_envelopes(json.loads(Path(xrefs_path).read_text())))
    by_address = {}
    for envelope in envelopes:
        address = int(envelope["address"], 16) & ~1
        result = envelope["result"]
        status = "error" if envelope.get("isError") else evidence_status(result)
        by_address[address] = status
    rows = doc["candidates"]
    statuses = {int(r["address"], 16): by_address.get(int(r["address"], 16)) for r in rows}
    positive = [r for r in rows if statuses[int(r["address"], 16)] == "positive"]
    queried = [r for r in rows if statuses[int(r["address"], 16)] is not None]
    errors = [r for r in queried if statuses[int(r["address"], 16)] == "error"]
    negative = [r for r in queried if statuses[int(r["address"], 16)] == "negative"]
    unqueried = [r for r in rows if statuses[int(r["address"], 16)] is None]
    missed_thumb = doc.get("missing_thumb_functions", [])
    recovered = [r for r in missed_thumb if by_address.get(int(r["address"], 16)) == "positive"]
    positive_without_rea = [r for r in positive if not r["in_rea"]]
    repo_confirmed = [r for r in positive_without_rea if r["classification"] == "repo_thumb"]
    repo_arm = [r for r in positive if r["classification"] == "repo_arm"]
    repo_arm_mismatches = [r for r in repo_arm if not r["in_rea"]]
    pct = lambda n, d: "n/a" if not d else f"{100*n/d:.1f}%"
    lines = [
        "# Odd ROM pointer xrefs",
        "",
        f"- ROM SHA1: `{doc['rom_sha1']}`",
        f"- REA procedures SHA256: `{doc['procs_sha256']}`",
        f"- Scanned candidates: {len(rows)}; queried: {len(queried)}; errors: {len(errors)}; negative: {len(negative)}; unqueried: {len(unqueried)}",
        f"- Xref-positive candidates: {len(positive)}/{len(queried)} queried; {len(positive)}/{len(rows)} all candidates ({pct(len(positive), len(rows))})",
        f"- Missing Thumb repo functions: {len(missed_thumb)}",
        f"- Missing Thumb functions with positive xrefs: {len(recovered)}/{len(missed_thumb)} ({pct(len(recovered), len(missed_thumb))})",
        f"- Repo-confirmed Thumb among all xref-positive candidates: {len([r for r in positive if r['classification'] == 'repo_thumb'])}/{len(positive)} ({pct(len([r for r in positive if r['classification'] == 'repo_thumb']), len(positive))})",
        f"- Repo-confirmed Thumb among xref-positive candidates without baseline REA functions: {len(repo_confirmed)}/{len(positive_without_rea)} ({pct(len(repo_confirmed), len(positive_without_rea))})",
        f"- Repo ARM targets with odd-pointer xrefs (mode mismatch): {len(repo_arm_mismatches)}/{len(repo_arm)} positive repo ARM targets",
        "",
        "The last proportion is confirmation against the repo reference. Targets absent from the repo remain unknown, not false positives; this is not an overall precision estimate.",
        "",
        "## Positive targets",
        "",
        "| Target | Classification | Missing | Xrefs |",
        "|---|---|---:|---:|",
    ]
    for row in positive:
        name = row["repo"]["name"] if row["repo"] else "—"
        lines.append(f"| `{row['address']}` {name} | {row['classification']} | {row['missing']} | yes |")
    lines.extend(["", "## Repo ARM mode mismatches", ""])
    lines.extend(f"- `{r['address']}` {r['repo']['name']} (in REA: {r['in_rea']})"
                 for r in repo_arm_mismatches)
    Path(out_path).write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("scan", help="enumerate aligned odd ROM pointers")
    p.add_argument("rom")
    p.add_argument("repo_funcs")
    p.add_argument("procs")
    p.add_argument("out_json")
    p = commands.add_parser("summarize", help="summarize saved REA xref envelopes")
    p.add_argument("candidates_json")
    p.add_argument("xrefs_json")
    p.add_argument("out_md")
    args = parser.parse_args()
    if args.command == "scan":
        scan(args.rom, args.repo_funcs, args.procs, args.out_json)
    else:
        summarize(args.candidates_json, args.xrefs_json, args.out_md)


if __name__ == "__main__":
    main()
