#!/usr/bin/env python3
"""Compare Ghidra recovery snapshots with repo functions and the REA baseline."""
import argparse
import json
import re
from collections import Counter
from pathlib import Path

BASE = 0x08000000
FUNC = re.compile(r"_?Func_([0-9a-f]+)")
ADDRESS_KEYS = ("address", "entry", "entryPoint", "entry_point", "function_address", "target_address", "start")
RECORD_KEYS = ("normalized_result", "functions", "procedures", "results", "targets")


def address(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return None


def records(doc):
    if isinstance(doc, list):
        return [item for item in doc if isinstance(item, dict)]
    if not isinstance(doc, dict):
        return []
    for key in RECORD_KEYS:
        if isinstance(doc.get(key), list):
            return records(doc[key])
    # Also accept an address-keyed mapping emitted by small Ghidra scripts.
    if doc and all(address(key) is not None for key in doc):
        return [dict(value, address=key) if isinstance(value, dict) else {"address": key}
                for key, value in doc.items()]
    return []


def load_snapshot(path):
    doc = json.loads(Path(path).read_text())
    found = {}
    for row in records(doc):
        addr = next((address(row.get(k)) for k in ADDRESS_KEYS
                     if address(row.get(k)) is not None), None)
        if addr is None:
            continue
        found[addr] = row
    return found


def load_repo(path):
    funcs = {}
    for line in Path(path).read_text().splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        match = FUNC.fullmatch(fields[1])
        if match:
            funcs[BASE + int(match.group(1), 16)] = {
                "mode": fields[0], "name": fields[1],
            }
    return funcs


def load_targets(path):
    doc = json.loads(Path(path).read_text())
    result = {}
    for row in records(doc):
        addr = next((address(row.get(k)) for k in ADDRESS_KEYS
                     if address(row.get(k)) is not None), None)
        if addr is not None:
            result[addr] = row
    return result


def find_value(row, keys):
    for key in keys:
        if key in row:
            return row[key]
    for parent in ("metadata", "analysis", "procedure", "decompilation", "decompile", "decomp"):
        nested = row.get(parent)
        if isinstance(nested, dict):
            for key in keys:
                if key in nested:
                    return nested[key]
    return None


def thumb_value(row):
    value = find_value(row, ("tmode", "TMode", "thumb_mode", "thumb", "mode"))
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        low = value.lower()
        if low in ("thumb", "true", "yes"):
            return 1
        if low in ("arm", "false", "no"):
            return 0
        match = re.search(r"(?:tmode\s*[=:]\s*)?(0x[0-9a-f]+|\d+)", low)
        if match:
            return int(match.group(1), 0)
    return None


def decomp_status(row):
    value = find_value(row, ("decompileCompleted", "decompile_completed",
                             "decomp_success", "decompile_success", "decomp_ok"))
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.lower()
        if low in ("true", "success", "ok", "completed"):
            return True
        if low in ("false", "failed", "error", "incomplete"):
            return False
    if isinstance(value, dict):
        for key in ("completed", "success", "ok"):
            if isinstance(value.get(key), bool):
                return value[key]
    return None


def bool_value(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.lower()
        if low in ("true", "success", "ok", "completed"):
            return True
        if low in ("false", "failed", "error", "incomplete"):
            return False
    return None


def pct(n, d):
    return None if not d else round(100 * n / d, 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_funcs")
    parser.add_argument("before_json")
    parser.add_argument("after_json")
    parser.add_argument("targets_json")
    parser.add_argument("baseline_json")
    parser.add_argument("out_dir")
    args = parser.parse_args()

    repo = load_repo(args.repo_funcs)
    before, after = load_snapshot(args.before_json), load_snapshot(args.after_json)
    targets = load_targets(args.targets_json)
    baseline = load_snapshot(args.baseline_json)
    old, new, target_set = set(before), set(after), set(targets)
    repo_set = set(repo)
    created = new - old
    lost = old - new
    newly_added_targets = created & target_set
    extras = created - target_set
    missing_targets = target_set - new
    common_before, common_after = repo_set & old, repo_set & new
    thumb_repo = {a for a, f in repo.items() if f["mode"] == "thumb"}
    arm_repo = {a for a, f in repo.items() if f["mode"] == "arm"}
    baseline_equal = set(before) == set(baseline)

    target_rows = []
    for addr in sorted(target_set | (created & target_set)):
        row = after.get(addr, {})
        target_meta = targets[addr]
        mode = thumb_value(row) if row else None
        if mode is None:
            mode = thumb_value(target_meta)
        dec = decomp_status(row) if row else None
        if dec is None:
            dec = decomp_status(target_meta) if target_meta.get("status") == "created" else None
        disasm = bool_value(target_meta.get("disassemble_success"))
        target_rows.append({
            "address": hex(addr),
            "name": target_meta.get("name") or target_meta.get("repo_name") or repo.get(addr, {}).get("name"),
            "target_status": "missing_after" if addr not in new else (
                "created" if addr in created else "already_present"),
            "recovery_status": target_meta.get("status", "unknown"),
            "recovery_detail": target_meta.get("detail", ""),
            "body_size": target_meta.get("body_size"),
            "disassemble_success": disasm,
            "target_metadata": target_meta,
            "after_metadata": row,
            "tmode": mode,
            "thumbmode_non1_created": addr in created and mode is not None and mode != 1,
            "decompile_success": dec,
        })
    mode_known = [r for r in target_rows if r["target_status"] == "created" and r["tmode"] is not None]
    dec_known = [r for r in target_rows if r["target_status"] == "created" and r["decompile_success"] is not None]
    attempt_dec_known = [r for r in target_rows if r["decompile_success"] is not None]
    attempt_disasm_known = [r for r in target_rows if r["disassemble_success"] is not None]
    statuses = Counter(r["target_status"] for r in target_rows)
    attempt_statuses = Counter(r["recovery_status"] for r in target_rows)
    summary = {
        "inputs": {
            "repo_funcs": str(args.repo_funcs), "before": str(args.before_json),
            "after": str(args.after_json), "targets": str(args.targets_json),
            "baseline": str(args.baseline_json),
        },
        "counts": {
            "repo_functions": len(repo), "before_functions": len(old),
            "after_functions": len(new), "baseline_functions": len(baseline),
            "baseline_exact_address_set_equal_before": baseline_equal,
            "baseline_only_before": len(old - set(baseline)),
            "baseline_only_current": len(set(baseline) - old),
            "repo_common_before": len(common_before),
            "repo_common_before_recall_percent": pct(len(common_before), len(repo_set)),
            "repo_common_after": len(common_after),
            "repo_common_after_recall_percent": pct(len(common_after), len(repo_set)),
            "repo_thumb_total": len(thumb_repo), "repo_thumb_common_before": len(thumb_repo & old),
            "repo_thumb_common_after": len(thumb_repo & new),
            "repo_arm_total": len(arm_repo), "repo_arm_common_before": len(arm_repo & old),
            "repo_arm_common_after": len(arm_repo & new),
            "lost_baseline_entries": len(lost), "created_entries": len(created),
            "target_count": len(target_set), "created_targets": len(newly_added_targets),
            "targets_missing_after": len(missing_targets), "unexpected_added_extras": len(extras),
            "target_statuses": dict(statuses),
            "recovery_attempt_statuses": dict(attempt_statuses),
            "attempt_disassemble_known": len(attempt_disasm_known),
            "attempt_disassemble_success": sum(r["disassemble_success"] is True for r in attempt_disasm_known),
            "attempt_decompile_known": len(attempt_dec_known),
            "attempt_decompile_success": sum(r["decompile_success"] is True for r in attempt_dec_known),
            "attempt_decompile_failure": sum(r["decompile_success"] is False for r in attempt_dec_known),
            "attempt_decompile_unknown": len(target_rows) - len(attempt_dec_known),
            "created_thumbmode_known": len(mode_known),
            "created_thumbmode_non1": sum(r["thumbmode_non1_created"] for r in target_rows),
            "created_thumbmode_unknown": statuses["created"] - len(mode_known),
            "created_decompile_known": len(dec_known),
            "created_decompile_success": sum(r["decompile_success"] is True for r in dec_known),
            "created_decompile_failure": sum(r["decompile_success"] is False for r in dec_known),
            "created_decompile_unknown": statuses["created"] - len(dec_known),
        },
        "lost_baseline_addresses": [hex(a) for a in sorted(lost)],
        "created_addresses": [hex(a) for a in sorted(created)],
        "created_targets": [hex(a) for a in sorted(newly_added_targets)],
        "targets_missing_after": [hex(a) for a in sorted(missing_targets)],
        "unexpected_added_extras": [hex(a) for a in sorted(extras)],
        "targets": target_rows,
        "caveat": "Function creation alone does not validate correct Thumb decoding or complete body bounds. Decompilation success is only a tool status; compare instructions, control flow, memory accesses, calls, and return behavior with repo source, and inspect body truncation/overlap.",
    }

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "recovery_report.json").write_text(json.dumps(summary, indent=2) + "\n")
    c = summary["counts"]
    lines = [
        "# Thumb function recovery report", "",
        f"- Baseline addresses exactly equal to before snapshot: **{baseline_equal}** ({len(baseline)} current, {len(old)} before)",
        f"- Repo recall: before {c['repo_common_before']}/{len(repo_set)} ({c['repo_common_before_recall_percent']}%); after {c['repo_common_after']}/{len(repo_set)} ({c['repo_common_after_recall_percent']}%)",
        f"- Lost baseline entries: {len(lost)}; added entries: {len(created)}; targets created: {len(newly_added_targets)}/{len(target_set)}; missing after: {len(missing_targets)}; unexpected extras: {len(extras)}",
        f"- Target statuses: {dict(statuses)}",
        f"- Recovery attempt statuses: {dict(attempt_statuses)}",
        f"- Attempts with disassembly status: {len(attempt_disasm_known)}; disassembly success: {sum(r['disassemble_success'] is True for r in attempt_disasm_known)}",
        f"- Attempts with decompile status: {len(attempt_dec_known)}; decompile success: {sum(r['decompile_success'] is True for r in attempt_dec_known)}; failure: {sum(r['decompile_success'] is False for r in attempt_dec_known)}",
        f"- Created functions with known Thumb mode: {len(mode_known)}; mode != 1: {c['created_thumbmode_non1']}; mode unknown: {c['created_thumbmode_unknown']}",
        f"- Created functions with known decompile status: {len(dec_known)}; success: {c['created_decompile_success']}; failure: {c['created_decompile_failure']}; unknown: {c['created_decompile_unknown']}",
        "",
        summary["caveat"],
        "",
        "## Per-target status", "",
        "| Address | Name | After | Attempt | TMode | Disasm | Decompile |",
        "|---|---|---|---|---:|---|---|",
    ]
    for row in target_rows:
        lines.append(f"| `{row['address']}` | {row['name'] or '—'} | {row['target_status']} | {row['recovery_status']} | {row['tmode'] if row['tmode'] is not None else 'unknown'} | {row['disassemble_success'] if row['disassemble_success'] is not None else 'unknown'} | {row['decompile_success'] if row['decompile_success'] is not None else 'unknown'} |")
    (out / "recovery_report.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
