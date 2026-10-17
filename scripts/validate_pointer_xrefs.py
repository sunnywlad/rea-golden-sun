#!/usr/bin/env python3
"""Validate saved odd-pointer xrefs against ROM words and repo data ranges."""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

BASE = 0x08000000


def num(text):
    return int(text.strip(), 0)


def data_ranges(root):
    ranges = []
    for path in sorted(Path(root).rglob("*.s")):
        if "overlays" in path.parts:
            continue
        section = ""
        for lineno, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
            line = raw.split("@", 1)[0].strip()
            match = re.match(r"\.section\s+([^,\s]+)", line)
            if match:
                section = match.group(1)
            if not (section.startswith(".rodata") or section.startswith(".data")):
                continue
            match = re.match(r"\.incrom\s+([^,]+),\s*([^,\s]+)", line)
            kind = "incrom"
            if not match:
                match = re.match(r"\.incdata\s+[^,]+,\s*([^,]+),\s*([^,\s]+)", line)
                kind = "incdata"
            if match:
                start, end = map(num, match.groups())
                if end > start:
                    ranges.append({
                        "start": start, "end": end, "path": str(path),
                        "line": lineno, "kind": kind, "section": section,
                    })
    return ranges


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidates")
    parser.add_argument("xrefs")
    parser.add_argument("rom")
    parser.add_argument("repo_dir")
    parser.add_argument("out_json")
    parser.add_argument("--extra-xrefs", help="additional envelopes for targets absent from pointer scan")
    args = parser.parse_args()

    cand_doc = json.loads(Path(args.candidates).read_text())
    candidates = cand_doc["candidates"]
    xrefs = json.loads(Path(args.xrefs).read_text())
    extra_xrefs = json.loads(Path(args.extra_xrefs).read_text()) if args.extra_xrefs else []
    rom = Path(args.rom).read_bytes()
    if hashlib.sha1(rom).hexdigest() != cand_doc["rom_sha1"]:
        raise ValueError("ROM SHA1 does not match the candidate inventory")
    for row in candidates:
        for source in row["sources"]:
            offset = int(source, 16) - BASE
            if offset < 0 or offset + 4 > len(rom) or offset % 4:
                raise ValueError(f"Invalid aligned pointer source: {source}")
            if struct.unpack_from("<I", rom, offset)[0] != int(row["pointer_value"], 16):
                raise ValueError(f"Pointer word differs at {source}")
    ranges = data_ranges(args.repo_dir)
    raw_sources = {int(src, 16) for row in candidates for src in row["sources"]}
    by_target = {}
    for envelope in xrefs + extra_xrefs:
        target = int(envelope["address"], 16) & ~1
        result = envelope.get("result", {})
        if envelope.get("isError") or result.get("isError"):
            status, refs = "error", []
        else:
            evidence = result.get("structuredContent", {})
            refs = evidence.get("normalized_result") if isinstance(evidence, dict) else None
            if not isinstance(refs, list):
                texts = [b.get("text", "") for b in result.get("content", [])
                         if isinstance(b, dict) and b.get("type") == "text"]
                decoded = []
                for text in texts:
                    try:
                        decoded.append(json.loads(text))
                    except (json.JSONDecodeError, TypeError):
                        pass
                decoded = next((d for d in decoded if isinstance(d, dict)
                                and isinstance(d.get("normalized_result"), list)), None)
                refs = decoded["normalized_result"] if decoded else None
            status = "positive" if isinstance(refs, list) and refs else (
                "negative" if isinstance(refs, list) else "error")
        by_target[target] = {"status": status, "sources": refs if status == "positive" else []}

    positives, recovered, missing_pointer_negative = [], [], []
    exact_target_count = exact_source_count = all_raw_source_count = xref_source_count = 0
    outside_rom_source_count = 0
    rom_end = BASE + len(rom)
    for row in candidates:
        target = int(row["address"], 16)
        envelope = by_target.get(target, {"status": "unqueried", "sources": []})
        if row["classification"] == "repo_thumb" and row["missing"]:
            if row["sources"]:
                if envelope["status"] == "positive":
                    recovered.append(row["address"])
                elif envelope["status"] == "negative":
                    missing_pointer_negative.append(row["address"])
        if envelope["status"] != "positive":
            continue
        refs = {int(value, 16) for value in envelope["sources"]
                if isinstance(value, str) and value.startswith("0x")}
        words = {int(value, 16) for value in row["sources"]}
        matched = refs & words
        xref_source_count += len(refs)
        exact_source_count += len(matched)
        all_raw_source_count += len(refs & raw_sources)
        outside_rom_source_count += sum(1 for source in refs if not BASE <= source < rom_end)
        exact_target_count += bool(matched)
        record = {
            "address": row["address"], "classification": row["classification"],
            "in_rea": row["in_rea"], "xref_sources": sorted(hex(v) for v in refs),
            "exact_pointer_sources": sorted(hex(v) for v in matched),
        }
        if row["classification"] == "unknown":
            hits = [r for r in ranges if r["start"] <= target - BASE < r["end"]]
            record["repo_data_ranges"] = [
                {"path": hit["path"], "line": hit["line"], "kind": hit["kind"],
                 "section": hit["section"], "start": hex(BASE + hit["start"]),
                 "end": hex(BASE + hit["end"])} for hit in hits
            ]
            record["data_confirmed"] = bool(hits)
            if hits:
                record["classification"] = "repo_data"
        positives.append(record)

    missing_thumb = cand_doc.get("missing_thumb_functions", [])
    targets = {int(row["address"], 16): row for row in candidates}
    pointer_missing = [m for m in missing_thumb if int(m["address"], 16) in targets]
    no_pointer_missing = [m for m in missing_thumb if int(m["address"], 16) not in targets]
    no_pointer_positive = [m["address"] for m in no_pointer_missing
                           if by_target.get(int(m["address"], 16), {}).get("status") == "positive"]
    no_pointer_errors = sum(1 for m in no_pointer_missing
                            if by_target.get(int(m["address"], 16), {}).get("status") == "error")
    no_pointer_negative = sum(1 for m in no_pointer_missing
                              if by_target.get(int(m["address"], 16), {}).get("status") == "negative")
    errors = sum(1 for t in targets if by_target.get(t, {}).get("status") == "error")
    negative = sum(1 for t in targets if by_target.get(t, {}).get("status") == "negative")
    output = {
        "rom_sha1": hashlib.sha1(rom).hexdigest(),
        "procs_sha256": cand_doc["procs_sha256"],
        "counts": {
            "candidates": len(candidates), "queries": len(by_target),
            "positive": sum(1 for t in targets if by_target.get(t, {}).get("status") == "positive"),
            "negative": negative, "error": errors,
            "missing_thumb_total": len(missing_thumb),
            "missing_thumb_with_odd_pointer": len(pointer_missing),
            "missing_thumb_positive_xrefs": len(recovered),
            "missing_thumb_pointer_negative": len(missing_pointer_negative),
            "missing_thumb_without_odd_pointer": len(no_pointer_missing),
            "missing_thumb_without_pointer_positive_xrefs": len(no_pointer_positive),
            "missing_thumb_without_pointer_negative_xrefs": no_pointer_negative,
            "missing_thumb_without_pointer_errors": no_pointer_errors,
            "positive_target_exact_pointer_source": exact_target_count,
            "positive_target_without_exact_pointer_source": len(positives) - exact_target_count,
            "positive_xref_sources": xref_source_count,
            "positive_xref_sources_matching_any_odd_pointer_word": all_raw_source_count,
            "positive_xref_sources_matching_target_pointer_word": exact_source_count,
            "positive_xref_sources_not_any_odd_pointer_word": xref_source_count - all_raw_source_count,
            "positive_xref_sources_outside_rom": outside_rom_source_count,
            "unknown_positive_total": sum(1 for p in positives if p["classification"] == "unknown" or p["classification"] == "repo_data"),
            "unknown_positive_data_confirmed": sum(1 for p in positives if p["classification"] == "repo_data"),
            "unknown_positive_still_unknown": sum(1 for p in positives if p["classification"] == "unknown"),
        },
        "missing_thumb_recovered": recovered,
        "missing_thumb_pointer_negative": missing_pointer_negative,
        "missing_thumb_without_pointer_positive": no_pointer_positive,
        "positive_targets": positives,
        "data_ranges_scanned": len(ranges),
    }
    Path(args.out_json).write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
