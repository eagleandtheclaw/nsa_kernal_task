#!/usr/bin/env python3
"""Emit verified public samples as JSONL for incremental indexing."""

import argparse
import hashlib
import json
import lzma
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent
REPOSITORY = "nsa_kernal_task"
PROCESS = "kernel_task"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", type=int, default=0, help="last indexed sequence")
    parser.add_argument("--limit", type=int, default=100, help="maximum records to emit")
    args = parser.parse_args()
    if args.since < 0 or args.limit < 1:
        parser.error("--since must be nonnegative and --limit must be positive")

    paths = sorted((ROOT / "samples").glob("*/*.json.xz"))
    commit = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
    ).strip()
    emitted = 0
    previous = "0" * 64 if args.since == 0 else None
    expected = args.since + 1
    for path in paths:
        sequence = int(path.name.split("_", 1)[0])
        if sequence < args.since:
            continue
        record = json.loads(lzma.decompress(path.read_bytes()))
        body = record["body"]
        if sequence != body["sequence"]:
            raise ValueError("sequence mismatch: " + str(path))
        if sha256(canonical(body)) != record["body_sha256"]:
            raise ValueError("body hash mismatch: " + str(path))
        report = body["stack_report"]
        if sha256(report.encode()) != body["stack_report_sha256"]:
            raise ValueError("report hash mismatch: " + str(path))
        if sequence == args.since:
            previous = record["body_sha256"]
            continue
        if sequence != expected:
            raise ValueError("sequence gap before: " + str(path))
        if previous is None:
            raise ValueError("last indexed sequence is missing locally")
        if body["previous_public_body_sha256"] != previous:
            raise ValueError("chain mismatch: " + str(path))
        previous = record["body_sha256"]
        expected += 1
        relative = path.relative_to(ROOT).as_posix()
        print(json.dumps({
            "repository": REPOSITORY,
            "process": PROCESS,
            "sequence": sequence,
            "capture_started_utc": body["capture_started_utc"],
            "source_url": f"https://github.com/eagleandtheclaw/{REPOSITORY}/blob/{commit}/{relative}",
            "public_body_sha256": record["body_sha256"],
            "stack_report_sha256": body["stack_report_sha256"],
            "stack_report": report,
        }, ensure_ascii=False))
        emitted += 1
        if emitted >= args.limit:
            break


if __name__ == "__main__":
    main()
