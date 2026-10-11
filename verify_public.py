#!/usr/bin/python3
"""Verify the local public derivative chain and reject direct identifiers."""

import hashlib
import json
import lzma
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent
PRIVATE = re.compile(
    r"(?i)(/Users/|/Volumes/|/private/var/|"
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|"
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])|"
    r"(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])|"
    r"\b(?:password|secret|credential|api[_ -]?key)\b)"
)
UUID = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
ADDRESS = re.compile(r"(?i)0x[0-9a-f]+")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def main():
    files = sorted((ROOT / "samples").glob("*/*.json.xz"))
    head = json.loads((ROOT / "PUBLIC_CHAIN_HEAD.json").read_text())
    previous = "0" * 64
    for number, path in enumerate(files, 1):
        packed = path.read_bytes()
        if len(packed) > 2_000_000:
            raise RuntimeError("oversize public sample: " + path.name)
        record = json.loads(lzma.decompress(packed))
        body = record["body"]
        if body["sequence"] != number or int(path.name.split("_", 1)[0]) != number:
            raise RuntimeError("sequence gap at " + path.name)
        if body["previous_public_body_sha256"] != previous:
            raise RuntimeError("chain break at " + path.name)
        if body["kernel_task_pid"] != 0 or body["kernel_task_num_samples"] < 1:
            raise RuntimeError("invalid kernel_task sample at " + path.name)
        report = body["stack_report"]
        if PRIVATE.search(report) or UUID.search(report) or ADDRESS.search(report):
            raise RuntimeError("identifier in report " + path.name)
        if sha256(report.encode()) != body["stack_report_sha256"]:
            raise RuntimeError("report hash mismatch at " + path.name)
        previous = sha256(canonical(body))
        if previous != record["body_sha256"]:
            raise RuntimeError("body hash mismatch at " + path.name)
    if len(files) != head["sequence"] or previous != head["body_sha256"]:
        raise RuntimeError("public chain head mismatch")
    print("PASS %d sanitized kernel_task samples; chain head %s" % (len(files), previous))


if __name__ == "__main__":
    main()
