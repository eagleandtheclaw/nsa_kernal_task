#!/usr/bin/env python3
"""Build a crawlable site from the already published public samples."""

import argparse
import hashlib
from html import escape
import json
import lzma
from pathlib import Path
import runpy
import shutil
import subprocess
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
BASE = "https://eagleandtheclaw.github.io"
PUBLIC_CHECKS = runpy.run_path(str(ROOT / "verify_public.py"))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sample(path, process):
    record = json.loads(lzma.decompress(path.read_bytes()))
    body = record["body"]
    report = body["stack_report"]
    if sha256(canonical(body)) != record["body_sha256"]:
        raise ValueError("public body hash mismatch: " + str(path))
    if sha256(report.encode()) != body["stack_report_sha256"]:
        raise ValueError("stack report hash mismatch: " + str(path))
    if any(PUBLIC_CHECKS[name].search(report) for name in ("PRIVATE", "UUID", "ADDRESS")):
        raise ValueError("identifier in public report: " + str(path))
    if body[f"{process}_pid"] != (0 if process == "kernel_task" else 1):
        raise ValueError("unexpected process: " + str(path))
    return body, record["body_sha256"]


def page(title, description, content, url, home_url, updated, feed_url, dataset=None):
    structured = ""
    if dataset is not None:
        structured = '<script type="application/ld+json">' + json.dumps(
            dataset, ensure_ascii=False, separators=(",", ":")
        ).replace("<", "\\u003c") + "</script>"
    return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">" + (
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escape(title)}</title>"
        f'<meta name="description" content="{escape(description, quote=True)}">'
        f'<link rel="canonical" href="{escape(url, quote=True)}">'
        f'<link rel="alternate" type="application/atom+xml" href="{escape(feed_url, quote=True)}">'
        f'<meta property="og:title" content="{escape(title, quote=True)}">'
        f'<meta property="og:description" content="{escape(description, quote=True)}">'
        f'<meta property="og:url" content="{escape(url, quote=True)}">'
        '<style>body{font:17px/1.55 system-ui,sans-serif;max-width:72rem;margin:auto;padding:2rem;color:#17212b}'
        'a{color:#064e8a}pre{overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f5f7;padding:1rem}'
        'nav,footer{border-block:1px solid #d6dce2;padding:.75rem 0}small{color:#4b5563}</style>'
        + structured + f'</head><body><nav><a href="{escape(home_url, quote=True)}">Dataset home</a> · '
        '<a href="https://eagleandtheclaw.github.io/">All public datasets</a> · '
        '<a href="https://github.com/eagleandtheclaw">GitHub owner</a></nav>'
        + content + f'<footer><small>Last public update: {escape(updated)}. '
        'Published samples are observations, not attribution or evidence of compromise.</small></footer>'
        '</body></html>\n'
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, choices=("nsa_kernal_task", "nsa_launchd_task"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    process = "kernel_task" if args.repository == "nsa_kernal_task" else "launchd"
    pid = 0 if process == "kernel_task" else 1
    site = f"{BASE}/{args.repository}/"
    feed_url = site + "feed.xml"
    files = sorted((ROOT / "samples").glob("*/*.json.xz"))
    if not files:
        raise ValueError("no public samples found")
    head = json.loads((ROOT / "PUBLIC_CHAIN_HEAD.json").read_text())
    if len(files) != head["sequence"]:
        raise ValueError("sample count does not match public chain head")
    by_day = {}
    for path in files:
        by_day.setdefault(path.parent.name, []).append(path)
    last_body, last_hash = sample(files[-1], process)
    if last_hash != head["body_sha256"]:
        raise ValueError("last sample does not match public chain head")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    updated = head["updated_at_utc"]
    repo_url = f"https://github.com/eagleandtheclaw/{args.repository}"
    commit = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
    ).strip()
    name = f"macOS {process} (PID {pid}) public stack samples"
    description = (
        f"Sanitized, SHA-256-linked macOS {process} stack samples with UTC capture times, "
        "source records, and a reproducible public verifier."
    )
    dataset = {"@context": "https://schema.org", "@type": "Dataset", "name": name,
               "description": description, "url": site, "dateModified": updated,
               "isAccessibleForFree": True, "identifier": repo_url}
    day_links = []
    sitemap_urls = [(site, updated)]
    entries = []
    for day, day_files in sorted(by_day.items(), reverse=True):
        body, body_hash = sample(day_files[-1], process)
        day_url = site + f"days/{day}.html"
        raw_url = repo_url + "/blob/" + commit + "/" + day_files[-1].relative_to(ROOT).as_posix()
        day_title = f"{process} stack samples for {day}"
        content = (
            f"<main><h1>{escape(day_title)}</h1>"
            f"<p>{len(day_files)} public samples on this UTC date. "
            f"The latest is sequence {body['sequence']}, captured at "
            f"<time datetime=\"{escape(body['capture_started_utc'], quote=True)}\">"
            f"{escape(body['capture_started_utc'])}</time>.</p>"
            f"<p>Public body SHA-256: <code>{body_hash}</code>. "
            f"Stack report SHA-256: <code>{body['stack_report_sha256']}</code>.</p>"
            f'<p><a href="{escape(raw_url, quote=True)}">Source record on GitHub</a> · '
            f'<a href="{repo_url}/tree/main/samples/{day}">All records for this date</a></p>'
            "<h2>Latest sanitized stack report for this date</h2>"
            f"<pre>{escape(body['stack_report'])}</pre></main>"
        )
        target = output / "days" / f"{day}.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(page(day_title, f"{len(day_files)} sanitized {process} stack samples captured on {day}.",
                               content, day_url, site, updated, feed_url), encoding="utf-8")
        day_links.append(f'<li><a href="days/{day}.html">{day}</a>: {len(day_files)} samples, '
                         f"latest sequence {body['sequence']}</li>")
        sitemap_urls.append((day_url, body["capture_started_utc"]))
        entries.append((day_title, day_url, body["capture_started_utc"],
                        f"{len(day_files)} public {process} stack samples."))
    home = (
        f"<main><h1>{escape(name)}</h1><p>{escape(description)}</p>"
        f"<p><strong>Latest public sequence:</strong> {head['sequence']}; "
        f"<strong>latest capture:</strong> {escape(last_body['capture_started_utc'])}. "
        f"<a href=\"days/{sorted(by_day)[-1]}.html\">Read the latest dated page</a>.</p>"
        "<h2>What these records show</h2><p>Each record contains a sanitized stack report "
        "from one sampling window. The public hashes link records and allow local consistency "
        "checks. The private originals are not published here. Samples do not establish "
        "continuous monitoring, attribution, or compromise.</p>"
        f'<p><a href="{repo_url}">Public repository and methodology</a> · '
        f'<a href="{repo_url}/blob/main/verify_public.py">Verifier</a> · '
        f'<a href="{repo_url}/blob/main/mine_samples.py">Incremental JSONL extractor</a> · '
        f'<a href="{site}sitemap.xml">Sitemap</a> · <a href="{feed_url}">Atom feed</a></p>'
        "<h2>Browse by UTC date</h2><ul>" + "".join(day_links) + "</ul></main>"
    )
    (output / "index.html").write_text(page(name, description, home, site, site, updated,
                                            feed_url, dataset), encoding="utf-8")
    (output / "llms.txt").write_text(
        f"# {name}\n\n{description}\n\n- [Dataset home]({site})\n"
        f"- [Latest dated sample]({site}days/{sorted(by_day)[-1]}.html)\n"
        f"- [Public source and miner]({repo_url})\n", encoding="utf-8")
    xml_ns = "http://www.sitemaps.org/schemas/sitemap/0.9"
    ET.register_namespace("", xml_ns)
    urlset = ET.Element(f"{{{xml_ns}}}urlset")
    for url, modified in sitemap_urls:
        item = ET.SubElement(urlset, f"{{{xml_ns}}}url")
        ET.SubElement(item, f"{{{xml_ns}}}loc").text = url
        ET.SubElement(item, f"{{{xml_ns}}}lastmod").text = modified
    ET.ElementTree(urlset).write(output / "sitemap.xml", encoding="utf-8", xml_declaration=True)
    atom_ns = "http://www.w3.org/2005/Atom"
    ET.register_namespace("", atom_ns)
    feed = ET.Element(f"{{{atom_ns}}}feed")
    ET.SubElement(feed, f"{{{atom_ns}}}title").text = name
    ET.SubElement(feed, f"{{{atom_ns}}}id").text = site
    ET.SubElement(feed, f"{{{atom_ns}}}updated").text = updated
    ET.SubElement(feed, f"{{{atom_ns}}}link", href=site)
    for title, url, captured, summary in entries:
        entry = ET.SubElement(feed, f"{{{atom_ns}}}entry")
        ET.SubElement(entry, f"{{{atom_ns}}}title").text = title
        ET.SubElement(entry, f"{{{atom_ns}}}id").text = url
        ET.SubElement(entry, f"{{{atom_ns}}}link", href=url)
        ET.SubElement(entry, f"{{{atom_ns}}}updated").text = captured
        ET.SubElement(entry, f"{{{atom_ns}}}summary").text = summary
    ET.ElementTree(feed).write(output / "feed.xml", encoding="utf-8", xml_declaration=True)
    shutil.copyfile(ROOT / "PUBLIC_CHAIN_HEAD.json", output / "PUBLIC_CHAIN_HEAD.json")
    key = (ROOT / "site" / "indexnow-key.txt").read_text().strip()
    if len(key) != 32 or any(char not in "0123456789abcdef" for char in key):
        raise ValueError("invalid public IndexNow key")
    (output / f"{key}.txt").write_text(key, encoding="utf-8")
    (output / "indexnow.json").write_text(json.dumps({
        "host": "eagleandtheclaw.github.io",
        "key": key,
        "keyLocation": site + f"{key}.txt",
        "urlList": [site, site + f"days/{sorted(by_day)[-1]}.html"],
    }, separators=(",", ":")), encoding="utf-8")
    print(f"built {args.repository}: {len(files)} samples, {len(by_day)} dated pages")


if __name__ == "__main__":
    main()
