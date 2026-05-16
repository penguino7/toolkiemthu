from __future__ import annotations

import argparse
from pathlib import Path

from .config import load_config
from .crawlers.playwright_dynamic import crawl_dynamic
from .crawlers.static_html import crawl_static
from .dedupe import dedupe
from .enrich import enrich_records
from .exporters import export_all
from .importers.har import import_har
from .importers.manual_seed import import_manual_seed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generic recon inventory tool")
    parser.add_argument("-c", "--config", help="Đường dẫn file config JSON")
    parser.add_argument("-o", "--out", help="Thư mục output")
    parser.add_argument("--base-url", help="Override base_url")
    parser.add_argument("--seed", action="append", default=[], help="Thêm seed URL/path")
    parser.add_argument("--har", action="append", default=[], help="Import HAR file")
    parser.add_argument("--manual", action="append", default=[], help="Import manual seed file")
    parser.add_argument("--no-static", action="store_true", help="Tắt static crawler")
    parser.add_argument("--dynamic", action="store_true", help="Bật Playwright dynamic crawler")
    parser.add_argument("--dedupe-mode", choices=["strict", "smart"], help="Chế độ dedupe")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config)

    if args.base_url:
        config["base_url"] = args.base_url
    if args.seed:
        config["seeds"] = args.seed
    if args.out:
        config["output_dir"] = args.out
    if args.no_static:
        config.setdefault("static", {})["enabled"] = False
    if args.dynamic:
        config.setdefault("dynamic", {})["enabled"] = True
    if args.dedupe_mode:
        config.setdefault("dedupe", {})["mode"] = args.dedupe_mode
    if args.har:
        config.setdefault("imports", {}).setdefault("har_files", [])
        config["imports"]["har_files"].extend(args.har)
    if args.manual:
        config.setdefault("imports", {}).setdefault("manual_seed_files", [])
        config["imports"]["manual_seed_files"].extend(args.manual)

    all_records = []

    if config.get("static", {}).get("enabled", True):
        print("[*] Running static crawler...")
        all_records.extend(crawl_static(config))

    if config.get("dynamic", {}).get("enabled", False):
        print("[*] Running Playwright dynamic crawler...")
        all_records.extend(crawl_dynamic(config))

    for har_file in config.get("imports", {}).get("har_files", []):
        print(f"[*] Importing HAR: {har_file}")
        all_records.extend(import_har(har_file, config))

    for manual_file in config.get("imports", {}).get("manual_seed_files", []):
        print(f"[*] Importing manual seeds: {manual_file}")
        all_records.extend(import_manual_seed(manual_file, config))

    print(f"[*] Raw records: {len(all_records)}")
    enriched = enrich_records(all_records)
    mode = config.get("dedupe", {}).get("mode", "smart")
    merged = dedupe(enriched, mode=mode)
    print(f"[*] Records after dedupe ({mode}): {len(merged)}")

    output_dir = Path(config.get("output_dir", "recon-output"))
    export_all(merged, output_dir)
    print(f"[*] Wrote: {output_dir / 'inventory.json'}")
    print(f"[*] Wrote: {output_dir / 'inventory.md'}")
    print(f"[*] Wrote: {output_dir / 'params.txt'}")
    return 0
