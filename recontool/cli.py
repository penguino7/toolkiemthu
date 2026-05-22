from __future__ import annotations

import argparse
from pathlib import Path

from .auth import AuthManager
from .config import ConfigLoader
from .crawlers.playwright_dynamic import DynamicCrawler
from .crawlers.static_html import StaticHtmlCrawler
from .dedupe import EndpointDeduplicator
from .exporters import ReconExporter
from .importers.har import HarImporter
from .importers.manual_seed import ManualSeedImporter
from .models import EndpointRecord


RECON_OUTPUT_DIR = Path("recon-output")


def build_parser() -> argparse.ArgumentParser:
    """Tạo parser đơn giản cho recontool."""
    parser = argparse.ArgumentParser(description="Công cụ recon sinh inventory endpoint")

    parser.add_argument("-c", "--config", default="recon.config.example.json", help="File config recon")
    parser.add_argument("--base-url", help="Ghi đè base_url trong config")
    parser.add_argument("--seed", action="append", default=[], help="Thêm seed URL/path")
    parser.add_argument("--har", action="append", default=[], help="Import file HAR")
    parser.add_argument("--manual", action="append", default=[], help="Import file manual seed")
    parser.add_argument("--auth-profile", action="append", default=[], help="Chỉ crawl auth profile được chọn")
    parser.add_argument("--dedupe-mode", choices=["strict", "smart"], help="Chế độ lọc trùng")

    return parser


class ReconApplication:
    """Luồng recon: đọc config -> crawl static/dynamic -> import -> dedupe -> export."""

    def __init__(self) -> None:
        self.config_loader = ConfigLoader()
        self.exporter = ReconExporter()

    def run(self, argv=None) -> int:
        args = build_parser().parse_args(argv)
        config = self._load_config(args)

        records = self._collect_records(config, args.auth_profile)
        records = self._dedupe_records(records, config)
        self.exporter.export_all(records, RECON_OUTPUT_DIR)

        self._print_outputs()
        return 0

    def _load_config(self, args: argparse.Namespace) -> dict:
        config = self.config_loader.load(args.config)

        if args.base_url:
            config["base_url"] = args.base_url
        if args.seed:
            config["seeds"] = args.seed
        if args.dedupe_mode:
            config.setdefault("dedupe", {})["mode"] = args.dedupe_mode

        imports = config.setdefault("imports", {})
        if args.har:
            imports.setdefault("har_files", []).extend(args.har)
        if args.manual:
            imports.setdefault("manual_seed_files", []).extend(args.manual)

        return config

    def _collect_records(self, config: dict, auth_profile_names: list[str]) -> list[EndpointRecord]:
        records = []
        records.extend(self._crawl(config, auth_profile_names))
        records.extend(self._import(config))
        print(f"[*] Tổng số bản ghi thô thu thập được: {len(records)}")
        return records

    def _crawl(self, config: dict, auth_profile_names: list[str]) -> list[EndpointRecord]:
        try:
            auth_manager = AuthManager(config)
            profiles = auth_manager.select_profiles(auth_profile_names)
        except ValueError as error:
            raise SystemExit(f"Lỗi cấu hình Auth: {error}") from error

        print(f"[*] Auth profiles: {auth_manager.profile_names(profiles)}")
        records = []

        for profile in profiles:
            profile_config = auth_manager.config_for_profile(profile)
            auth_context = profile_config.get("auth_context", "anonymous")

            print(f"[*] Static crawl: {auth_context}")
            records.extend(StaticHtmlCrawler(profile_config).crawl())

            print(f"[*] Dynamic crawl: {auth_context}")
            records.extend(DynamicCrawler(profile_config).crawl())

        return records

    def _import(self, config: dict) -> list[EndpointRecord]:
        records = []
        imports = config.get("imports", {})

        for har_file in imports.get("har_files", []):
            print(f"[*] Import HAR: {har_file}")
            records.extend(HarImporter(config).import_file(har_file))

        for manual_file in imports.get("manual_seed_files", []):
            print(f"[*] Import manual seed: {manual_file}")
            records.extend(ManualSeedImporter(config).import_file(manual_file))

        return records

    def _dedupe_records(self, records: list[EndpointRecord], config: dict) -> list[EndpointRecord]:
        mode = config.get("dedupe", {}).get("mode", "smart")
        final_records = EndpointDeduplicator(mode=mode).dedupe(records)
        print(f"[*] Số bản ghi sau khi lọc trùng ({mode}): {len(final_records)}")
        return final_records

    def _print_outputs(self) -> None:
        print(f"[+] Đã lưu file: {RECON_OUTPUT_DIR / 'inventory.json'}")
        print(f"[+] Đã lưu file: {RECON_OUTPUT_DIR / 'params.txt'}")


def main(argv=None) -> int:
    return ReconApplication().run(argv)
