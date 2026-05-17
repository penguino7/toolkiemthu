from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

from .auth import AuthManager
from .config import ConfigLoader
from .crawlers.playwright_dynamic import DynamicCrawler
from .crawlers.static_html import StaticHtmlCrawler
from .dedupe import EndpointDeduplicator
from .enrich import RecordEnricher
from .exporters import ReconExporter
from .importers.har import HarImporter
from .importers.manual_seed import ManualSeedImporter
from .models import EndpointRecord


class CliArgumentParser:
    """Tạo argparse parser cho command line."""

    def build(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Generic recon inventory tool")
        parser.add_argument("-c", "--config", help="Đường dẫn file config JSON")
        parser.add_argument("-o", "--out", help="Thư mục output")
        parser.add_argument("--base-url", help="Override base_url")
        parser.add_argument("--seed", action="append", default=[], help="Thêm seed URL/path")
        parser.add_argument("--har", action="append", default=[], help="Import HAR file")
        parser.add_argument("--manual", action="append", default=[], help="Import manual seed file")
        parser.add_argument("--no-static", action="store_true", help="Tắt static crawler")
        parser.add_argument("--dynamic", action="store_true", help="Bật Playwright dynamic crawler")
        parser.add_argument("--auth-profile", action="append", default=[], help="Chỉ crawl auth profile có tên tương ứng")
        parser.add_argument("--dedupe-mode", choices=["strict", "smart"], help="Chế độ dedupe")
        return parser


class ReconApplication:
    """Điều phối toàn bộ pipeline recon.

    CLI chỉ là lớp mỏng. Mọi bước chính được đặt trong class này để luồng chạy
    dễ đọc theo thứ tự: load config -> crawl/import -> enrich -> dedupe -> export.
    """

    def __init__(
        self,
        config_loader: ConfigLoader | None = None,
        parser_builder: CliArgumentParser | None = None,
        enricher: RecordEnricher | None = None,
        exporter: ReconExporter | None = None,
    ) -> None:
        self.config_loader = config_loader or ConfigLoader()
        self.parser_builder = parser_builder or CliArgumentParser()
        self.enricher = enricher or RecordEnricher()
        self.exporter = exporter or ReconExporter()

    def run(self, argv=None) -> int:
        args = self.parser_builder.build().parse_args(argv)
        config = self.config_loader.load(args.config)
        self._apply_cli_overrides(config, args)

        all_records = self._collect_records(config, args)
        print(f"[*] Raw records: {len(all_records)}")

        enriched = self.enricher.enrich_many(all_records)
        mode = config.get("dedupe", {}).get("mode", "smart")
        merged = EndpointDeduplicator(mode=mode).dedupe(enriched)
        print(f"[*] Records after dedupe ({mode}): {len(merged)}")

        output_dir = Path(config.get("output_dir", "recon-output"))
        self.exporter.export_all(merged, output_dir)
        self._print_outputs(output_dir)
        return 0

    def _apply_cli_overrides(self, config: dict, args: argparse.Namespace) -> None:
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

    def _collect_records(self, config: dict, args: argparse.Namespace) -> List[EndpointRecord]:
        records: List[EndpointRecord] = []
        records.extend(self._run_crawlers(config, args))
        records.extend(self._run_importers(config))
        return records

    def _run_crawlers(self, config: dict, args: argparse.Namespace) -> List[EndpointRecord]:
        records: List[EndpointRecord] = []
        run_static = config.get("static", {}).get("enabled", True)
        run_dynamic = config.get("dynamic", {}).get("enabled", False)

        if not run_static and not run_dynamic:
            return records

        auth_manager = AuthManager(config)
        try:
            profiles = auth_manager.select_profiles(args.auth_profile)
        except ValueError as error:
            raise SystemExit(str(error)) from error

        print(f"[*] Auth profiles: {auth_manager.profile_names(profiles)}")
        for profile in profiles:
            profile_config = auth_manager.config_for_profile(profile)
            auth_context = profile_config.get("auth_context", "anonymous")

            if run_static:
                print(f"[*] Running static crawler as {auth_context}...")
                records.extend(StaticHtmlCrawler(profile_config).crawl())

            if run_dynamic:
                print(f"[*] Running Playwright dynamic crawler as {auth_context}...")
                records.extend(DynamicCrawler(profile_config).crawl())

        return records

    def _run_importers(self, config: dict) -> List[EndpointRecord]:
        records: List[EndpointRecord] = []

        for har_file in config.get("imports", {}).get("har_files", []):
            print(f"[*] Importing HAR: {har_file}")
            records.extend(HarImporter(config).import_file(har_file))

        for manual_file in config.get("imports", {}).get("manual_seed_files", []):
            print(f"[*] Importing manual seeds: {manual_file}")
            records.extend(ManualSeedImporter(config).import_file(manual_file))

        return records

    def _print_outputs(self, output_dir: Path) -> None:
        print(f"[*] Wrote: {output_dir / 'inventory.json'}")
        print(f"[*] Wrote: {output_dir / 'inventory.md'}")
        print(f"[*] Wrote: {output_dir / 'params.txt'}")
        print(f"[*] Wrote: {output_dir / 'test_plan.md'}")


def build_parser() -> argparse.ArgumentParser:
    return CliArgumentParser().build()


def main(argv=None) -> int:
    return ReconApplication().run(argv)
