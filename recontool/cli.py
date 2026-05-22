from __future__ import annotations 

import argparse
from pathlib import Path

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


def build_parser() -> argparse.ArgumentParser:
    """Tạo parser dòng lệnh cho recontool với các nhóm logic rõ ràng."""
    parser = argparse.ArgumentParser(description="Công cụ recon sinh inventory endpoint")

    # Nhóm 1: Cấu hình cơ bản (I/O)
    io_group = parser.add_argument_group("Cấu hình Đầu vào / Đầu ra")
    io_group.add_argument("-c", "--config", help="Đường dẫn file config JSON")
    io_group.add_argument("-o", "--out", help="Thư mục output")
    io_group.add_argument("--base-url", help="Ghi đè base_url trong config")

    # Nhóm 2: Nguồn dữ liệu (Seeds & Imports)
    seed_group = parser.add_argument_group("Nguồn dữ liệu bổ sung")
    seed_group.add_argument("--seed", action="append", default=[], help="Thêm seed URL/path")
    seed_group.add_argument("--har", action="append", default=[], help="Import file HAR")
    seed_group.add_argument("--manual", action="append", default=[], help="Import file manual seed")

    # Nhóm 3: Cấu hình Crawler & Xử lý
    crawl_group = parser.add_argument_group("Cấu hình Thu thập & Xử lý")
    crawl_group.add_argument("--no-static", action="store_true", help="Tắt static crawler")
    crawl_group.add_argument("--dynamic", action="store_true", help="Bật Playwright dynamic crawler")
    crawl_group.add_argument("--auth-profile", action="append", default=[], help="Chỉ crawl auth profile được chọn")
    crawl_group.add_argument("--dedupe-mode", choices=["strict", "smart"], help="Chế độ lọc trùng")

    return parser


class ReconApplication:
    """Điều phối luồng recon: đọc config -> crawl/import -> lọc trùng -> xuất file."""

    def __init__(self) -> None:
        self.config_loader = ConfigLoader()
        self.enricher = RecordEnricher()
        self.exporter = ReconExporter()

    def run(self, argv=None) -> int:
        args = build_parser().parse_args(argv)
        config = self._load_config(args)

        records = self._collect_records(config, args.auth_profile)
        records = self._enrich_and_dedupe(records, config)
        output_dir = self._export(records, config)

        self._print_outputs(output_dir)
        return 0

    def _load_config(self, args: argparse.Namespace) -> dict:
        config = self.config_loader.load(args.config)

        # 1. Ghi đè các cấu hình mức cao (Top-level configs)
        overrides = {
            "base_url": args.base_url,
            "seeds": args.seed or None,
            "output_dir": args.out,
        }
        for key, value in overrides.items():
            if value:
                config[key] = value

        # 2. Ghi đè các cấu hình lồng nhau (Nested configs)
        if args.no_static:
            config.setdefault("static", {})["enabled"] = False
        if args.dynamic:
            config.setdefault("dynamic", {})["enabled"] = True
        if args.dedupe_mode:
            config.setdefault("dedupe", {})["mode"] = args.dedupe_mode

        # 3. Ghi đè cấu hình Imports
        imports = config.setdefault("imports", {})
        if args.har: imports.setdefault("har_files", []).extend(args.har)
        if args.manual: imports.setdefault("manual_seed_files", []).extend(args.manual)

        return config

    def _collect_records(self, config: dict, auth_profile_names: list[str]) -> list[EndpointRecord]:
        records = []
        records.extend(self._crawl(config, auth_profile_names))
        records.extend(self._import(config))
        print(f"[*] Tổng số bản ghi thô thu thập được: {len(records)}")
        return records

    def _crawl(self, config: dict, auth_profile_names: list[str]) -> list[EndpointRecord]:
        run_static = config.get("static", {}).get("enabled", True)
        run_dynamic = config.get("dynamic", {}).get("enabled", False)

        if not (run_static or run_dynamic):
            return []

        try:
            auth_manager = AuthManager(config)
            profiles = auth_manager.select_profiles(auth_profile_names)
        except ValueError as error:
            raise SystemExit(f"Lỗi cấu hình Auth: {error}") from error

        print(f"[*] Đang chạy Crawler với các hồ sơ auth: {auth_manager.profile_names(profiles)}")
        records = []

        for profile in profiles:
            p_config = auth_manager.config_for_profile(profile)
            ctx = p_config.get("auth_context", "anonymous")

            if run_static:
                print(f"  -> [Static] Quét HTML thuần (Context: {ctx})...")
                records.extend(StaticHtmlCrawler(p_config).crawl())

            if run_dynamic:
                print(f"  -> [Dynamic] Quét bằng Playwright (Context: {ctx})...")
                records.extend(DynamicCrawler(p_config).crawl())

        return records

    def _import(self, config: dict) -> list[EndpointRecord]:
        records = []
        imports = config.get("imports", {})

        for har_file in imports.get("har_files", []):
            print(f"[*] Import dữ liệu từ HAR: {har_file}")
            records.extend(HarImporter(config).import_file(har_file))

        for manual_file in imports.get("manual_seed_files", []):
            print(f"[*] Import danh sách URL mồi: {manual_file}")
            records.extend(ManualSeedImporter(config).import_file(manual_file))

        return records

    def _enrich_and_dedupe(self, records: list[EndpointRecord], config: dict) -> list[EndpointRecord]:
        mode = config.get("dedupe", {}).get("mode", "smart")

        enriched_records = self.enricher.enrich_many(records)
        final_records = EndpointDeduplicator(mode=mode).dedupe(enriched_records)

        print(f"[*] Số bản ghi sau khi lọc trùng (Chế độ: {mode}): {len(final_records)}")
        return final_records

    def _export(self, records: list[EndpointRecord], config: dict) -> Path:
        output_dir = Path(config.get("output_dir", "recon-output"))
        self.exporter.export_all(records, output_dir)
        return output_dir

    def _print_outputs(self, output_dir: Path) -> None:
        files = ["inventory.json", "inventory.md", "params.txt", "test_plan.md"]
        for filename in files:
            print(f"[+] Đã lưu file: {output_dir / filename}")


def main(argv=None) -> int:
    return ReconApplication().run(argv)
