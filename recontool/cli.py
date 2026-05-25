from __future__ import annotations

import argparse
from pathlib import Path

from toolcli.table import ConsoleTable

from .config import ConfigLoader
from .crawlers.playwright_dynamic import DynamicCrawler
from .crawlers.static_html import StaticHtmlCrawler
from .dedupe import EndpointDeduplicator
from .exporters import ReconExporter
from .models import EndpointRecord


RECON_OUTPUT_DIR = Path("recon-output")


def build_parser() -> argparse.ArgumentParser:
    """Tạo parser đơn giản cho recontool."""
    parser = argparse.ArgumentParser(description="Công cụ recon sinh inventory endpoint")

    parser.add_argument("-c", "--config", default="recon.config.example.json", help="File config recon")
    parser.add_argument("--base-url", help="Ghi đè base_url trong config")
    parser.add_argument("--seed", action="append", default=[], help="Thêm seed URL/path")
    parser.add_argument("--dedupe-mode", choices=["strict", "smart"], help="Chế độ lọc trùng")

    return parser


class ReconApplication:
    """Luồng recon: đọc config -> crawl static/dynamic -> dedupe -> export."""

    def __init__(self) -> None:
        self.config_loader = ConfigLoader()
        self.exporter = ReconExporter()

    def run(self, argv=None) -> int:
        args = build_parser().parse_args(argv)
        config = self._load_config(args)

        records = self._collect_records(config)
        records = self._dedupe_records(records, config)
        ReconEndpointTablePrinter().show(records)
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

        return config

    def _collect_records(self, config: dict) -> list[EndpointRecord]:
        records = []
        records.extend(self._crawl(config))
        print(f"[*] Tổng số bản ghi thô thu thập được: {len(records)}")
        return records

    def _crawl(self, config: dict) -> list[EndpointRecord]:
        records = []

        print("[*] Static crawl")
        records.extend(StaticHtmlCrawler(config).crawl())

        print("[*] Dynamic crawl")
        records.extend(DynamicCrawler(config).crawl())

        return records

    def _dedupe_records(self, records: list[EndpointRecord], config: dict) -> list[EndpointRecord]:
        mode = config.get("dedupe", {}).get("mode", "smart")
        final_records = EndpointDeduplicator(mode=mode).dedupe(records)
        print(f"[*] Số bản ghi sau khi lọc trùng ({mode}): {len(final_records)}")
        return final_records

    def _print_outputs(self) -> None:
        print(f"[+] Đã lưu file: {RECON_OUTPUT_DIR / 'inventory.json'}")
        print(f"[+] Đã lưu file: {RECON_OUTPUT_DIR / 'params.txt'}")


class ReconEndpointTablePrinter:
    COLUMNS = [
        ("No", 4),
        ("Method", 6),
        ("Endpoint/url", 34),
        ("Param", 18),
        ("Where", 8),
        ("Type", 8),
        ("Sample", 20),
        ("Status", 8),
        ("Source", 14),
        ("Seen", 5),
    ]

    def __init__(self) -> None:
        self.table = ConsoleTable("RECON ENDPOINT INVENTORY", self.COLUMNS)

    def show(self, records: list[EndpointRecord]) -> None:
        self.table.start()
        row_number = 0
        for record in records:
            params = sorted(record.params.values(), key=lambda param: param.key)
            if not params:
                row_number += 1
                self._print_row(row_number, record, None)
                continue

            for param in params:
                row_number += 1
                self._print_row(row_number, record, param)

        if row_number == 0:
            self.table.print_row(["-", "-", "No endpoint collected", "-", "-", "-", "-", "-", "-", "-"])
        self.table.finish()

    def _print_row(self, row_number: int, record: EndpointRecord, param) -> None:
        row = [
            row_number,
            record.method,
            record.canonical_path or record.path or record.url,
            param.name if param else "-",
            param.location if param else "-",
            param.type_hint if param else "-",
            self._sample(param),
            ",".join(str(status) for status in record.statuses) or "-",
            self._source(record),
            record.seen_count,
        ]
        self.table.print_row(row)

    def _sample(self, param) -> str:
        if not param or not param.sample_values:
            return "-"
        return ", ".join(param.sample_values[:2])

    def _source(self, record: EndpointRecord) -> str:
        sources = []
        for source in record.source_tools:
            if "playwright" in source:
                sources.append("dynamic")
            elif "static" in source:
                sources.append("static")
            else:
                sources.append(source)
        return ",".join(sorted(set(sources))) or "-"


def main(argv=None) -> int:
    return ReconApplication().run(argv)
