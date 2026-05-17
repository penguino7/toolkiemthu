from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

from .config import FuzzConfigLoader
from .http_client import FuzzHttpClient, RequestBudgetExceeded
from .inventory_loader import InventoryLoader
from .models import Finding, FuzzTarget
from .plugins.sqli.runner import SqliRunner
from .plugins.xss.runner import XssRunner
from .reporter import FuzzReporter


class FuzzCliParser:
    """Parser dòng lệnh cho fuzztool."""

    def build(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Fuzz tool đọc inventory.json từ recontool")
        parser.add_argument("inventory", help="Đường dẫn inventory.json sinh bởi recontool")
        parser.add_argument("-c", "--config", default="fuzz.config.example.json", help="File config fuzz")
        parser.add_argument("-o", "--out", help="Thư mục output")
        parser.add_argument("--xss", action="store_true", help="Bật nhóm XSS")
        parser.add_argument("--xss-reflected", action="store_true", help="Bật reflected XSS")
        parser.add_argument("--xss-stored", action="store_true", help="Bật stored XSS")
        parser.add_argument("--xss-dom", action="store_true", help="Bật DOM XSS")
        parser.add_argument("--sqli", action="store_true", help="Bật nhóm SQLi")
        parser.add_argument("--sqli-error", action="store_true", help="Bật SQLi error-based")
        parser.add_argument("--sqli-boolean", action="store_true", help="Bật SQLi boolean-based")
        parser.add_argument("--sqli-time", action="store_true", help="Bật SQLi time-based")
        parser.add_argument("--include-post", action="store_true", help="Cho phép fuzz body/json POST")
        parser.add_argument("--max-requests", type=int, help="Giới hạn số request fuzz")
        parser.add_argument("--dry-run", action="store_true", help="Chỉ liệt kê target, không gửi request")
        return parser


class FuzzApplication:
    """Điều phối pipeline fuzz."""

    def __init__(self, loader: FuzzConfigLoader | None = None, reporter: FuzzReporter | None = None) -> None:
        self.loader = loader or FuzzConfigLoader()
        self.reporter = reporter or FuzzReporter()

    def run(self, argv=None) -> int:
        args = FuzzCliParser().build().parse_args(argv)
        config = self.loader.load(args.config)
        self._apply_overrides(config, args)

        selected = self._selected_kinds(config)
        if not selected:
            print("[!] Chưa chọn scanner. Dùng --xss, --sqli hoặc bật trong config.")
            return 2

        targets = InventoryLoader(config).targets_for(args.inventory, selected)
        targets = self._filter_post_targets(targets, config)
        print(f"[*] Selected targets: {len(targets)}")

        if config.get("safety", {}).get("dry_run", False):
            self._print_targets(targets)
            self.reporter.export([], config.get("output_dir", "fuzz-output"))
            return 0

        client = self._build_client(config)
        findings = self._run_scanners(config, client, targets)
        output_dir = config.get("output_dir", "fuzz-output")
        self.reporter.export(findings, output_dir)
        print(f"[*] Findings: {len(findings)}")
        print(f"[*] Wrote: {Path(output_dir) / 'findings.json'}")
        print(f"[*] Wrote: {Path(output_dir) / 'findings.md'}")
        return 0

    def _apply_overrides(self, config: dict, args: argparse.Namespace) -> None:
        if args.out:
            config["output_dir"] = args.out
        if args.include_post:
            config.setdefault("safety", {})["include_post"] = True
        if args.max_requests is not None:
            config.setdefault("safety", {})["max_requests"] = args.max_requests
        if args.dry_run:
            config.setdefault("safety", {})["dry_run"] = True

        if args.xss or args.xss_reflected or args.xss_stored or args.xss_dom:
            config.setdefault("xss", {})["enabled"] = True
        if args.xss_reflected:
            config.setdefault("xss", {})["reflected"] = True
        if args.xss_stored:
            config.setdefault("xss", {})["stored"] = True
        if args.xss_dom:
            config.setdefault("xss", {})["dom"] = True

        if args.sqli or args.sqli_error or args.sqli_boolean or args.sqli_time:
            config.setdefault("sqli", {})["enabled"] = True
        if args.sqli_error:
            config.setdefault("sqli", {})["error_based"] = True
        if args.sqli_boolean:
            config.setdefault("sqli", {})["boolean_based"] = True
        if args.sqli_time:
            config.setdefault("sqli", {})["time_based"] = True

    def _selected_kinds(self, config: dict) -> set[str]:
        selected = set()
        if config.get("xss", {}).get("enabled", False):
            selected.add("xss")
        if config.get("sqli", {}).get("enabled", False):
            selected.add("sqli")
        return selected

    def _filter_post_targets(self, targets: List[FuzzTarget], config: dict) -> List[FuzzTarget]:
        include_post = bool(config.get("safety", {}).get("include_post", False))
        if include_post:
            return targets
        return [target for target in targets if target.param_location == "query"]

    def _build_client(self, config: dict) -> FuzzHttpClient:
        safety = config.get("safety", {})
        return FuzzHttpClient(
            headers=config.get("headers", {}),
            max_requests=int(safety.get("max_requests", 100)),
            delay_seconds=float(safety.get("delay_seconds", 0.0)),
        )

    def _run_scanners(self, config: dict, client: FuzzHttpClient, targets: List[FuzzTarget]) -> List[Finding]:
        findings: List[Finding] = []
        try:
            if config.get("xss", {}).get("enabled", False):
                xss_targets = [target for target in targets if self._is_xss_target(target)]
                findings.extend(XssRunner(client, config).run(xss_targets))
            if config.get("sqli", {}).get("enabled", False):
                sqli_targets = [target for target in targets if self._is_sqli_target(target)]
                findings.extend(SqliRunner(client, config).run(sqli_targets))
        except RequestBudgetExceeded as error:
            print(f"[!] {error}")
        return findings

    def _is_xss_target(self, target: FuzzTarget) -> bool:
        tests = set(target.candidate_tests)
        return bool(tests & {"reflected_xss_candidate", "stored_xss_candidate", "api_xss_source", "reflection_detected"})

    def _is_sqli_target(self, target: FuzzTarget) -> bool:
        return any(test.startswith("sqli") for test in target.candidate_tests)

    def _print_targets(self, targets: List[FuzzTarget]) -> None:
        for target in targets:
            print(f"[DRY] {target.key} sample={target.sample_value!r} candidates={','.join(target.candidate_tests)}")


def main(argv=None) -> int:
    return FuzzApplication().run(argv)
