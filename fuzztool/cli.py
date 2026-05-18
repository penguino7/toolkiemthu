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
    """Parser dong lenh cho fuzztool."""

    def build(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Fuzz tool doc inventory.json tu recontool")
        parser.add_argument("inventory", help="Duong dan inventory.json sinh boi recontool")
        parser.add_argument("-c", "--config", default="fuzz.config.example.json", help="File config fuzz")
        parser.add_argument("-o", "--out", help="Thu muc output")
        parser.add_argument("--xss", action="store_true", help="Bat tat ca XSS: reflected, DOM, stored")
        parser.add_argument("--xss-reflected", action="store_true", help="Bat rieng reflected XSS")
        parser.add_argument("--xss-stored", action="store_true", help="Bat rieng stored XSS")
        parser.add_argument("--xss-dom", action="store_true", help="Bat rieng DOM XSS")
        parser.add_argument("--sqli", action="store_true", help="Bat tat ca SQLi: error, boolean, time")
        parser.add_argument("--sqli-error", action="store_true", help="Bat rieng SQLi error-based")
        parser.add_argument("--sqli-boolean", action="store_true", help="Bat rieng SQLi boolean-based")
        parser.add_argument("--sqli-time", action="store_true", help="Bat rieng SQLi time-based")
        parser.add_argument("--include-post", action="store_true", help="Cho phep fuzz body/json POST")
        parser.add_argument("--max-requests", type=int, help="Gioi han so request fuzz")
        parser.add_argument("--dry-run", action="store_true", help="Chi liet ke target, khong gui request")
        return parser


class FuzzApplication:
    """Dieu phoi pipeline fuzz."""

    def __init__(self, loader: FuzzConfigLoader | None = None, reporter: FuzzReporter | None = None) -> None:
        self.loader = loader or FuzzConfigLoader()
        self.reporter = reporter or FuzzReporter()

    def run(self, argv=None) -> int:
        args = FuzzCliParser().build().parse_args(argv)
        config = self.loader.load(args.config)
        self._apply_overrides(config, args)

        selected = self._selected_kinds(config)
        if not selected:
            print("[!] Chua chon scanner. Dung --xss, --sqli hoac bat trong config.")
            return 2

        targets = InventoryLoader(config).targets_for(args.inventory, selected)
        targets = self._filter_post_targets(targets, config)
        self._print_scanner_summary(config)
        self._print_safety_warnings(config)
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
        print(f"[*] Requests sent: {client.request_count}")
        if client.error_count:
            print(f"[!] Request errors: {client.error_count} (timeouts: {client.timeout_count})")
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

        self._apply_xss_overrides(config, args)
        self._apply_sqli_overrides(config, args)

    def _apply_xss_overrides(self, config: dict, args: argparse.Namespace) -> None:
        selected_xss_type = args.xss_reflected or args.xss_stored or args.xss_dom
        if args.xss or selected_xss_type:
            config.setdefault("xss", {})["enabled"] = True

        if args.xss:
            # Trong lab, --xss nghia la fuzz du reflected, DOM va stored.
            config.setdefault("xss", {})["reflected"] = True
            config.setdefault("xss", {})["dom"] = True
            config.setdefault("xss", {})["stored"] = True
            config.setdefault("safety", {})["include_post"] = True
            return

        if selected_xss_type:
            config.setdefault("xss", {})["reflected"] = bool(args.xss_reflected)
            config.setdefault("xss", {})["stored"] = bool(args.xss_stored)
            config.setdefault("xss", {})["dom"] = bool(args.xss_dom)
            if args.xss_stored:
                config.setdefault("safety", {})["include_post"] = True

    def _apply_sqli_overrides(self, config: dict, args: argparse.Namespace) -> None:
        selected_sqli_type = args.sqli_error or args.sqli_boolean or args.sqli_time
        if args.sqli or selected_sqli_type:
            config.setdefault("sqli", {})["enabled"] = True

        if args.sqli:
            # Trong lab, --sqli nghia la fuzz du error-based, boolean va time.
            config.setdefault("sqli", {})["error_based"] = True
            config.setdefault("sqli", {})["boolean_based"] = True
            config.setdefault("sqli", {})["time_based"] = True
            config.setdefault("safety", {})["include_post"] = True
            if args.max_requests is None:
                current_limit = int(config.setdefault("safety", {}).get("max_requests", 300))
                config.setdefault("safety", {})["max_requests"] = max(current_limit, 300)
            return

        if selected_sqli_type:
            config.setdefault("sqli", {})["error_based"] = bool(args.sqli_error)
            config.setdefault("sqli", {})["boolean_based"] = bool(args.sqli_boolean)
            config.setdefault("sqli", {})["time_based"] = bool(args.sqli_time)
            config.setdefault("safety", {})["include_post"] = True

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

    def _print_scanner_summary(self, config: dict) -> None:
        if config.get("xss", {}).get("enabled", False):
            xss = config.get("xss", {})
            active = []
            if xss.get("reflected", False):
                active.append("reflected")
            if xss.get("dom", False):
                active.append("dom")
            if xss.get("stored", False):
                active.append("stored")
            print(f"[*] XSS scanners: {', '.join(active) if active else 'none'}")

        if config.get("sqli", {}).get("enabled", False):
            sqli = config.get("sqli", {})
            active = []
            if sqli.get("error_based", False):
                active.append("error-based")
            if sqli.get("boolean_based", False):
                active.append("boolean-based")
            if sqli.get("time_based", False):
                active.append("time-based")
            print(f"[*] SQLi scanners: {', '.join(active) if active else 'none'}")

    def _print_safety_warnings(self, config: dict) -> None:
        stored_enabled = bool(config.get("xss", {}).get("stored", False))
        if stored_enabled and not config.get("xss", {}).get("stored_check_paths", []):
            print("[!] Stored XSS can stored_check_paths de biet URL nao se mo lai de xac minh payload da luu.")

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
