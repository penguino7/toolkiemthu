from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from toolcli.table import ConsoleTable

from .config import FuzzConfigLoader
from .http_client import FuzzHttpClient, RequestBudgetExceeded
from .inventory_loader import InventoryLoader
from .models import Finding, FuzzTarget
from .reporter import FuzzReporter
from .sqli_scanner import SqliScanner
from .xss_scanner import XssScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fuzz XSS/SQLi tu inventory.json cua recontool")
    parser.add_argument("inventory", help="Duong dan recon-output/inventory.json")
    parser.add_argument("--base-url", help="Doi host/port khi fuzz")
    parser.add_argument("-c", "--config", default="fuzz.config.example.json", help="File config fuzz")
    parser.add_argument("-o", "--out", help="Thu muc output")
    parser.add_argument("--xss", action="store_true", help="Chay tat ca XSS")
    parser.add_argument("--sqli", action="store_true", help="Chay tat ca SQLi")
    parser.add_argument("--include-post", action="store_true", help="Cho phep fuzz body/json POST")
    parser.add_argument("--max-requests", type=int, help="Gioi han so request")
    return parser


class FuzzApplication:
    """Luồng chính: đọc inventory -> chọn target -> chạy scanner -> ghi report."""

    def __init__(self, loader: FuzzConfigLoader | None = None, reporter: FuzzReporter | None = None) -> None:
        self.loader = loader or FuzzConfigLoader()
        self.reporter = reporter or FuzzReporter()

    def run(self, argv=None) -> int:
        args = build_parser().parse_args(argv)
        config = self._load_config(args)
        selected = self._selected_scanners(config)

        if not selected:
            print("[!] Chua chon scanner. Dung --xss hoac --sqli.")
            return 2

        targets = self._load_targets(args.inventory, config)
        self._print_plan(config, targets)

        client = self._build_client(config)
        findings_table = FindingTablePrinter()
        findings_table.start()
        findings = self._scan(config, client, targets, findings_table.show)
        findings_table.finish()
        self._write_report(findings, client, config)
        return 0

    def _load_config(self, args: argparse.Namespace) -> dict:
        config = self.loader.load(args.config)

        if args.out:
            config["output_dir"] = args.out
        if args.base_url:
            config["base_url"] = args.base_url.rstrip("/")
        if args.include_post:
            config.setdefault("safety", {})["include_post"] = True
        if args.max_requests is not None:
            config.setdefault("safety", {})["max_requests"] = args.max_requests

        if args.xss:
            self._enable_all_xss(config)
        if args.sqli:
            self._enable_all_sqli(config, args.max_requests)

        sync_scope_with_base_url(config)
        return config

    def _enable_all_xss(self, config: dict) -> None:
        xss = config.setdefault("xss", {})
        xss["enabled"] = True
        xss["reflected"] = True
        xss["dom"] = True
        xss["stored"] = True
        config.setdefault("safety", {})["include_post"] = True

    def _enable_all_sqli(self, config: dict, max_requests: int | None) -> None:
        sqli = config.setdefault("sqli", {})
        sqli["enabled"] = True
        sqli["error_based"] = True
        sqli["boolean_based"] = True
        sqli["union_based"] = True
        config.setdefault("safety", {})["include_post"] = True

        if max_requests is None:
            safety = config.setdefault("safety", {})
            safety["max_requests"] = max(int(safety.get("max_requests", 800)), 800)

    def _selected_scanners(self, config: dict) -> set[str]:
        selected = set()
        if config.get("xss", {}).get("enabled", False):
            selected.add("xss")
        if config.get("sqli", {}).get("enabled", False):
            selected.add("sqli")
        return selected

    def _load_targets(self, inventory_path: str, config: dict) -> list[FuzzTarget]:
        targets = InventoryLoader(config).targets_for(inventory_path)
        if config.get("safety", {}).get("include_post", False):
            return targets
        return [target for target in targets if target.param_location == "query"]

    def _build_client(self, config: dict) -> FuzzHttpClient:
        safety = config.get("safety", {})
        return FuzzHttpClient(
            headers=config.get("headers", {}),
            max_requests=int(safety.get("max_requests", 100)),
            delay_seconds=float(safety.get("delay_seconds", 0.0)),
            timeout=int(safety.get("request_timeout_seconds", 15)),
            use_environment_proxy=bool(safety.get("use_environment_proxy", False)),
        )

    def _scan(self, config: dict, client: FuzzHttpClient, targets: list[FuzzTarget], on_finding=None) -> list[Finding]:
        findings: list[Finding] = []
        try:
            if config.get("xss", {}).get("enabled", False):
                findings.extend(XssScanner(client, config, on_finding=on_finding).run(targets))
            if config.get("sqli", {}).get("enabled", False):
                findings.extend(SqliScanner(client, config, on_finding=on_finding).run(targets))
        except RequestBudgetExceeded as error:
            print(f"[!] {error}")
        return findings

    def _print_plan(self, config: dict, targets: list[FuzzTarget]) -> None:
        if config.get("xss", {}).get("enabled", False):
            print("[*] XSS scanners: reflected, dom, stored")
        if config.get("sqli", {}).get("enabled", False):
            print("[*] SQLi scanners: error-based, boolean-based, union-based")
        print(f"[*] Selected targets: {len(targets)}")

    def _write_report(self, findings: list[Finding], client: FuzzHttpClient, config: dict) -> None:
        output_dir = config.get("output_dir", "fuzz-output")
        self.reporter.export(findings, output_dir)
        print(f"[*] Findings: {len(findings)}")
        print(f"[*] Requests sent: {client.request_count}")
        if client.error_count:
            print(f"[!] Request errors: {client.error_count} (timeouts: {client.timeout_count})")
        print(f"[*] Wrote: {Path(output_dir) / 'findings.json'}")


class FindingTablePrinter:
    COLUMNS = [
        ("Time", 19),
        ("Source", 8),
        ("Issue type", 33),
        ("Host", 26),
        ("Path", 24),
        ("Insertion point", 22),
        ("Severity", 9),
        ("Confidence", 10),
        ("Comment", 46),
    ]

    def __init__(self) -> None:
        self.count = 0
        self.table = ConsoleTable("LIVE FINDINGS", self.COLUMNS)

    def start(self) -> None:
        self.table.start()

    def show(self, finding: Finding) -> None:
        self.count += 1
        parsed = urlparse(finding.request_url or finding.target.url)
        host = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else finding.target.url
        path = parsed.path or finding.target.path or "/"

        row = [
            datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "Fuzz",
            self._issue_type(finding),
            host,
            path,
            self._insertion_point(finding),
            finding.severity.title(),
            self._confidence(finding),
            self._comment(finding),
        ]
        self.table.print_row(row)

    def finish(self) -> None:
        if self.count == 0:
            self.table.print_row(["-", "-", "No confirmed findings", "-", "-", "-", "-", "-", "-"])
        self.table.finish()

    def _issue_type(self, finding: Finding) -> str:
        if finding.vuln_type == "xss":
            return f"Cross-site scripting ({finding.subtype})"
        if finding.vuln_type == "sqli":
            return f"SQL injection ({finding.subtype})"
        return f"{finding.vuln_type} ({finding.subtype})"

    def _insertion_point(self, finding: Finding) -> str:
        return f"{finding.target.param_location} {finding.target.param_name} parameter"

    def _confidence(self, finding: Finding) -> str:
        if finding.vuln_type == "xss" and finding.subtype in {"reflected", "stored", "dom"}:
            return "Certain"
        if finding.vuln_type == "sqli" and finding.subtype in {"error_based", "union_based"}:
            return "Certain"
        return "Firm"

    def _comment(self, finding: Finding) -> str:
        details = finding.details or {}

        if finding.vuln_type == "sqli" and finding.subtype == "union_based":
            columns = details.get("column_count", "?")
            visible = ",".join(details.get("visible_columns", [])) or "-"
            paths = ",".join(details.get("matched_paths", [])) or "html"
            return f"columns={columns} visible={visible} at={paths}"

        if finding.vuln_type == "sqli" and finding.subtype == "error_based":
            patterns = ",".join(details.get("matched_patterns", []))
            return patterns or finding.evidence

        if finding.vuln_type == "sqli" and finding.subtype == "boolean_based":
            return f"true_len={details.get('true_length')} false_len={details.get('false_length')}"

        return finding.evidence


def main(argv=None) -> int:
    return FuzzApplication().run(argv)


def sync_scope_with_base_url(config: dict) -> None:
    """Base URL la target chinh, nen host cua no phai nam trong scope."""
    base_url = str(config.get("base_url", "")).rstrip("/")
    config["base_url"] = base_url

    host = (urlparse(base_url).hostname or "").lower()
    if not host:
        return

    include_hosts = config.setdefault("scope", {}).setdefault("include_hosts", [])
    normalized_hosts = {str(item).lower() for item in include_hosts}
    if host not in normalized_hosts:
        include_hosts.append(host)
