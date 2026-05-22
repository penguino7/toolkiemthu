from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .runner import LiveCommandRunner


@dataclass
class LauncherState:
    """User-editable values stored while the menu is running."""

    base_url: str = "http://127.0.0.1:12001"
    recon_output: str = "recon-output"
    fuzz_output: str = "fuzz-output"
    inventory_path: str = "recon-output/inventory.json"
    findings_path: str = "fuzz-output/findings.json"
    max_requests: str = ""
    trace_log: bool = True
    ai_config: str = "ai.config.example.json"
    ai_output: str = "ai-output"
    aitest_output: str = "aitest-output"
    aitest_max_targets: str = "5"
    aitest_rounds: str = "4"


class ToolCliMenu:
    """Terminal launcher for recon, fuzz, and AI workflows."""

    def __init__(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.state = LauncherState()
        self.runner = LiveCommandRunner(self.root)

    def run(self) -> int:
        while True:
            self._print_menu()
            choice = input("Choose: ").strip()

            if choice == "1":
                self.run_recon(dynamic=False)
            elif choice == "2":
                self.run_recon(dynamic=True)
            elif choice == "3":
                self.run_fuzz(["--xss"], title="fuzz-xss")
            elif choice == "4":
                self.run_fuzz(["--sqli"], title="fuzz-sqli")
            elif choice == "5":
                self.run_fuzz(["--xss", "--sqli"], title="fuzz-all")
            elif choice == "6":
                self.run_fuzz(["--xss", "--sqli", "--dry-run"], title="fuzz-dry-run")
            elif choice == "7":
                self.show_inventory_summary()
            elif choice == "8":
                self.show_findings_summary()
            elif choice == "9":
                self.run_ai_analysis()
            elif choice == "10":
                self.show_ai_report_summary()
            elif choice == "11":
                self.edit_tool_settings()
            elif choice == "12":
                self.edit_ai_settings()
            elif choice == "13":
                self.test_ai_provider()
            elif choice == "14":
                self.run_ai_iterative_test()
            elif choice == "0":
                return 0
            else:
                print("[!] Invalid choice.")

            input("\nPress Enter to return to menu...")

    def _print_menu(self) -> None:
        print("")
        print("=" * 72)
        print("ToolKiemThu CLI Menu")
        print("=" * 72)
        print(f"Base URL      : {self.state.base_url}")
        print(f"Recon output  : {self.state.recon_output}")
        print(f"Inventory     : {self.state.inventory_path}")
        print(f"Fuzz output   : {self.state.fuzz_output}")
        print(f"Findings      : {self.state.findings_path}")
        print(f"Max requests  : {self.state.max_requests or 'default'}")
        print(f"Trace log     : {'ON' if self.state.trace_log else 'OFF'}")
        print(f"AI config     : {self.state.ai_config}")
        print(f"AI output     : {self.state.ai_output}")
        print(f"AI test output: {self.state.aitest_output}")
        print(f"AI test limit : {self.state.aitest_max_targets} targets, {self.state.aitest_rounds} rounds")
        print("-" * 72)
        print("1. Run static recon")
        print("2. Run static + dynamic Playwright recon")
        print("3. Run XSS fuzz")
        print("4. Run SQLi fuzz")
        print("5. Run XSS + SQLi fuzz")
        print("6. Dry-run all fuzz")
        print("7. Show inventory summary")
        print("8. Show findings summary")
        print("9. Run AI analysis")
        print("10. Show AI report summary")
        print("11. Recon/fuzz settings")
        print("12. AI settings")
        print("13. Test AI provider/API key")
        print("14. Run AI iterative test")
        print("0. Exit")

    def run_recon(self, dynamic: bool) -> None:
        args = [
            "-c",
            "recon.config.example.json",
            "--base-url",
            self.state.base_url,
            "--out",
            self.state.recon_output,
        ]
        if dynamic:
            args.append("--dynamic")

        module, final_args = self._module_and_args("recon", args)
        title = "recon-dynamic" if dynamic else "recon-static"
        self.runner.run_python_module(title, module, final_args)

        self.state.inventory_path = f"{self.state.recon_output}/inventory.json"

    def run_fuzz(self, flags: List[str], title: str) -> None:
        args = [self.state.inventory_path, "--base-url", self.state.base_url, *flags, "--out", self.state.fuzz_output]
        if self.state.max_requests:
            args.extend(["--max-requests", self.state.max_requests])

        module, final_args = self._module_and_args("fuzz", args)
        self.runner.run_python_module(title, module, final_args)
        self.state.findings_path = f"{self.state.fuzz_output}/findings.json"

    def run_ai_analysis(self) -> None:
        args = [
            self.state.findings_path,
            "--config",
            self.state.ai_config,
            "--out",
            self.state.ai_output,
        ]
        self.runner.run_python_module("ai-analysis", "aitool", args)

    def run_ai_iterative_test(self) -> None:
        args = [
            self.state.inventory_path,
            "--base-url",
            self.state.base_url,
            "--ai-config",
            self.state.ai_config,
            "--out",
            self.state.aitest_output,
            "--max-targets",
            self.state.aitest_max_targets,
            "--rounds",
            self.state.aitest_rounds,
        ]
        self.runner.run_python_module("ai-iterative-test", "aitest", args)

    def test_ai_provider(self) -> None:
        args = [
            "--config",
            self.state.ai_config,
            "--test-provider",
        ]
        self.runner.run_python_module("ai-provider-test", "aitool", args)

    def _module_and_args(self, tool_name: str, args: List[str]) -> tuple[str, List[str]]:
        if self.state.trace_log:
            return "toolcli.trace_runner", [tool_name, *args]
        return f"{tool_name}tool", args

    def edit_tool_settings(self) -> None:
        print("")
        print("Recon/fuzz settings. Leave blank to keep the current value.")
        self.state.base_url = self._ask("Base URL", self.state.base_url)
        self.state.recon_output = self._ask("Recon output", self.state.recon_output)
        self.state.inventory_path = self._ask("Inventory path", self.state.inventory_path)
        self.state.fuzz_output = self._ask("Fuzz output", self.state.fuzz_output)
        self.state.findings_path = self._ask("Findings path", self.state.findings_path)
        self.state.max_requests = self._ask("Max requests", self.state.max_requests)
        trace_answer = self._ask("Trace log ON/OFF", "ON" if self.state.trace_log else "OFF")
        self.state.trace_log = trace_answer.strip().lower() in {"on", "yes", "y", "1", "true"}

    def edit_ai_settings(self) -> None:
        print("")
        print("AI settings. Leave blank to keep the current value.")
        self.state.ai_config = self._ask("AI config", self.state.ai_config)
        self.state.ai_output = self._ask("AI output", self.state.ai_output)
        self.state.aitest_output = self._ask("AI test output", self.state.aitest_output)
        self.state.aitest_max_targets = self._ask("AI test max targets", self.state.aitest_max_targets)
        self.state.aitest_rounds = self._ask("AI test rounds", self.state.aitest_rounds)
        self.state.findings_path = self._ask("Findings path", self.state.findings_path)

    def show_inventory_summary(self) -> None:
        path = self.root / self.state.inventory_path
        data = self._read_json(path)
        if data is None:
            return

        param_count = sum(len(record.get("params", [])) for record in data)
        candidate_count = sum(1 for record in data if record.get("candidate_tests"))
        print(f"Inventory: {path}")
        print(f"- Endpoints: {len(data)}")
        print(f"- Params: {param_count}")
        print(f"- Candidate endpoints: {candidate_count}")

        for record in data[:10]:
            tests = ", ".join(record.get("candidate_tests", [])) or "-"
            print(f"  {record.get('method')} {record.get('canonical_path') or record.get('path')} tests={tests}")

    def show_findings_summary(self) -> None:
        path = self.root / self.state.findings_path
        data = self._read_json(path)
        if data is None:
            return

        print(f"Findings: {path}")
        print(f"- Total: {len(data)}")
        for finding in data:
            print(
                "  {vuln_type}/{subtype} {method} {path} param={location}:{param}".format(
                    vuln_type=finding.get("vuln_type"),
                    subtype=finding.get("subtype"),
                    method=finding.get("method"),
                    path=finding.get("path"),
                    location=finding.get("location"),
                    param=finding.get("param"),
                )
            )

    def show_ai_report_summary(self) -> None:
        path = self.root / self.state.ai_output / "ai-report.json"
        data = self._read_json(path)
        if data is None:
            return

        print(f"AI report: {path}")
        print(f"- Analyses: {len(data)}")
        for item in data:
            result = item.get("ai_result", {})
            finding = item.get("source_finding", {})
            print(
                "  #{index} {vuln}/{subtype} cwe={cwe} severity={severity} confidence={confidence}".format(
                    index=item.get("index"),
                    vuln=finding.get("vuln_type"),
                    subtype=finding.get("subtype"),
                    cwe=result.get("cwe"),
                    severity=result.get("severity"),
                    confidence=result.get("confidence"),
                )
            )

    def _read_json(self, path: Path):
        if not path.exists():
            print(f"[!] Missing file: {path}")
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            print(f"[!] JSON error: {path}: {error}")
            return None

    def _ask(self, label: str, current: str) -> str:
        value = input(f"{label} [{current or '-'}]: ").strip()
        return value or current


def main() -> int:
    return ToolCliMenu().run()
