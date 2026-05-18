from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .runner import LiveCommandRunner


@dataclass
class LauncherState:
    """Các giá trị người dùng có thể đổi trong menu."""

    base_url: str = "http://127.0.0.1:12001"
    recon_output: str = "recon-output"
    fuzz_output: str = "fuzz-output"
    inventory_path: str = "recon-output/inventory.json"
    max_requests: str = ""
    trace_log: bool = True


class ToolCliMenu:
    """Menu terminal để chạy recon/fuzz bằng phím số."""

    def __init__(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.state = LauncherState()
        self.runner = LiveCommandRunner(self.root)

    def run(self) -> int:
        while True:
            self._print_menu()
            choice = input("Chọn: ").strip()

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
                self.edit_settings()
            elif choice == "0":
                return 0
            else:
                print("[!] Lựa chọn không hợp lệ.")

            input("\nNhấn Enter để quay lại menu...")

    def _print_menu(self) -> None:
        print("")
        print("=" * 72)
        print("ToolKiemThu CLI Menu")
        print("=" * 72)
        print(f"Base URL      : {self.state.base_url}")
        print(f"Recon output  : {self.state.recon_output}")
        print(f"Inventory     : {self.state.inventory_path}")
        print(f"Fuzz output   : {self.state.fuzz_output}")
        print(f"Max requests  : {self.state.max_requests or 'default'}")
        print(f"Trace log     : {'ON' if self.state.trace_log else 'OFF'}")
        print("-" * 72)
        print("1. Chạy recon tĩnh")
        print("2. Chạy recon tĩnh + dynamic Playwright")
        print("3. Chạy fuzz XSS")
        print("4. Chạy fuzz SQLi")
        print("5. Chạy fuzz XSS + SQLi")
        print("6. Dry-run fuzz all")
        print("7. Xem tóm tắt inventory")
        print("8. Xem tóm tắt findings")
        print("9. Cài đặt")
        print("0. Thoát")

    def run_recon(self, dynamic: bool) -> None:
        args = [
            "-c",
            "config.example.json",
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
        args = [self.state.inventory_path, *flags, "--out", self.state.fuzz_output]
        if self.state.max_requests:
            args.extend(["--max-requests", self.state.max_requests])

        module, final_args = self._module_and_args("fuzz", args)
        self.runner.run_python_module(title, module, final_args)

    def _module_and_args(self, tool_name: str, args: List[str]) -> tuple[str, List[str]]:
        if self.state.trace_log:
            return "toolcli.trace_runner", [tool_name, *args]
        return f"{tool_name}tool", args

    def edit_settings(self) -> None:
        print("")
        print("Bỏ trống để giữ nguyên giá trị hiện tại.")
        self.state.base_url = self._ask("Base URL", self.state.base_url)
        self.state.recon_output = self._ask("Recon output", self.state.recon_output)
        self.state.inventory_path = self._ask("Inventory path", self.state.inventory_path)
        self.state.fuzz_output = self._ask("Fuzz output", self.state.fuzz_output)
        self.state.max_requests = self._ask("Max requests", self.state.max_requests)
        trace_answer = self._ask("Trace log ON/OFF", "ON" if self.state.trace_log else "OFF")
        self.state.trace_log = trace_answer.strip().lower() in {"on", "yes", "y", "1", "true"}

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
        path = self.root / self.state.fuzz_output / "findings.json"
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

    def _read_json(self, path: Path):
        if not path.exists():
            print(f"[!] Chưa có file: {path}")
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            print(f"[!] JSON lỗi: {path}: {error}")
            return None

    def _ask(self, label: str, current: str) -> str:
        value = input(f"{label} [{current or '-'}]: ").strip()
        return value or current


def main() -> int:
    return ToolCliMenu().run()

