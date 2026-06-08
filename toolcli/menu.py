from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .runner import LiveCommandRunner


@dataclass
class LauncherState:
    """User-editable values stored while the menu is running."""

    base_url: str = "http://127.0.0.1:12001"
    fuzz_output: str = "fuzz-output"
    inventory_path: str = "recon-output/inventory.json"
    max_requests: str = ""
    trace_log: bool = False
    ai_config: str = "ai.config.example.json"
    aitest_output: str = "aitest-output"
    aitest_max_targets: str = "2"
    aitest_rounds: str = "5"


class ToolCliMenu:
    """Terminal launcher for recon, fuzz, and AI workflows."""

    def __init__(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.state = LauncherState()
        self.runner = LiveCommandRunner(self.root)

    def run(self) -> int:
        while True:
            self._print_menu()
            choice = input("Chọn: ").strip()

            if choice == "1":
                self.run_recon()
            elif choice == "2":
                self.run_fuzz(["--xss"], title="fuzz-xss")
            elif choice == "3":
                self.run_fuzz(["--sqli"], title="fuzz-sqli")
            elif choice == "4":
                self.run_fuzz(["--xss", "--sqli"], title="fuzz-all")
            elif choice == "5":
                self.run_ai_iterative_test()
            elif choice == "6":
                self.edit_tool_settings()
            elif choice == "7":
                self.edit_ai_settings()
            elif choice == "8":
                self.test_ai_provider()
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
        print(f"Inventory     : {self.state.inventory_path}")
        print(f"Fuzz output   : {self.state.fuzz_output}")
        print(f"Max requests  : {self.state.max_requests or 'default'}")
        print(f"Trace log     : {'ON' if self.state.trace_log else 'OFF'}")
        print(f"AI config     : {self.state.ai_config}")
        print(f"AI test output: {self.state.aitest_output}")
        print(f"AI test limit : {self.state.aitest_max_targets} targets, {self.state.aitest_rounds} rounds")
        print("-" * 72)
        print("1. Chạy recon")
        print("2. Chạy fuzz XSS")
        print("3. Chạy fuzz SQLi")
        print("4. Chạy fuzz XSS + SQLi")
        print("5. Chạy AI SQLi test")
        print("6. Cài đặt recon/fuzz")
        print("7. Cài đặt AI")
        print("8. Kiểm tra AI provider/API key")
        print("0. Thoát")

    def run_recon(self) -> None:
        args = [
            "-c",
            "recon.config.example.json",
            "--base-url",
            self.state.base_url,
        ]

        module, final_args = self._module_and_args("recon", args)
        self.runner.run_python_module("recon", module, final_args)

        self.state.inventory_path = "recon-output/inventory.json"

    def run_fuzz(self, flags: List[str], title: str) -> None:
        args = [self.state.inventory_path, "--base-url", self.state.base_url, *flags, "--out", self.state.fuzz_output]
        if self.state.max_requests:
            args.extend(["--max-requests", self.state.max_requests])

        module, final_args = self._module_and_args("fuzz", args)
        self.runner.run_python_module(title, module, final_args)

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
        self.runner.run_python_module("ai-sqli-test", "aitest", args)

    def test_ai_provider(self) -> None:
        args = [
            "--config",
            self.state.ai_config,
        ]
        self.runner.run_python_module("ai-provider-test", "aicore", args)

    def _module_and_args(self, tool_name: str, args: List[str]) -> tuple[str, List[str]]:
        if self.state.trace_log:
            return "toolcli.trace_runner", [tool_name, *args]
        return f"{tool_name}tool", args

    def edit_tool_settings(self) -> None:
        print("")
        print("Cài đặt recon/fuzz. Bỏ trống để giữ giá trị hiện tại.")
        self.state.base_url = self._normalize_base_url(self._ask("Base URL", self.state.base_url))
        self.state.fuzz_output = self._ask("Fuzz output", self.state.fuzz_output)
        self.state.max_requests = self._ask("Max requests", self.state.max_requests)
        trace_answer = self._ask("Trace log ON/OFF", "ON" if self.state.trace_log else "OFF")
        self.state.trace_log = trace_answer.strip().lower() in {"on", "yes", "y", "1", "true"}

    def edit_ai_settings(self) -> None:
        print("")
        print("Cài đặt AI. Bỏ trống để giữ giá trị hiện tại.")
        self.state.ai_config = self._ask("AI config", self.state.ai_config)
        self.state.aitest_output = self._ask("AI test output", self.state.aitest_output)
        self.state.aitest_max_targets = self._ask("AI test max targets", self.state.aitest_max_targets)
        self.state.aitest_rounds = self._ask("AI test rounds", self.state.aitest_rounds)

    def _ask(self, label: str, current: str) -> str:
        value = input(f"{label} [{current or '-'}]: ").strip()
        return value or current

    def _normalize_base_url(self, value: str) -> str:
        text = value.strip().rstrip("/")
        if text and "://" not in text:
            text = "http://" + text
        return text


def main() -> int:
    return ToolCliMenu().run()
