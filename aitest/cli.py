from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from aicore.config import AiConfigLoader
from toolcli.table import ConsoleTable

from .reporter import AiTestReporter
from .session_runner import AiIterativeSessionRunner
from .target_selector import AiTestTargetSelector


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI-assisted iterative payload tester")
    parser.add_argument("inventory", help="Đường dẫn recon-output/inventory.json")
    parser.add_argument("--base-url", default="http://127.0.0.1:12001", help="Base URL của lab")
    parser.add_argument("--ai-config", default="ai.config.example.json", help="File config AI")
    parser.add_argument("--out", default="aitest-output", help="Thư mục output")
    parser.add_argument("--max-targets", type=int, default=2, help="Số target tối đa")
    parser.add_argument("--rounds", type=int, default=5, help="Số vòng AI cho mỗi target")
    parser.add_argument("--max-requests", type=int, default=80, help="Giới hạn request")
    return parser


class AiTestApplication:
    """Điều phối module AI iterative riêng, không ghi vào findings chính."""

    def run(self, argv=None) -> int:
        args = build_parser().parse_args(argv)
        tool_config = self._tool_config(args)
        ai_config = AiConfigLoader().load(args.ai_config)
        tool_config["aitest"].update(ai_config.get("aitest", {}))

        reporter = AiTestReporter()
        sessions = []
        reporter.export(sessions, args.out)

        targets = AiTestTargetSelector(tool_config).select(
            args.inventory,
            max_targets=args.max_targets,
        )
        print(f"[*] AI test targets: {len(targets)}")

        table = AiTestTablePrinter()
        table.start()
        runner = AiIterativeSessionRunner(
            tool_config,
            ai_config,
            on_round=table.show,
        )

        total = len(targets)
        for index, target in enumerate(targets, start=1):
            try:
                session = runner.run_one_target(target, args.rounds, index, total)
            except Exception as error:
                session = {
                    "target": {
                        "method": target.method,
                        "path": target.path,
                        "param": target.param_name,
                        "location": target.param_location,
                    },
                    "error": str(error),
                    "rounds": [],
                }
            sessions.append(session)
            reporter.export(sessions, args.out)

        table.finish()

        print(f"[*] Sessions: {len(sessions)}")
        print(f"[*] Wrote: {Path(args.out).resolve() / 'sessions.json'}")
        return 0

    def _tool_config(self, args: argparse.Namespace) -> dict:
        host = urlparse(args.base_url).hostname or "127.0.0.1"
        return {
            "base_url": args.base_url.rstrip("/"),
            "headers": {"User-Agent": "AiTest/0.1"},
            "scope": {
                "include_hosts": [host, "localhost", "127.0.0.1"],
                "exclude_paths": ["/user/logout.php"],
            },
            "safety": {
                "max_requests": int(args.max_requests),
                "delay_seconds": 0.05,
                "request_timeout_seconds": 15,
                "use_environment_proxy": False,
                "skip_param_names": [
                    "csrf",
                    "csrf_token",
                    "_csrf",
                    "token",
                    "auth",
                    "authorization",
                    "password",
                    "pass",
                    "pwd",
                    "session",
                    "sid",
                    "phpsessid",
                ],
            },
            "aitest": {
                "full_raw_under_chars": 4000,
                "json_raw_under_chars": 8000,
                "raw_head_chars": 2000,
                "raw_tail_chars": 2000,
                "signal_window_chars": 700,
                "text_preview_chars": 1200,
            },
        }


class AiTestTablePrinter:
    COLUMNS = [
        ("Time", 19),
        ("Target", 9),
        ("Round", 7),
        ("Point", 34),
        ("AI attack", 16),
        ("Payload", 34),
        ("Status", 8),
        ("Proof", 10),
        ("Reason", 42),
        ("Comment", 34),
    ]

    def __init__(self) -> None:
        self.count = 0
        self.table = ConsoleTable("AI ITERATIVE TEST LIVE TABLE", self.COLUMNS)

    def start(self) -> None:
        self.table.start()

    def show(self, event: dict) -> None:
        self.count += 1
        target = event.get("target")
        focus = getattr(target, "aitest_focus", "auto") if target else "auto"
        row = [
            datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            f"{event.get('target_index')}/{event.get('target_total')}",
            event.get("round", "-"),
            f"[{focus}] {getattr(target, 'key', '-')}",
            event.get("attack_type", "-"),
            event.get("payload", "-"),
            event.get("status", "-"),
            "yes" if event.get("proof") or event.get("confirmed") else "no",
            event.get("reason", "-"),
            event.get("comment", "-"),
        ]
        self.table.print_row(row)

    def finish(self) -> None:
        if self.count == 0:
            self.table.print_row(["-", "-", "-", "No AI test rounds", "-", "-", "-", "-", "-", "-"])
        self.table.finish()


def main(argv=None) -> int:
    return AiTestApplication().run(argv)
