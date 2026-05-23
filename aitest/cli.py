from __future__ import annotations

import argparse
from datetime import datetime
from urllib.parse import urlparse

from aitool.config import AiConfigLoader

from .reporter import AiTestReporter
from .session_runner import AiIterativeSessionRunner
from .target_selector import AiTestTargetSelector


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI-assisted iterative payload tester")
    parser.add_argument("inventory", help="Đường dẫn recon-output/inventory.json")
    parser.add_argument("--base-url", default="http://127.0.0.1:12001", help="Base URL của lab")
    parser.add_argument("--ai-config", default="ai.config.example.json", help="File config AI")
    parser.add_argument("--out", default="aitest-output", help="Thư mục output")
    parser.add_argument("--max-targets", type=int, default=5, help="Số target tối đa")
    parser.add_argument("--rounds", type=int, default=4, help="Số vòng AI cho mỗi target")
    parser.add_argument("--include-post", action="store_true", help="Cho phép test body/json POST")
    parser.add_argument("--max-requests", type=int, default=80, help="Giới hạn request")
    parser.add_argument("--quiet", action="store_true", help="Không in log chi tiết khi chạy")
    return parser


class AiTestApplication:
    """Điều phối module AI iterative riêng, không ghi vào findings chính."""

    def run(self, argv=None) -> int:
        args = build_parser().parse_args(argv)
        tool_config = self._tool_config(args)
        ai_config = AiConfigLoader().load(args.ai_config)

        targets = AiTestTargetSelector(tool_config).select(
            args.inventory,
            max_targets=args.max_targets,
            include_post=args.include_post,
        )
        print(f"[*] AI test targets: {len(targets)}")

        table = AiTestTablePrinter()
        table.start()
        sessions = AiIterativeSessionRunner(
            tool_config,
            ai_config,
            verbose=not args.quiet,
            on_round=table.show,
        ).run_targets(
            targets,
            rounds=args.rounds,
        )
        table.finish()
        AiTestReporter().export(sessions, args.out)

        print(f"[*] Sessions: {len(sessions)}")
        print(f"[*] Wrote: {args.out}/sessions.json")
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
                "include_post": bool(args.include_post),
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
        ("Confirmed", 10),
        ("Reason", 42),
        ("Comment", 24),
    ]

    def __init__(self) -> None:
        self.count = 0
        self.started = False

    def start(self) -> None:
        if self.started:
            return
        self.started = True
        self._print_header()

    def show(self, event: dict) -> None:
        self.start()
        self.count += 1
        target = event.get("target")
        row = [
            datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            f"{event.get('target_index')}/{event.get('target_total')}",
            event.get("round", "-"),
            getattr(target, "key", "-"),
            event.get("attack_type", "-"),
            event.get("payload", "-"),
            event.get("status", "-"),
            "yes" if event.get("confirmed") else "no",
            event.get("reason", "-"),
            event.get("comment", "-"),
        ]
        print(self._row(row), flush=True)

    def finish(self) -> None:
        if self.count == 0:
            print(self._row(["-", "-", "-", "No AI test rounds", "-", "-", "-", "-", "-", "-"]))
        print("-" * self._table_width())

    def _print_header(self) -> None:
        print("")
        print("=" * self._table_width())
        print("AI ITERATIVE TEST LIVE TABLE")
        print("=" * self._table_width())
        print(self._row([name for name, _ in self.COLUMNS]))
        print("-" * self._table_width())

    def _row(self, values: list[object]) -> str:
        cells = []
        for value, (_, width) in zip(values, self.COLUMNS):
            cells.append(self._short(value, width).ljust(width))
        return "  ".join(cells)

    def _short(self, value: object, width: int) -> str:
        text = str(value).replace("\n", " ").replace("\r", " ")
        return text if len(text) <= width else text[: max(0, width - 3)] + "..."

    def _table_width(self) -> int:
        return sum(width for _, width in self.COLUMNS) + (len(self.COLUMNS) - 1) * 2


def main(argv=None) -> int:
    return AiTestApplication().run(argv)
