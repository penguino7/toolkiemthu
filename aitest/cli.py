from __future__ import annotations

import argparse
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

        sessions = AiIterativeSessionRunner(tool_config, ai_config).run_targets(targets, rounds=args.rounds)
        AiTestReporter().export(sessions, args.out)

        print(f"[*] Sessions: {len(sessions)}")
        print(f"[*] Wrote: {args.out}/sessions.json")
        print(f"[*] Wrote: {args.out}/sessions.md")
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


def main(argv=None) -> int:
    return AiTestApplication().run(argv)
