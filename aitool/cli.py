from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from toolcli.table import ConsoleTable

from .analyzer import FindingAnalyzer
from .api_client import AiApiClient, ChatMessage
from .config import AiConfigLoader
from .reporter import AiReportWriter


class AiCliParser:
    """Command-line parser for the AI analysis tool."""

    def build(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Analyze fuzz findings with a configurable AI provider")
        parser.add_argument("findings", nargs="?", help="Path to fuzz-output/findings.json")
        parser.add_argument("-c", "--config", default="ai.config.example.json", help="AI config file")
        parser.add_argument("-o", "--out", help="AI report output directory")
        parser.add_argument("--test-provider", action="store_true", help="Test AI provider/API key")
        parser.add_argument(
            "--test-prompt",
            default="Tra loi ngan gon bang dung chu OK.",
            help="Prompt used when testing the AI provider",
        )
        return parser


class AiApplication:
    """Coordinates AI report generation."""

    def __init__(
        self,
        config_loader: AiConfigLoader | None = None,
        reporter: AiReportWriter | None = None,
    ) -> None:
        self.config_loader = config_loader or AiConfigLoader()
        self.reporter = reporter or AiReportWriter()

    def run(self, argv=None) -> int:
        parser = AiCliParser().build()
        args = parser.parse_args(argv)
        config = self.config_loader.load(args.config)
        if args.out:
            config["output_dir"] = args.out

        if args.test_provider:
            return self.test_provider(config, args.test_prompt)

        if not args.findings:
            parser.error("findings is required unless --test-provider is used")

        output_dir = Path(config.get("output_dir", "ai-output"))
        table = AiAnalysisTablePrinter()
        table.start()
        analyses = FindingAnalyzer(config).analyze_file(args.findings, on_analysis=table.show)
        table.finish()
        self.reporter.export(analyses, output_dir)

        print(f"[*] AI analyses: {len(analyses)}")
        print(f"[*] Wrote: {output_dir / 'ai-report.json'}")
        return 0

    def test_provider(self, config: dict, prompt: str) -> int:
        provider_config = config.get("provider", {})
        provider_name = str(provider_config.get("name", "openai_compatible"))
        model = str(provider_config.get("model", "-"))
        base_url = str(provider_config.get("base_url", "-"))
        api_key_env = str(provider_config.get("api_key_env", ""))

        print("[*] Testing AI provider")
        print(f"[*] Provider : {provider_name}")
        print(f"[*] Model    : {model}")
        print(f"[*] Base URL : {base_url}")
        if api_key_env:
            if not os.environ.get(api_key_env):
                print(f"[!] Missing API key env: {api_key_env}")
                return 2
            print(f"[*] API key  : loaded from {api_key_env}")
        else:
            print("[*] API key  : not configured")

        api_client = AiApiClient(config)
        started = time.perf_counter()
        try:
            content = api_client.complete([ChatMessage(role="user", content=prompt)])
        except Exception as error:
            print(f"[!] Provider test failed: {error}")
            return 1

        elapsed = time.perf_counter() - started
        preview = content.strip().replace("\n", " ")
        if len(preview) > 300:
            preview = preview[:297] + "..."
        preview = self._safe_terminal_text(preview)

        print(f"[+] Provider test OK in {elapsed:.2f}s")
        print(f"[+] Content: {preview or '<empty>'}")

        usage = api_client.last_usage
        if usage:
            print(f"[+] Tokens : {self._format_token_usage(usage)}")
        return 0

    def _safe_terminal_text(self, value: str) -> str:
        encoding = sys.stdout.encoding or "utf-8"
        return value.encode(encoding, errors="replace").decode(encoding)

    def _format_token_usage(self, usage: dict) -> str:
        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")
        total_tokens = usage.get("total_tokens")
        reasoning_tokens = usage.get("reasoning_tokens")

        if reasoning_tokens is None:
            completion_details = usage.get("completion_tokens_details", {})
            if isinstance(completion_details, dict):
                reasoning_tokens = completion_details.get("reasoning_tokens")

        parts = []
        if prompt_tokens is not None:
            parts.append(f"prompt={prompt_tokens}")
        if completion_tokens is not None:
            parts.append(f"completion={completion_tokens}")
        if total_tokens is not None:
            parts.append(f"total={total_tokens}")
        if reasoning_tokens is not None:
            parts.append(f"reasoning={reasoning_tokens}")
        return " ".join(parts) or "unavailable"


class AiAnalysisTablePrinter:
    COLUMNS = [
        ("Time", 19),
        ("Finding", 8),
        ("Source issue", 28),
        ("Path", 24),
        ("Param", 18),
        ("AI confirmed", 12),
        ("AI severity", 11),
        ("Confidence", 10),
        ("CWE", 10),
        ("Comment", 38),
    ]

    def __init__(self) -> None:
        self.count = 0
        self.table = ConsoleTable("AI ANALYSIS LIVE TABLE", self.COLUMNS)

    def start(self) -> None:
        self.table.start()

    def show(self, analysis: dict) -> None:
        self.count += 1
        source = analysis.get("source_finding", {})
        ai_result = analysis.get("ai_result", {})

        row = [
            datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            f"#{analysis.get('index', self.count)}",
            self._source_issue(source),
            source.get("path", "-"),
            self._param(source),
            "yes" if ai_result.get("confirmed") else "no",
            ai_result.get("severity", "-"),
            ai_result.get("confidence", "-"),
            ai_result.get("cwe") or "-",
            ai_result.get("reason_vi", "-"),
        ]
        self.table.print_row(row)

    def finish(self) -> None:
        if self.count == 0:
            self.table.print_row(["-", "-", "No AI analyses", "-", "-", "-", "-", "-", "-", "-"])
        self.table.finish()

    def _source_issue(self, finding: dict) -> str:
        vuln_type = finding.get("vuln_type", "unknown")
        subtype = finding.get("subtype", "unknown")
        return f"{vuln_type} ({subtype})"

    def _param(self, finding: dict) -> str:
        location = finding.get("location", "-")
        param = finding.get("param", "-")
        return f"{location}:{param}"


def main(argv=None) -> int:
    return AiApplication().run(argv)
