from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from .analyzer import FindingAnalyzer
from .config import AiConfigLoader
from .providers import ChatMessage, build_provider
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
        analyses = FindingAnalyzer(config).analyze_file(args.findings)
        self.reporter.export(analyses, output_dir)

        print(f"[*] AI analyses: {len(analyses)}")
        print(f"[*] Wrote: {output_dir / 'ai-report.json'}")
        print(f"[*] Wrote: {output_dir / 'ai-report.md'}")
        return 0

    def test_provider(self, config: dict, prompt: str) -> int:
        provider_config = config.get("provider", {})
        provider_name = str(provider_config.get("name", "offline"))
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

        provider = build_provider(config)
        started = time.perf_counter()
        try:
            content = provider.complete([ChatMessage(role="user", content=prompt)])
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

        usage = getattr(provider, "last_usage", None)
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


def main(argv=None) -> int:
    return AiApplication().run(argv)
