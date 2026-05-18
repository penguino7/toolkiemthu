from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import FindingAnalyzer
from .config import AiConfigLoader
from .reporter import AiReportWriter


class AiCliParser:
    """Parser dòng lệnh cho AI analysis tool."""

    def build(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Analyze fuzz findings with a configurable AI provider")
        parser.add_argument("findings", help="Đường dẫn fuzz-output/findings.json")
        parser.add_argument("-c", "--config", default="ai.config.example.json", help="File cấu hình AI")
        parser.add_argument("-o", "--out", help="Thư mục output AI report")
        return parser


class AiApplication:
    """Điều phối luồng AI report."""

    def __init__(
        self,
        config_loader: AiConfigLoader | None = None,
        reporter: AiReportWriter | None = None,
    ) -> None:
        self.config_loader = config_loader or AiConfigLoader()
        self.reporter = reporter or AiReportWriter()

    def run(self, argv=None) -> int:
        args = AiCliParser().build().parse_args(argv)
        config = self.config_loader.load(args.config)
        if args.out:
            config["output_dir"] = args.out

        output_dir = Path(config.get("output_dir", "ai-output"))
        analyses = FindingAnalyzer(config).analyze_file(args.findings)
        self.reporter.export(analyses, output_dir)

        print(f"[*] AI analyses: {len(analyses)}")
        print(f"[*] Wrote: {output_dir / 'ai-report.json'}")
        print(f"[*] Wrote: {output_dir / 'ai-report.md'}")
        return 0


def main(argv=None) -> int:
    return AiApplication().run(argv)

