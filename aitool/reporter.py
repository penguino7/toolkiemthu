from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


class AiReportWriter:
    """Ghi kết quả AI ra JSON và Markdown."""

    def export(self, analyses: List[Dict], output_dir: str | Path) -> None:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        self.export_json(analyses, output / "ai-report.json")
        self.export_markdown(analyses, output / "ai-report.md")

    def export_json(self, analyses: List[Dict], output_path: str | Path) -> None:
        Path(output_path).write_text(
            json.dumps(analyses, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def export_markdown(self, analyses: List[Dict], output_path: str | Path) -> None:
        lines = ["# AI Vulnerability Report", "", f"Tổng finding phân tích: **{len(analyses)}**", ""]

        if not analyses:
            lines.extend(["Không có finding để phân tích.", ""])

        for item in analyses:
            self._append_item(lines, item)

        Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _append_item(self, lines: List[str], item: Dict) -> None:
        finding = item.get("source_finding", {})
        result = item.get("ai_result", {})
        title = "{vuln}/{subtype} - {path}".format(
            vuln=finding.get("vuln_type", "unknown"),
            subtype=finding.get("subtype", "unknown"),
            path=finding.get("path", finding.get("url", "-")),
        )

        lines.extend(
            [
                f"## {item.get('index')}. {title}",
                "",
                f"- Confirmed: `{result.get('confirmed')}`",
                f"- CWE: `{result.get('cwe')}`",
                f"- Possible CVE: `{result.get('possible_cve')}`",
                f"- Severity: `{result.get('severity')}`",
                f"- Confidence: `{result.get('confidence')}`",
                f"- Method: `{finding.get('method')}`",
                f"- URL: `{finding.get('url')}`",
                f"- Param: `{finding.get('location')}:{finding.get('param')}`",
                f"- Payload: `{finding.get('payload')}`",
                f"- Evidence: `{finding.get('evidence')}`",
                "",
                "### Nhận Xét",
                "",
                str(result.get("reason_vi", "-")),
                "",
                "### False Positive",
                "",
                str(result.get("false_positive_note_vi", "-")),
                "",
                "### Khắc Phục",
                "",
                str(result.get("remediation_vi", "-")),
                "",
            ]
        )

