from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .models import Finding


class FuzzReporter:
    """Xuất findings ra JSON và Markdown."""

    def export(self, findings: List[Finding], output_dir: str | Path) -> None:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        self.export_json(findings, output / "findings.json")
        self.export_markdown(findings, output / "findings.md")

    def export_json(self, findings: List[Finding], output_path: str | Path) -> None:
        data = [finding.to_dict() for finding in findings]
        Path(output_path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def export_markdown(self, findings: List[Finding], output_path: str | Path) -> None:
        lines = ["# Fuzz Findings", "", f"Tổng finding: **{len(findings)}**", ""]
        if not findings:
            lines.extend(["Không có finding.", ""])
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"## {index}. {finding.vuln_type} - {finding.subtype}",
                    "",
                    f"- Severity: `{finding.severity}`",
                    f"- Method: `{finding.target.method}`",
                    f"- URL: `{finding.request_url}`",
                    f"- Param: `{finding.target.param_location}:{finding.target.param_name}`",
                    f"- Payload: `{finding.payload}`",
                    f"- Status: `{finding.status}`",
                    f"- Evidence: `{finding.evidence}`",
                    "",
                ]
            )
            if finding.details:
                lines.append("Details:")
                for key, value in finding.details.items():
                    lines.append(f"- `{key}`: `{value}`")
                lines.append("")
        Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
