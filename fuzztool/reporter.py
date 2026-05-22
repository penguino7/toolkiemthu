from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .models import Finding


class FuzzReporter:
    """Xuất findings ra JSON."""

    def export(self, findings: List[Finding], output_dir: str | Path) -> None:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        self.export_json(findings, output / "findings.json")

    def export_json(self, findings: List[Finding], output_path: str | Path) -> None:
        data = [finding.to_dict() for finding in findings]
        Path(output_path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
