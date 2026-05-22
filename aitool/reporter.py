from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


class AiReportWriter:
    """Ghi kết quả AI ra JSON."""

    def export(self, analyses: List[Dict], output_dir: str | Path) -> None:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        self.export_json(analyses, output / "ai-report.json")

    def export_json(self, analyses: List[Dict], output_path: str | Path) -> None:
        Path(output_path).write_text(
            json.dumps(analyses, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
