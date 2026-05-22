from __future__ import annotations

import json
from pathlib import Path
from typing import List


class AiTestReporter:
    """Ghi session AI iterative ra JSON."""

    def export(self, sessions: List[dict], output_dir: str | Path) -> None:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        self.export_json(sessions, output / "sessions.json")

    def export_json(self, sessions: List[dict], path: str | Path) -> None:
        Path(path).write_text(json.dumps(sessions, indent=2, ensure_ascii=False), encoding="utf-8")
