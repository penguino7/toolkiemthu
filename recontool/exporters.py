from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from .models import EndpointRecord


class ReconExporter:
    """Xuất kết quả recon ra JSON và danh sách param dạng text."""

    def export_all(self, records: List[EndpointRecord], output_dir: str | Path) -> None:
        output = self._ensure_dir(output_dir)
        self.export_json(records, output / "inventory.json")
        self.export_params(records, output / "params.txt")

    def export_json(self, records: Iterable[EndpointRecord], output_path: str | Path) -> None:
        data = [record.to_dict() for record in records]
        Path(output_path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def export_params(self, records: Iterable[EndpointRecord], output_path: str | Path) -> None:
        lines = []
        for record in records:
            for param in sorted(record.params.values(), key=lambda item: item.key):
                lines.append(f"{record.method} {record.canonical_path} {param.location}:{param.name} {param.type_hint}")
        Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _ensure_dir(self, path: str | Path) -> Path:
        output = Path(path)
        output.mkdir(parents=True, exist_ok=True)
        return output
