from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import EndpointRecord, Param


class ReconExporter:
    """Xuat ket qua recon o dang gon de fuzz/AI doc tiep."""

    def export_all(self, records: list[EndpointRecord], output_dir: str | Path, base_url: str = "") -> None:
        output = self._ensure_dir(output_dir)
        self.export_json(records, output / "inventory.json", base_url)
        self.export_params(records, output / "params.txt")

    def export_json(self, records: Iterable[EndpointRecord], output_path: str | Path, base_url: str = "") -> None:
        data = {
            "base_url": base_url,
            "endpoints": [self._endpoint_dict(record) for record in records],
        }
        Path(output_path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def export_params(self, records: Iterable[EndpointRecord], output_path: str | Path) -> None:
        lines = []
        for record in records:
            for param in sorted(record.params.values(), key=lambda item: item.key):
                lines.append(f"{record.method} {record.canonical_path} {param.location}:{param.name} {param.type_hint}")
        Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _endpoint_dict(self, record: EndpointRecord) -> dict:
        return {
            "method": record.method,
            "url": self._best_url(record),
            "path": record.canonical_path or record.path,
            "source": self._source(record),
            "params": [self._param_dict(param) for param in sorted(record.params.values(), key=lambda item: item.key)],
        }

    def _param_dict(self, param: Param) -> dict:
        return {
            "name": param.name,
            "in": param.location,
            "type": param.type_hint,
            "sample": param.sample_values[0] if param.sample_values else "",
        }

    def _best_url(self, record: EndpointRecord) -> str:
        return record.examples[0] if record.examples else record.url

    def _source(self, record: EndpointRecord) -> str:
        sources = ",".join(record.source_tools).lower()
        if "playwright" in sources:
            return "dynamic"
        if "static" in sources or "form" in sources:
            return "static"
        return record.source_tools[0] if record.source_tools else "unknown"

    def _ensure_dir(self, path: str | Path) -> Path:
        output = Path(path)
        output.mkdir(parents=True, exist_ok=True)
        return output
