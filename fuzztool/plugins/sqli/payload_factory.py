from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

from ...models import FuzzTarget


class SqliPayloadFactory:
    """Doc payload SQLi tu payloads.txt va render theo target."""

    def __init__(self, payload_file: str | Path | None = None, sleep_seconds: int = 3) -> None:
        self.payload_file = Path(payload_file) if payload_file else Path(__file__).with_name("payloads.txt")
        self.sleep_seconds = sleep_seconds
        self.sections = self._load_sections()

    def error_payloads(self, target: FuzzTarget) -> List[str]:
        return self._render_section(f"error.{self._kind(target)}", target)

    def boolean_payload_pairs(self, target: FuzzTarget) -> List[Tuple[str, str]]:
        kind = self._kind(target)
        true_payloads = self._render_section(f"boolean.{kind}.true", target)
        false_payloads = self._render_section(f"boolean.{kind}.false", target)
        return list(zip(true_payloads, false_payloads))

    def time_payloads(self, target: FuzzTarget) -> List[str]:
        return self._render_section(f"time.{self._kind(target)}", target)

    def _kind(self, target: FuzzTarget) -> str:
        return "numeric" if target.type_hint in {"int", "float"} else "string"

    def _render_section(self, section: str, target: FuzzTarget) -> List[str]:
        rendered = []
        for template in self.sections.get(section, []):
            payload = template.replace("{sample}", target.sample_value)
            payload = payload.replace("{sleep}", str(self.sleep_seconds))
            rendered.append(payload)
        return rendered

    def _load_sections(self) -> Dict[str, List[str]]:
        sections: Dict[str, List[str]] = {}
        current = ""
        for raw_line in self.payload_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1].strip()
                sections.setdefault(current, [])
                continue
            if current:
                sections.setdefault(current, []).append(line)
        return sections
