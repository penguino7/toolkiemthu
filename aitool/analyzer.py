from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .ai_client import AiClient
from .prompts import build_finding_prompt
from .redactor import DataRedactor, trim_text
from .schemas import fallback_analysis, parse_ai_json


class FindingAnalyzer:
    """Đọc findings.json và tạo nhận xét AI cho từng finding."""

    def __init__(self, config: dict, client: AiClient | None = None) -> None:
        self.config = config
        self.client = client or AiClient(config)
        self.redactor = DataRedactor(config)
        analysis = config.get("analysis", {})
        self.language = str(analysis.get("language", "vi"))
        self.max_findings = int(analysis.get("max_findings", 50))
        self.max_payload_chars = int(analysis.get("max_payload_chars", 500))
        self.max_detail_chars = int(analysis.get("max_detail_chars", 1200))
        self.provider_name = str(config.get("provider", {}).get("name", "offline")).lower()

    def analyze_file(self, findings_path: str | Path) -> List[Dict[str, Any]]:
        findings = json.loads(Path(findings_path).read_text(encoding="utf-8-sig"))
        results = []

        for index, finding in enumerate(findings[: self.max_findings], start=1):
            print(f"[*] AI analyzing finding {index}/{min(len(findings), self.max_findings)}")
            results.append(self.analyze_finding(index, finding))

        return results

    def analyze_finding(self, index: int, finding: Dict[str, Any]) -> Dict[str, Any]:
        prepared = self._prepare_finding(finding)

        if self.provider_name == "offline":
            ai_result = fallback_analysis(prepared, "provider offline")
            raw_response = ""
        else:
            prompt = build_finding_prompt(prepared, language=self.language)
            try:
                raw_response = self.client.analyze_prompt(prompt)
                ai_result = parse_ai_json(raw_response)
            except Exception as error:
                ai_result = fallback_analysis(prepared, str(error))
                raw_response = ""

        return {
            "index": index,
            "source_finding": prepared,
            "ai_result": ai_result,
            "raw_ai_response": raw_response,
        }

    def _prepare_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        cleaned = self.redactor.redact(finding)
        cleaned["payload"] = trim_text(cleaned.get("payload", ""), self.max_payload_chars)

        details = cleaned.get("details", {})
        if isinstance(details, dict):
            cleaned["details"] = {
                str(key): trim_text(value, self.max_detail_chars)
                for key, value in details.items()
            }
        return cleaned
