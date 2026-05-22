from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .api_client import AiApiClient, ChatMessage
from .prompts import build_finding_prompt
from .prompts import SYSTEM_PROMPT
from .redactor import DataRedactor, trim_text


class FindingAnalyzer:
    """Đọc findings.json và tạo nhận xét AI cho từng finding."""

    def __init__(self, config: dict, api_client: AiApiClient | None = None) -> None:
        self.config = config
        self.api_client = api_client or AiApiClient(config)
        self.redactor = DataRedactor(config)
        analysis = config.get("analysis", {})
        self.language = str(analysis.get("language", "vi"))
        self.max_findings = int(analysis.get("max_findings", 50))
        self.max_payload_chars = int(analysis.get("max_payload_chars", 500))
        self.max_detail_chars = int(analysis.get("max_detail_chars", 1200))

    def analyze_file(self, findings_path: str | Path) -> List[Dict[str, Any]]:
        findings = json.loads(Path(findings_path).read_text(encoding="utf-8-sig"))
        results = []

        for index, finding in enumerate(findings[: self.max_findings], start=1):
            print(f"[*] AI analyzing finding {index}/{min(len(findings), self.max_findings)}")
            results.append(self.analyze_finding(index, finding))

        return results

    def analyze_finding(self, index: int, finding: Dict[str, Any]) -> Dict[str, Any]:
        prepared = self._prepare_finding(finding)
        prompt = build_finding_prompt(prepared, language=self.language)

        try:
            raw_response = self._ask_ai(prompt)
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

    def _ask_ai(self, prompt: str) -> str:
        messages = [
            ChatMessage(role="system", content=SYSTEM_PROMPT),
            ChatMessage(role="user", content=prompt),
        ]
        return self.api_client.complete(messages)


REQUIRED_AI_KEYS = {
    "confirmed",
    "vulnerability_type",
    "subtype",
    "cwe",
    "possible_cve",
    "severity",
    "confidence",
    "reason_vi",
    "false_positive_note_vi",
    "remediation_vi",
}


def parse_ai_json(raw_text: str) -> Dict[str, Any]:
    text = raw_text.strip()
    if not text:
        raise ValueError("AI response is empty")

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("AI response does not contain JSON") from None
        data = json.loads(text[start : end + 1])

    missing = REQUIRED_AI_KEYS - set(data)
    if missing:
        raise ValueError(f"AI JSON missing keys: {', '.join(sorted(missing))}")
    return data


def fallback_analysis(finding: Dict[str, Any], reason: str) -> Dict[str, Any]:
    return {
        "confirmed": False,
        "vulnerability_type": finding.get("vuln_type", "unknown"),
        "subtype": finding.get("subtype", "unknown"),
        "cwe": None,
        "possible_cve": None,
        "severity": "low",
        "confidence": 0.0,
        "reason_vi": f"AI API không trả được kết quả hợp lệ: {reason}. Tool chưa kết luận thay AI.",
        "false_positive_note_vi": "Cần chạy lại AI analysis hoặc đọc evidence thủ công.",
        "remediation_vi": "Chưa sinh khuyến nghị vì AI analysis chưa thành công.",
    }
