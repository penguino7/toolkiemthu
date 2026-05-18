from __future__ import annotations

import json
from typing import Any, Dict


REQUIRED_KEYS = {
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
    """Parse JSON từ AI, chịu được trường hợp model bọc thêm text ngoài JSON."""

    text = raw_text.strip()
    if not text:
        raise ValueError("AI response is empty")

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = json.loads(_extract_json_object(text))

    missing = REQUIRED_KEYS - set(data)
    if missing:
        raise ValueError(f"AI JSON missing keys: {', '.join(sorted(missing))}")
    return data


def fallback_analysis(finding: Dict[str, Any], reason: str) -> Dict[str, Any]:
    vuln_type = str(finding.get("vuln_type", "unknown"))
    subtype = str(finding.get("subtype", "unknown"))

    cwe = None
    if vuln_type == "xss":
        cwe = "CWE-79"
    elif vuln_type == "sqli":
        cwe = "CWE-89"

    return {
        "confirmed": bool(finding.get("evidence")),
        "vulnerability_type": vuln_type,
        "subtype": subtype,
        "cwe": cwe,
        "possible_cve": None,
        "severity": finding.get("severity", "medium"),
        "confidence": 0.75 if finding.get("evidence") else 0.35,
        "reason_vi": f"Fallback nội bộ: {reason}. Finding có evidence `{finding.get('evidence', '-')}`.",
        "false_positive_note_vi": "Chưa có phân tích từ AI provider, nên cần đọc lại evidence thủ công.",
        "remediation_vi": remediation_for(vuln_type),
    }


def remediation_for(vuln_type: str) -> str:
    if vuln_type == "xss":
        return "Encode output theo đúng context HTML/attribute/JS, validate input và bật CSP phù hợp."
    if vuln_type == "sqli":
        return "Dùng prepared statements/parameterized queries, không nối chuỗi SQL trực tiếp từ input."
    return "Kiểm tra lại input validation, output encoding và xử lý lỗi phía server."


def _extract_json_object(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("AI response does not contain a JSON object")
    return text[start:end + 1]

