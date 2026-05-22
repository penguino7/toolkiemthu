from __future__ import annotations

import json
from typing import Any, Dict


SYSTEM_PROMPT = """Bạn là trợ lý phân tích kết quả kiểm thử bảo mật web.
Chỉ dựa trên evidence được cung cấp, không tự bịa request/response không có trong dữ liệu.
Trả lời duy nhất bằng JSON hợp lệ, không markdown, không giải thích ngoài JSON.
"""


def build_finding_prompt(finding: Dict[str, Any], language: str = "vi") -> str:
    """Tạo prompt cho một finding đã được fuzztool ghi nhận."""

    expected_schema = {
        "confirmed": True,
        "vulnerability_type": "xss|sqli|unknown",
        "subtype": "reflected|stored|dom|error_based|boolean_based|union_based|unknown",
        "cwe": "CWE-79|CWE-89|null",
        "possible_cve": None,
        "severity": "low|medium|high|critical",
        "confidence": 0.0,
        "reason_vi": "Giải thích ngắn vì sao kết luận như vậy.",
        "false_positive_note_vi": "Rủi ro false positive nếu có.",
        "remediation_vi": "Cách khắc phục ngắn gọn.",
    }

    payload = {
        "task": "Phân tích một finding bảo mật web và chuẩn hóa kết luận.",
        "language": language,
        "rules": [
            "Nếu evidence chưa đủ, đặt confirmed=false và giảm confidence.",
            "Nếu là XSS thì ưu tiên CWE-79.",
            "Nếu là SQL injection thì ưu tiên CWE-89.",
            "Với union_based SQLi, ưu tiên matched_paths/ignored_paths để đánh giá marker có nằm trong dữ liệu thật hay chỉ nằm trong debug/echo.",
            "possible_cve chỉ điền khi dữ liệu có nêu rõ sản phẩm và phiên bản cụ thể.",
            "Không tạo CVE giả.",
        ],
        "expected_json_schema": expected_schema,
        "finding": finding,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
