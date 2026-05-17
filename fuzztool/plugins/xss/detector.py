from __future__ import annotations


class XssDetector:
    """Detector XSS mức recon/fuzz nhẹ.

    Detector này tìm marker phản xạ trong response/DOM. Nó không khẳng định chắc
    chắn có XSS thực thi JavaScript; finding nên được hiểu là candidate cần xác minh.
    """

    def reflected(self, response_text: str, marker: str, content_type: str = "") -> tuple[bool, str]:
        if marker not in response_text:
            return False, ""
        return True, self.context(response_text, marker, content_type)

    def context(self, response_text: str, marker: str, content_type: str = "") -> str:
        if "json" in (content_type or "").lower():
            return "json"
        index = response_text.find(marker)
        if index == -1:
            return "unknown"
        before = response_text[max(0, index - 40):index].lower()
        after = response_text[index:index + len(marker) + 40].lower()
        if "<script" in before or "</script" in after:
            return "script"
        if "=" in before and ("\"" in before[-5:] or "'" in before[-5:]):
            return "html_attribute"
        if "<" in before and ">" in after:
            return "html_body"
        return "raw"
