from __future__ import annotations


class XssDetector:
    """Detector phu tro de tim marker trong HTTP response.

    Detector nay khong tu ket luan XSS. No chi giup reflected scanner loc ra
    response co marker truoc khi BrowserXssVerifier mo browser de xac minh
    payload co thuc thi JavaScript hay khong.
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
