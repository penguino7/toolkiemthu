from __future__ import annotations

from fuzztool.models import HttpExchange

from .detectors import AiTestDetectors


class ResponseSummarizer:
    """Tao response context vua du de AI doc, khong nem HTML dai vao prompt."""

    def __init__(self, detector: AiTestDetectors | None = None, options: dict | None = None) -> None:
        options = options or {}
        self.detector = detector or AiTestDetectors()
        self.full_raw_under_chars = int(options.get("full_raw_under_chars", 4000))
        self.json_raw_under_chars = int(options.get("json_raw_under_chars", 8000))
        self.raw_head_chars = int(options.get("raw_head_chars", 2000))
        self.raw_tail_chars = int(options.get("raw_tail_chars", 2000))
        self.signal_window_chars = int(options.get("signal_window_chars", 700))
        self.text_preview_chars = int(options.get("text_preview_chars", 1200))

    def summarize(self, exchange: HttpExchange, marker: str) -> dict:
        content_type = exchange.headers.get("content-type", "")
        text = exchange.text or ""
        compact = self.detector.compact_text(text)
        signals = self.detector.detect(exchange, marker)

        return {
            "status": exchange.status,
            "url": exchange.url,
            "content_type": content_type,
            "elapsed_seconds": round(exchange.elapsed_seconds, 4),
            "response_length": len(text),
            "error": exchange.error,
            "signals": signals,
            "excerpt": compact[: self.text_preview_chars],
            "response_context": self._response_context(text, compact, content_type, marker, signals),
        }

    def _response_context(self, text: str, compact: str, content_type: str, marker: str, signals: dict) -> dict:
        if not text:
            return {"mode": "empty", "text_preview": ""}

        context = {
            "mode": "smart",
            "text_preview": compact[: self.text_preview_chars],
            "signal_windows": self._signal_windows(text, marker, signals),
        }

        if self._should_send_full_raw(text, content_type):
            context["mode"] = "full"
            context["raw_response"] = text
            return context

        context["raw_head"] = text[: self.raw_head_chars]
        context["raw_tail"] = text[-self.raw_tail_chars :] if self.raw_tail_chars > 0 else ""
        return context

    def _should_send_full_raw(self, text: str, content_type: str) -> bool:
        length = len(text)
        if "json" in content_type.lower():
            return length <= self.json_raw_under_chars
        return length <= self.full_raw_under_chars

    def _signal_windows(self, text: str, marker: str, signals: dict) -> list[dict]:
        windows = []
        seen = set()

        self._add_window(windows, seen, text, marker, "marker")
        for pattern in signals.get("sql_error_patterns", []):
            self._add_window(windows, seen, text, pattern, "sql_error", case_sensitive=False)

        return windows

    def _add_window(
        self,
        windows: list[dict],
        seen: set[tuple[str, int]],
        text: str,
        needle: str,
        label: str,
        case_sensitive: bool = True,
    ) -> None:
        if not needle:
            return

        haystack = text if case_sensitive else text.lower()
        query = needle if case_sensitive else needle.lower()
        index = haystack.find(query)
        if index < 0:
            return

        key = (label, index)
        if key in seen:
            return
        seen.add(key)

        half = max(80, self.signal_window_chars // 2)
        start = max(0, index - half)
        end = min(len(text), index + len(needle) + half)
        windows.append(
            {
                "type": label,
                "match": needle,
                "start": start,
                "end": end,
                "text": text[start:end],
            }
        )
