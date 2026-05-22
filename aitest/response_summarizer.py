from __future__ import annotations

from fuzztool.models import HttpExchange

from .detectors import AiTestDetectors


class ResponseSummarizer:
    """Rút gọn response để gửi cho AI ở vòng tiếp theo."""

    def __init__(self, detector: AiTestDetectors | None = None, max_excerpt_chars: int = 1200) -> None:
        self.detector = detector or AiTestDetectors()
        self.max_excerpt_chars = max_excerpt_chars

    def summarize(self, exchange: HttpExchange, marker: str) -> dict:
        content_type = exchange.headers.get("content-type", "")
        compact = self.detector.compact_text(exchange.text)
        signals = self.detector.detect(exchange, marker)

        return {
            "status": exchange.status,
            "url": exchange.url,
            "content_type": content_type,
            "elapsed_seconds": round(exchange.elapsed_seconds, 4),
            "response_length": len(exchange.text or ""),
            "error": exchange.error,
            "signals": signals,
            "excerpt": compact[: self.max_excerpt_chars],
        }
