from __future__ import annotations

import re


class SqliDetector:
    """Detector đơn giản cho SQLi candidate."""

    DB_ERROR_PATTERNS = [
        "sql syntax",
        "mysql",
        "mariadb",
        "pdo error",
        "database error",
        "db_error",
        "syntax error",
        "you have an error in your sql",
        "extractvalue",
        "xpath syntax",
        "ora-",
        "postgres",
        "sqlite",
    ]

    def has_db_error(self, text: str) -> bool:
        return bool(self.db_error_evidence(text))

    def db_error_evidence(self, text: str, max_chars: int = 800) -> dict:
        cleaned = self._compact_text(text or "")
        lowered = cleaned.lower()
        matched_patterns = [pattern for pattern in self.DB_ERROR_PATTERNS if pattern in lowered]
        if not matched_patterns:
            return {}

        first_match_index = min(lowered.find(pattern) for pattern in matched_patterns)
        excerpt_start = max(0, first_match_index - 160)
        excerpt_end = min(len(cleaned), excerpt_start + max_chars)

        return {
            "matched_patterns": matched_patterns,
            "response_excerpt": cleaned[excerpt_start:excerpt_end],
        }

    def response_changed(self, a: str, b: str) -> bool:
        if not a and not b:
            return False
        return abs(len(a) - len(b)) > max(20, int(max(len(a), len(b)) * 0.15))

    def marker_evidence(self, text: str, marker: str, max_chars: int = 500) -> dict:
        cleaned = self._compact_text(text or "")
        marker_index = cleaned.find(marker)
        if marker_index < 0:
            return {}

        excerpt_start = max(0, marker_index - 160)
        excerpt_end = min(len(cleaned), marker_index + len(marker) + max_chars)
        return {
            "marker": marker,
            "response_excerpt": cleaned[excerpt_start:excerpt_end],
        }

    def _compact_text(self, text: str) -> str:
        no_tags = re.sub(r"<[^>]+>", " ", text)
        return re.sub(r"\s+", " ", no_tags).strip()
