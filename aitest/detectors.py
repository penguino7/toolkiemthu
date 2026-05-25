from __future__ import annotations

import json
import re
from typing import Any, List

from fuzztool.models import HttpExchange


class AiTestDetectors:
    """Detector nhẹ để tóm tắt signal sau mỗi vòng AI test."""

    DB_ERROR_PATTERNS = [
        "mysqli_sql_exception",
        "you have an error in your sql",
        "sql syntax",
        "database error",
        "pdoexception",
        "unknown column",
        "different number of columns",
        "order by position",
        "extractvalue",
        "xpath syntax",
    ]

    DEBUG_JSON_KEYS = {"sql", "query", "debug", "request", "payload", "raw", "trace", "error", "errors"}
    TOP_LEVEL_ECHO_KEYS = {"id", "q", "keyword", "author", "sort", "page", "input", "value"}

    def detect(self, exchange: HttpExchange, marker: str) -> dict:
        text = exchange.text or ""
        content_type = exchange.headers.get("content-type", "")
        marker_info = self.marker_paths(text, marker, content_type)
        sql_errors = self.sql_error_patterns(text)
        compact = self.compact_text(text)
        marker_index = compact.find(marker)
        marker_in_html = marker in text and "html" in content_type.lower()

        return {
            "sql_error_patterns": sql_errors,
            "marker_in_response": marker in text,
            "marker_in_html": marker_in_html,
            "marker_in_data": bool(marker_info.get("matched_paths")),
            "matched_paths": marker_info.get("matched_paths", []),
            "ignored_paths": marker_info.get("ignored_paths", []),
            "visible_columns": self.visible_columns(text, marker),
            "marker_excerpt": self._excerpt(compact, marker_index, 300) if marker_index >= 0 else "",
            "xss_reflection": marker in text and "html" in content_type.lower(),
            "confirmed_signal": bool(marker_info.get("matched_paths")) or bool(sql_errors) or marker_in_html,
        }

    def sql_error_patterns(self, text: str) -> List[str]:
        lowered = (text or "").lower()
        return [pattern for pattern in self.DB_ERROR_PATTERNS if pattern in lowered]

    def marker_paths(self, text: str, marker: str, content_type: str = "") -> dict:
        if "json" not in (content_type or "").lower():
            return {"matched_paths": [], "ignored_paths": []}

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {"matched_paths": [], "ignored_paths": []}

        matched_paths: List[str] = []
        ignored_paths: List[str] = []
        self._walk_json(data, marker, [], matched_paths, ignored_paths)
        return {"matched_paths": matched_paths, "ignored_paths": ignored_paths}

    def _walk_json(self, value: Any, marker: str, path: List[str], matched: List[str], ignored: List[str]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                self._walk_json(child, marker, [*path, str(key)], matched, ignored)
            return

        if isinstance(value, list):
            for index, child in enumerate(value):
                self._walk_json(child, marker, [*path, str(index)], matched, ignored)
            return

        if marker not in str(value):
            return

        path_text = ".".join(path) if path else "$"
        if self._is_ignored_path(path):
            ignored.append(path_text)
        else:
            matched.append(path_text)

    def _is_ignored_path(self, path: List[str]) -> bool:
        lowered = [item.lower() for item in path]
        if any(item in self.DEBUG_JSON_KEYS for item in lowered):
            return True
        return len(lowered) == 1 and lowered[0] in self.TOP_LEVEL_ECHO_KEYS

    def compact_text(self, text: str) -> str:
        no_tags = re.sub(r"<[^>]+>", " ", text or "")
        return re.sub(r"\s+", " ", no_tags).strip()

    def visible_columns(self, text: str, marker: str) -> List[str]:
        pattern = re.escape(marker) + r"_C(\d+)"
        return sorted(set(re.findall(pattern, text or "")), key=int)

    def _excerpt(self, text: str, center_index: int, size: int) -> str:
        start = max(0, center_index - 120)
        end = min(len(text), start + size)
        return text[start:end]
