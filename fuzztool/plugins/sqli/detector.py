from __future__ import annotations


class SqliDetector:
    """Detector đơn giản cho SQLi candidate."""

    DB_ERROR_PATTERNS = [
        "sql syntax",
        "mysql",
        "mariadb",
        "pdo error",
        "database error",
        "you have an error in your sql",
        "ora-",
        "postgres",
        "sqlite",
    ]

    def has_db_error(self, text: str) -> bool:
        lowered = (text or "").lower()
        return any(pattern in lowered for pattern in self.DB_ERROR_PATTERNS)

    def response_changed(self, a: str, b: str) -> bool:
        if not a and not b:
            return False
        return abs(len(a) - len(b)) > max(20, int(max(len(a), len(b)) * 0.15))
