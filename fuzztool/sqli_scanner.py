from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from .http_client import FuzzHttpClient, RequestBudgetExceeded
from .models import Finding, FuzzTarget, HttpExchange
from .mutator import RequestMutator


class SqliScanner:
    """SQLi scanner: error-based, boolean-based va union-based."""

    DB_ERROR_PATTERNS = [
        "mysqli_sql_exception",
        "you have an error in your sql",
        "sql syntax",
        "mysql server version",
        "mysql_fetch",
        "mysql_num_rows",
        "pdoexception",
        "pdo error",
        "database error",
        "db_error",
        "extractvalue",
        "xpath syntax",
        "ora-",
        "postgresql error",
        "pg_query",
        "sqlite error",
        "sqliteexception",
        "syntax error",
    ]

    DEBUG_KEYS = {"sql", "query", "debug", "request", "payload", "raw", "raw_sql", "trace", "stack", "error", "errors"}
    ECHO_KEYS = {"id", "q", "keyword", "author", "sort", "page", "news_id", "category_id", "input", "value"}

    def __init__(
        self,
        client: FuzzHttpClient,
        config: dict,
        mutator: RequestMutator | None = None,
        on_finding: Callable[[Finding], None] | None = None,
    ) -> None:
        self.client = client
        self.config = config
        self.mutator = mutator or RequestMutator()
        self.on_finding = on_finding
        self.payloads = self._load_payloads()

        sqli_config = config.get("sqli", {})
        self.union_max_columns = int(sqli_config.get("union_max_columns", 12))
        self.union_marker_prefix = str(sqli_config.get("union_marker_prefix", "FUZZUNION"))

    def run(self, targets: list[FuzzTarget]) -> list[Finding]:
        findings: list[Finding] = []
        sqli_config = self.config.get("sqli", {})

        if sqli_config.get("error_based", True):
            findings.extend(self._scan_each_target(targets, self.scan_error_based_sqli))

        if sqli_config.get("boolean_based", False):
            findings.extend(self._scan_each_target(targets, self.scan_boolean_based_sqli))

        if sqli_config.get("union_based", False):
            findings.extend(self._scan_each_target(self._union_targets_first(targets), self.scan_union_based_sqli))

        return findings

    def scan_error_based_sqli(self, target: FuzzTarget) -> list[Finding]:
        """Gui payload pha SQL, neu response co loi DB thi ghi finding."""

        for payload in self._payloads_for(f"error.{self._payload_kind(target)}", target):
            response = self._send_payload(target, payload)
            evidence = self._db_error_evidence(response.text)
            if evidence:
                details = {
                    **evidence,
                    "content_type": response.headers.get("content-type", ""),
                    "elapsed_seconds": round(response.elapsed_seconds, 4),
                    "error": response.error,
                }
                return [self._finding("error_based", "high", target, payload, response, "database_error", details)]

        return []

    def scan_boolean_based_sqli(self, target: FuzzTarget) -> list[Finding]:
        """Gui cap payload true/false va so sanh response."""

        for true_payload, false_payload in self._boolean_payload_pairs(target):
            true_response = self._send_payload(target, true_payload)
            false_response = self._send_payload(target, false_payload)

            if true_response.error or false_response.error:
                continue
            if true_response.status != false_response.status:
                continue
            if not self._response_changed(true_response.text, false_response.text):
                continue

            details = {
                "true_length": len(true_response.text),
                "false_length": len(false_response.text),
            }
            payload = f"{true_payload} / {false_payload}"
            return [self._finding("boolean_based", "medium", target, payload, true_response, "true_false_diff", details)]

        return []

    def scan_union_based_sqli(self, target: FuzzTarget) -> list[Finding]:
        """Thu UNION SELECT va chi ghi finding khi marker nam trong data field."""

        baseline = self._send_baseline(target)
        if baseline.error:
            print(f"[!] Skip union target: {target.key} baseline error={baseline.error}")
            return []

        marker = self._new_marker()
        if marker in baseline.text:
            return []

        for column_count in range(1, self.union_max_columns + 1):
            columns = self._union_columns(marker, column_count)
            for payload in self._payloads_for(f"union.{self._payload_kind(target)}", target, {"columns": columns}):
                response = self._send_payload(target, payload)
                if response.error:
                    continue

                evidence = self._marker_evidence(response.text, marker, response.headers.get("content-type", ""))
                if not evidence:
                    continue

                details = {
                    **evidence,
                    "column_count": column_count,
                    "content_type": response.headers.get("content-type", ""),
                    "elapsed_seconds": round(response.elapsed_seconds, 4),
                }
                return [self._finding("union_based", "high", target, payload, response, "union_marker", details)]

        return []

    def _scan_each_target(self, targets: list[FuzzTarget], scan_func) -> list[Finding]:
        findings: list[Finding] = []
        for target in targets:
            try:
                findings.extend(scan_func(target))
            except RequestBudgetExceeded as error:
                print(f"[!] {error}")
                return findings
        return findings

    def _send_baseline(self, target: FuzzTarget) -> HttpExchange:
        method, url, body, headers = self.mutator.baseline(target)
        return self.client.send(method, url, body=body, headers=headers)

    def _send_payload(self, target: FuzzTarget, payload: str) -> HttpExchange:
        method, url, body, headers = self.mutator.mutate(target, payload)
        return self.client.send(method, url, body=body, headers=headers)

    def _finding(
        self,
        subtype: str,
        severity: str,
        target: FuzzTarget,
        payload: str,
        response: HttpExchange,
        evidence: str,
        details: dict,
    ) -> Finding:
        finding = Finding(
            vuln_type="sqli",
            subtype=subtype,
            severity=severity,
            target=target,
            payload=payload,
            evidence=evidence,
            request_url=response.url,
            status=response.status,
            details=details,
        )
        if self.on_finding:
            self.on_finding(finding)
        return finding

    def _payload_kind(self, target: FuzzTarget) -> str:
        return "numeric" if target.type_hint in {"int", "float"} else "string"

    def _boolean_payload_pairs(self, target: FuzzTarget) -> list[tuple[str, str]]:
        kind = self._payload_kind(target)
        true_payloads = self._payloads_for(f"boolean.{kind}.true", target)
        false_payloads = self._payloads_for(f"boolean.{kind}.false", target)
        return list(zip(true_payloads, false_payloads))

    def _payloads_for(self, section: str, target: FuzzTarget, extra: dict[str, str] | None = None) -> list[str]:
        rendered_payloads = []
        for template in self.payloads.get(section, []):
            payload = template.replace("{sample}", target.sample_value)
            for key, value in (extra or {}).items():
                payload = payload.replace("{" + key + "}", value)
            rendered_payloads.append(payload)
        return rendered_payloads

    def _load_payloads(self) -> dict[str, list[str]]:
        payload_file = Path(__file__).with_name("payloads") / "sqli.txt"
        sections: dict[str, list[str]] = {}
        current_section = ""

        for raw_line in payload_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip()
                sections.setdefault(current_section, [])
                continue
            if current_section:
                sections[current_section].append(line)

        return sections

    def _db_error_evidence(self, text: str) -> dict:
        compact = self._compact(text)
        lowered = compact.lower()
        matched = [pattern for pattern in self.DB_ERROR_PATTERNS if pattern in lowered]
        if not matched:
            return {}

        first_index = min(lowered.find(pattern) for pattern in matched)
        return {
            "matched_patterns": matched,
            "response_excerpt": self._excerpt(compact, first_index, 800),
        }

    def _response_changed(self, true_text: str, false_text: str) -> bool:
        if not true_text and not false_text:
            return False
        bigger_size = max(len(true_text), len(false_text))
        minimum_delta = max(20, int(bigger_size * 0.15))
        return abs(len(true_text) - len(false_text)) > minimum_delta

    def _marker_evidence(self, text: str, marker: str, content_type: str) -> dict:
        if "json" in content_type.lower():
            return self._json_marker_evidence(text, marker)
        return self._text_marker_evidence(text, marker)

    def _json_marker_evidence(self, text: str, marker: str) -> dict:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {}

        matched_paths: list[str] = []
        ignored_paths: list[str] = []
        matched_values: list[str] = []
        self._walk_json(data, marker, [], matched_paths, ignored_paths, matched_values)

        if not matched_paths:
            return {}

        return {
            "marker": marker,
            "matched_paths": matched_paths,
            "ignored_paths": ignored_paths,
            "response_excerpt": self._compact(matched_values[0])[:500],
        }

    def _walk_json(
        self,
        value: Any,
        marker: str,
        path: list[str],
        matched_paths: list[str],
        ignored_paths: list[str],
        matched_values: list[str],
    ) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                self._walk_json(child, marker, [*path, str(key)], matched_paths, ignored_paths, matched_values)
            return

        if isinstance(value, list):
            for index, child in enumerate(value):
                self._walk_json(child, marker, [*path, str(index)], matched_paths, ignored_paths, matched_values)
            return

        if marker not in str(value):
            return

        path_text = ".".join(path) if path else "$"
        if self._ignored_json_path(path):
            ignored_paths.append(path_text)
            return

        matched_paths.append(path_text)
        matched_values.append(str(value))

    def _ignored_json_path(self, path: list[str]) -> bool:
        lowered = [item.lower() for item in path]
        return any(item in self.DEBUG_KEYS for item in lowered) or (len(lowered) == 1 and lowered[0] in self.ECHO_KEYS)

    def _text_marker_evidence(self, text: str, marker: str) -> dict:
        compact = self._compact(text)
        marker_index = compact.find(marker)
        if marker_index < 0:
            return {}
        return {
            "marker": marker,
            "matched_paths": [],
            "ignored_paths": [],
            "response_excerpt": self._excerpt(compact, marker_index, 500),
        }

    def _compact(self, text: str) -> str:
        without_tags = re.sub(r"<[^>]+>", " ", text or "")
        return re.sub(r"\s+", " ", without_tags).strip()

    def _excerpt(self, text: str, center_index: int, size: int) -> str:
        start = max(0, center_index - 160)
        end = min(len(text), start + size)
        return text[start:end]

    def _new_marker(self) -> str:
        return f"{self.union_marker_prefix}_{uuid4().hex[:8]}"

    def _union_columns(self, marker: str, column_count: int) -> str:
        return ",".join([f"'{marker}'" for _ in range(column_count)])

    def _union_targets_first(self, targets: list[FuzzTarget]) -> list[FuzzTarget]:
        def score(target: FuzzTarget) -> tuple[int, int, int, str]:
            name = target.param_name.lower()
            type_score = 0 if target.type_hint in {"int", "float"} else 1
            name_score = 0 if name == "id" or name.endswith("_id") else 1
            location_score = {"query": 0, "body": 1, "json": 2}.get(target.param_location, 3)
            return type_score, name_score, location_score, target.key

        return sorted(targets, key=score)
