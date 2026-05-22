from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple
from uuid import uuid4

from .http_client import FuzzHttpClient, RequestBudgetExceeded
from .models import Finding, FuzzTarget
from .mutator import RequestMutator


class SqliScanner:
    """Scanner SQLi gom error-based, boolean-based va union-based.

    Moi loai SQLi van co ham rieng de de doc:
    - scan_error_based_sqli()
    - scan_boolean_based_sqli()
    - scan_union_based_sqli()
    """

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
    DEBUG_JSON_KEYS = {
        "sql",
        "query",
        "debug",
        "request",
        "payload",
        "raw",
        "raw_sql",
        "trace",
        "stack",
        "error",
        "errors",
    }
    TOP_LEVEL_ECHO_KEYS = {
        "id",
        "q",
        "keyword",
        "author",
        "sort",
        "page",
        "news_id",
        "category_id",
        "input",
        "value",
    }

    def __init__(self, client: FuzzHttpClient, config: dict, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.config = config
        self.mutator = mutator or RequestMutator()
        self.payload_sections = self._load_payload_sections()

        sqli_config = config.get("sqli", {})
        self.union_max_columns = int(sqli_config.get("union_max_columns", 12))
        self.union_marker_prefix = str(sqli_config.get("union_marker_prefix", "FUZZUNION"))

    def run(self, targets: List[FuzzTarget]) -> List[Finding]:
        options = self.config.get("sqli", {})
        findings: List[Finding] = []

        if options.get("error_based", True):
            findings.extend(self._scan_targets(targets, self.scan_error_based_sqli))

        if options.get("boolean_based", False):
            findings.extend(self._scan_targets(targets, self.scan_boolean_based_sqli))

        if options.get("union_based", False):
            prioritized_targets = self._prioritize_union_targets(targets)
            findings.extend(self._scan_targets(prioritized_targets, self.scan_union_based_sqli))

        return findings

    def scan_error_based_sqli(self, target: FuzzTarget) -> List[Finding]:
        """Gui payload pha SQL va tim loi database trong response."""

        for payload in self._error_payloads(target):
            method, url, body, headers = self.mutator.mutate(target, payload)
            response = self.client.send(method, url, body=body, headers=headers)

            db_error = self._db_error_evidence(response.text)
            if not db_error:
                continue

            return [
                Finding(
                    vuln_type="sqli",
                    subtype="error_based",
                    severity="high",
                    target=target,
                    payload=payload,
                    evidence="database_error_response",
                    request_url=response.url,
                    status=response.status,
                    details={
                        "matched_patterns": db_error.get("matched_patterns", []),
                        "response_excerpt": db_error.get("response_excerpt", ""),
                        "response_content_type": response.headers.get("content-type", ""),
                        "elapsed_seconds": round(response.elapsed_seconds, 4),
                        "error": response.error,
                    },
                )
            ]

        return []

    def scan_boolean_based_sqli(self, target: FuzzTarget) -> List[Finding]:
        """So sanh response khi dieu kien SQL dung va sai."""

        for true_payload, false_payload in self._boolean_payload_pairs(target):
            true_method, true_url, true_body, true_headers = self.mutator.mutate(target, true_payload)
            true_response = self.client.send(true_method, true_url, body=true_body, headers=true_headers)

            false_method, false_url, false_body, false_headers = self.mutator.mutate(target, false_payload)
            false_response = self.client.send(false_method, false_url, body=false_body, headers=false_headers)

            if true_response.error or false_response.error:
                continue

            same_status = true_response.status == false_response.status
            response_is_different = self._response_changed(true_response.text, false_response.text)
            if not same_status or not response_is_different:
                continue

            return [
                Finding(
                    vuln_type="sqli",
                    subtype="boolean_based",
                    severity="medium",
                    target=target,
                    payload=f"{true_payload} / {false_payload}",
                    evidence="true_false_response_difference",
                    request_url=true_response.url,
                    status=true_response.status,
                    details={
                        "true_length": len(true_response.text),
                        "false_length": len(false_response.text),
                    },
                )
            ]

        return []

    def scan_union_based_sqli(self, target: FuzzTarget) -> List[Finding]:
        """Thu UNION SELECT va chi ghi finding khi marker xuat hien trong response."""

        baseline_response = self._send_baseline(target)
        if baseline_response.error:
            print(f"[!] Skip union-based target because baseline failed: {target.key} error={baseline_response.error}")
            return []

        marker = self._new_union_marker()
        if marker in baseline_response.text:
            return []

        for column_count in range(1, self.union_max_columns + 1):
            columns_sql = self._union_columns(marker, column_count)

            for payload in self._union_payloads(target, columns_sql):
                method, url, body, headers = self.mutator.mutate(target, payload)
                response = self.client.send(method, url, body=body, headers=headers)

                if response.error:
                    continue

                marker_evidence = self._marker_evidence(
                    response.text,
                    marker,
                    response.headers.get("content-type", ""),
                )
                if not marker_evidence:
                    continue

                return [
                    Finding(
                        vuln_type="sqli",
                        subtype="union_based",
                        severity="high",
                        target=target,
                        payload=payload,
                        evidence="union_marker_in_response",
                        request_url=response.url,
                        status=response.status,
                        details={
                            "analysis_summary": (
                                "Union-based SQLi confirmed because a scanner-generated marker was returned "
                                "inside application data fields, not only inside debug SQL or echoed input."
                            ),
                            "confirmation_reason": "marker_found_in_non_debug_json_fields",
                            "marker": marker,
                            "column_count": column_count,
                            "matched_paths": marker_evidence.get("matched_paths", []),
                            "ignored_paths": marker_evidence.get("ignored_paths", []),
                            "ignored_reason": (
                                "Paths such as sql/debug/request and top-level echoed input fields are ignored "
                                "to reduce false positives."
                            ),
                            "response_excerpt": marker_evidence.get("response_excerpt", ""),
                            "response_content_type": response.headers.get("content-type", ""),
                            "elapsed_seconds": round(response.elapsed_seconds, 4),
                            "test_more_suggestions": [
                                "Use ORDER BY to confirm the SELECT column count.",
                                "Move the marker across individual UNION columns to identify which columns are rendered.",
                                "After authorization, test whether database metadata or low-risk proof values can be returned.",
                            ],
                            "remediation_hint": (
                                "Use parameterized queries/prepared statements, validate numeric parameters as integers, "
                                "and remove SQL/debug output from API responses."
                            ),
                        },
                    )
                ]

        return []

    def _scan_targets(self, targets: List[FuzzTarget], scan_function) -> List[Finding]:
        findings: List[Finding] = []
        for target in targets:
            try:
                findings.extend(scan_function(target))
            except RequestBudgetExceeded as error:
                print(f"[!] {error}")
                return findings
        return findings

    def _send_baseline(self, target: FuzzTarget):
        method, url, body, headers = self.mutator.baseline(target)
        return self.client.send(method, url, body=body, headers=headers)

    def _error_payloads(self, target: FuzzTarget) -> List[str]:
        return self._render_payload_section(f"error.{self._payload_kind(target)}", target)

    def _boolean_payload_pairs(self, target: FuzzTarget) -> List[Tuple[str, str]]:
        kind = self._payload_kind(target)
        true_payloads = self._render_payload_section(f"boolean.{kind}.true", target)
        false_payloads = self._render_payload_section(f"boolean.{kind}.false", target)
        return list(zip(true_payloads, false_payloads))

    def _union_payloads(self, target: FuzzTarget, columns_sql: str) -> List[str]:
        return self._render_payload_section(f"union.{self._payload_kind(target)}", target, {"columns": columns_sql})

    def _payload_kind(self, target: FuzzTarget) -> str:
        return "numeric" if target.type_hint in {"int", "float"} else "string"

    def _render_payload_section(
        self,
        section_name: str,
        target: FuzzTarget,
        extra_values: Dict[str, str] | None = None,
    ) -> List[str]:
        payloads: List[str] = []
        for template in self.payload_sections.get(section_name, []):
            payload = template.replace("{sample}", target.sample_value)
            for name, value in (extra_values or {}).items():
                payload = payload.replace("{" + name + "}", value)
            payloads.append(payload)
        return payloads

    def _load_payload_sections(self) -> Dict[str, List[str]]:
        payload_file = Path(__file__).with_name("payloads") / "sqli.txt"
        sections: Dict[str, List[str]] = {}
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
                sections.setdefault(current_section, []).append(line)

        return sections

    def _db_error_evidence(self, text: str, max_chars: int = 800) -> dict:
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

    def _response_changed(self, true_text: str, false_text: str) -> bool:
        if not true_text and not false_text:
            return False
        bigger_response_size = max(len(true_text), len(false_text))
        minimum_delta = max(20, int(bigger_response_size * 0.15))
        return abs(len(true_text) - len(false_text)) > minimum_delta

    def _marker_evidence(self, text: str, marker: str, content_type: str = "", max_chars: int = 500) -> dict:
        json_evidence = self._json_marker_evidence(text, marker)
        if json_evidence:
            return json_evidence

        if "json" in (content_type or "").lower():
            return {}

        return self._text_marker_evidence(text, marker, max_chars)

    def _json_marker_evidence(self, text: str, marker: str) -> dict:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {}

        matched_paths: List[str] = []
        ignored_paths: List[str] = []
        matched_values: List[str] = []

        self._find_marker_in_json(data, marker, [], matched_paths, ignored_paths, matched_values)
        if not matched_paths:
            return {}

        return {
            "marker": marker,
            "matched_paths": matched_paths,
            "ignored_paths": ignored_paths,
            "response_excerpt": self._short_json_value(matched_values[0]),
        }

    def _find_marker_in_json(
        self,
        value: Any,
        marker: str,
        path: List[str],
        matched_paths: List[str],
        ignored_paths: List[str],
        matched_values: List[str],
    ) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                self._find_marker_in_json(child, marker, [*path, str(key)], matched_paths, ignored_paths, matched_values)
            return

        if isinstance(value, list):
            for index, child in enumerate(value):
                self._find_marker_in_json(child, marker, [*path, str(index)], matched_paths, ignored_paths, matched_values)
            return

        if marker not in str(value):
            return

        path_text = ".".join(path) if path else "$"
        if self._is_ignored_marker_path(path):
            ignored_paths.append(path_text)
            return

        matched_paths.append(path_text)
        matched_values.append(str(value))

    def _is_ignored_marker_path(self, path: List[str]) -> bool:
        lowered_path = [item.lower() for item in path]
        if any(item in self.DEBUG_JSON_KEYS for item in lowered_path):
            return True
        return len(lowered_path) == 1 and lowered_path[0] in self.TOP_LEVEL_ECHO_KEYS

    def _short_json_value(self, value: str, max_chars: int = 500) -> str:
        compacted = self._compact_text(value)
        return compacted[:max_chars]

    def _text_marker_evidence(self, text: str, marker: str, max_chars: int = 500) -> dict:
        cleaned = self._compact_text(text or "")
        marker_index = cleaned.find(marker)
        if marker_index < 0:
            return {}

        excerpt_start = max(0, marker_index - 160)
        excerpt_end = min(len(cleaned), marker_index + len(marker) + max_chars)
        return {
            "marker": marker,
            "matched_paths": [],
            "ignored_paths": [],
            "response_excerpt": cleaned[excerpt_start:excerpt_end],
        }

    def _compact_text(self, text: str) -> str:
        no_tags = re.sub(r"<[^>]+>", " ", text)
        return re.sub(r"\s+", " ", no_tags).strip()

    def _new_union_marker(self) -> str:
        return f"{self.union_marker_prefix}_{uuid4().hex[:8]}"

    def _union_columns(self, marker: str, column_count: int) -> str:
        quoted_marker = f"'{marker}'"
        return ",".join([quoted_marker for _ in range(column_count)])

    def _prioritize_union_targets(self, targets: List[FuzzTarget]) -> List[FuzzTarget]:
        def priority(target: FuzzTarget) -> tuple[int, int, int, str]:
            name = target.param_name.lower()
            numeric_type = 0 if target.type_hint in {"int", "float"} else 1
            id_like_name = 0 if name == "id" or name.endswith("_id") or name in {"filter_cat", "edit_id"} else 1
            location_score = {"query": 0, "body": 1, "json": 2}.get(target.param_location, 3)
            return numeric_type, id_like_name, location_score, target.key

        return sorted(targets, key=priority)
