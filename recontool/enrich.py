from __future__ import annotations

from typing import Iterable, List

from .models import EndpointRecord, Param


TEXT_NAMES = {
    "q",
    "query",
    "search",
    "keyword",
    "content",
    "comment",
    "message",
    "body",
    "bio",
    "title",
    "summary",
    "tag",
    "tags",
    "name",
    "author",
    "author_name",
    "username",
}


class RecordEnricher:
    """Gắn nhãn candidate dựa trên metadata đã quan sát được.

    Class này không kết luận có lỗ hổng. Nó chỉ giúp người học biết endpoint
    nào nên được ưu tiên kiểm thử thủ công ở bước sau.
    """

    def enrich_many(self, records: Iterable[EndpointRecord]) -> List[EndpointRecord]:
        return [self.enrich_one(record) for record in records]

    def enrich_one(self, record: EndpointRecord) -> EndpointRecord:
        tests = set(record.candidate_tests)
        is_json = "json" in (record.response_content_type or "").lower()
        is_html = "html" in (record.response_content_type or "").lower()

        if record.evidence.get("db_error_pattern"):
            tests.add("sqli_error_evidence")
        if record.evidence.get("reflection_contexts"):
            tests.add("reflection_detected")

        for param in record.params.values():
            param_tests = set(param.candidate_tests)
            self._mark_sql_candidates(param, param_tests, tests, is_json)
            self._mark_xss_candidates(param, record, param_tests, tests, is_json, is_html)
            param.candidate_tests = sorted(param_tests)

        if record.forms:
            tests.add("form_endpoint")

        record.candidate_tests = sorted(tests)
        return record

    def _mark_sql_candidates(self, param: Param, param_tests: set, record_tests: set, is_json: bool) -> None:
        if not self._is_probably_sql_param(param):
            return
        param_tests.add("sqli")
        record_tests.add("sqli_json" if is_json else "sqli")

    def _mark_xss_candidates(
        self,
        param: Param,
        record: EndpointRecord,
        param_tests: set,
        record_tests: set,
        is_json: bool,
        is_html: bool,
    ) -> None:
        if not self._is_probably_xss_param(param):
            return

        if param.location in {"body", "json"} and record.method == "POST":
            param_tests.add("stored_xss_candidate")
            record_tests.add("stored_xss_candidate")
        elif param.reflected or is_html:
            param_tests.add("reflected_xss_candidate")
            record_tests.add("reflected_xss_candidate")

        if param.reflected:
            param_tests.add("reflection_detected")
        if is_json:
            param_tests.add("api_xss_source")
            record_tests.add("api_xss_source")

    def _is_probably_sql_param(self, param: Param) -> bool:
        name = param.name.lower()
        if param.type_hint in {"int", "float"}:
            return True
        return name in {"id", "user", "username", "author", "keyword", "q", "search"} or name.endswith("_id")

    def _is_probably_xss_param(self, param: Param) -> bool:
        name = param.name.lower()
        return param.reflected or name in TEXT_NAMES or any(token in name for token in ["name", "text", "html", "desc"])


def enrich_record(record: EndpointRecord) -> EndpointRecord:
    return RecordEnricher().enrich_one(record)


def enrich_records(records: Iterable[EndpointRecord]) -> List[EndpointRecord]:
    return RecordEnricher().enrich_many(records)
