from __future__ import annotations

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


def _is_probably_sql_param(param: Param) -> bool:
    name = param.name.lower()
    if param.type_hint in {"int", "float"}:
        return True
    return name in {"id", "user", "username", "author", "keyword", "q", "search"} or name.endswith("_id")


def _is_probably_xss_param(param: Param) -> bool:
    name = param.name.lower()
    return param.reflected or name in TEXT_NAMES or any(token in name for token in ["name", "text", "html", "desc"])


def enrich_record(record: EndpointRecord) -> EndpointRecord:
    tests = set(record.candidate_tests)
    is_json = "json" in (record.response_content_type or "").lower()
    is_html = "html" in (record.response_content_type or "").lower()

    if record.evidence.get("db_error_pattern"):
        tests.add("sqli_error_evidence")

    for param in record.params.values():
        param_tests = set(param.candidate_tests)
        if _is_probably_sql_param(param):
            param_tests.add("sqli")
            tests.add("sqli_json" if is_json else "sqli")
        if _is_probably_xss_param(param):
            if param.location in {"body", "json"} and record.method == "POST":
                param_tests.add("stored_xss_candidate")
                tests.add("stored_xss_candidate")
            elif param.reflected or is_html:
                param_tests.add("reflected_xss_candidate")
                tests.add("reflected_xss_candidate")
            if is_json:
                param_tests.add("api_xss_source")
                tests.add("api_xss_source")
        param.candidate_tests = sorted(param_tests)

    if record.forms:
        tests.add("form_endpoint")

    record.candidate_tests = sorted(tests)
    return record


def enrich_records(records):
    return [enrich_record(record) for record in records]
