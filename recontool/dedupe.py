from __future__ import annotations

from typing import Dict, Iterable, List

from .models import EndpointRecord


def fingerprint(record: EndpointRecord, mode: str = "strict") -> str:
    path = record.canonical_path if mode == "smart" else record.path
    query_names = sorted(p.name for p in record.params.values() if p.location == "query")
    body_names = sorted(p.name for p in record.params.values() if p.location == "body")
    json_names = sorted(p.name for p in record.params.values() if p.location == "json")
    return "|".join(
        [
            record.method,
            record.scheme,
            record.host,
            str(record.port or ""),
            path,
            "q:" + ",".join(query_names),
            "b:" + ",".join(body_names),
            "j:" + ",".join(json_names),
            "ct:" + (record.request_content_type or "").split(";")[0].strip().lower(),
            "auth:" + record.auth_context,
        ]
    )


def dedupe(records: Iterable[EndpointRecord], mode: str = "smart") -> List[EndpointRecord]:
    merged: Dict[str, EndpointRecord] = {}
    for record in records:
        key = fingerprint(record, mode)
        if key in merged:
            merged[key].merge(record)
        else:
            merged[key] = record
    return sorted(merged.values(), key=lambda r: (r.host, r.path, r.method))
