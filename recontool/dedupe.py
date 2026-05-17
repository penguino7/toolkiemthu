from __future__ import annotations

from typing import Dict, Iterable, List

from .models import EndpointRecord


class EndpointDeduplicator:
    """Gom các endpoint trùng nhau.

    `strict` dùng path thật. `smart` dùng canonical_path, nên `/news/1` và
    `/news/2` được xem là cùng một dạng endpoint.
    """

    def __init__(self, mode: str = "smart") -> None:
        self.mode = mode

    def dedupe(self, records: Iterable[EndpointRecord]) -> List[EndpointRecord]:
        merged: Dict[str, EndpointRecord] = {}
        for record in records:
            key = self.fingerprint(record)
            if key in merged:
                merged[key].merge(record)
            else:
                merged[key] = record
        return sorted(merged.values(), key=lambda r: (r.host, r.path, r.method))

    def fingerprint(self, record: EndpointRecord) -> str:
        path = record.canonical_path if self.mode == "smart" else record.path
        query_names = self._param_names(record, "query")
        body_names = self._param_names(record, "body")
        json_names = self._param_names(record, "json")
        content_type = (record.request_content_type or "").split(";")[0].strip().lower()

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
                "ct:" + content_type,
                "auth:" + record.auth_context,
            ]
        )

    def _param_names(self, record: EndpointRecord, location: str) -> List[str]:
        return sorted(param.name for param in record.params.values() if param.location == location)


def fingerprint(record: EndpointRecord, mode: str = "strict") -> str:
    return EndpointDeduplicator(mode=mode).fingerprint(record)


def dedupe(records: Iterable[EndpointRecord], mode: str = "smart") -> List[EndpointRecord]:
    return EndpointDeduplicator(mode=mode).dedupe(records)
