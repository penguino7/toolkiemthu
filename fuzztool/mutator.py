from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .models import FuzzTarget


class RequestMutator:
    """Thay giá trị của một param bằng payload fuzz."""

    def mutate(self, target: FuzzTarget, payload: str) -> tuple[str, str, str | None, dict]:
        if target.param_location == "query":
            return self._mutate_query(target, payload)
        if target.param_location == "body":
            return self._mutate_body(target, payload)
        if target.param_location == "json":
            return self._mutate_json(target, payload)
        return target.method, target.url, None, dict(target.request_headers)

    def baseline(self, target: FuzzTarget) -> tuple[str, str, str | None, dict]:
        return self.mutate(target, target.sample_value)

    def _mutate_query(self, target: FuzzTarget, payload: str) -> tuple[str, str, str | None, dict]:
        parsed = urlparse(target.url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        updated = []
        replaced = False
        for name, value in pairs:
            if name == target.param_name:
                updated.append((name, payload))
                replaced = True
            else:
                updated.append((name, value))
        if not replaced:
            updated.append((target.param_name, payload))
        url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(updated), parsed.fragment))
        return target.method, url, None, dict(target.request_headers)

    def _mutate_body(self, target: FuzzTarget, payload: str) -> tuple[str, str, str, dict]:
        pairs = []
        for param in target.record.get("params", []):
            if param.get("location") != "body":
                continue
            name = str(param.get("name", ""))
            values = param.get("sample_values", [])
            value = payload if name == target.param_name else (str(values[0]) if values else "")
            pairs.append((name, value))
        if not any(name == target.param_name for name, _ in pairs):
            pairs.append((target.param_name, payload))
        headers = dict(target.request_headers)
        headers["content-type"] = "application/x-www-form-urlencoded"
        return target.method, target.url, urlencode(pairs), headers

    def _mutate_json(self, target: FuzzTarget, payload: str) -> tuple[str, str, str, dict]:
        data = {}
        for param in target.record.get("params", []):
            if param.get("location") != "json":
                continue
            name = str(param.get("name", ""))
            values = param.get("sample_values", [])
            data[name] = payload if name == target.param_name else (str(values[0]) if values else "")
        if target.param_name not in data:
            data[target.param_name] = payload
        headers = dict(target.request_headers)
        headers["content-type"] = "application/json"
        return target.method, target.url, json.dumps(data), headers
