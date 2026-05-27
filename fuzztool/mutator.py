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
        parsed_url = urlparse(target.url)
        query_pairs = parse_qsl(parsed_url.query, keep_blank_values=True)
        updated_pairs = []
        target_param_was_found = False

        for name, value in query_pairs:
            if name == target.param_name:
                updated_pairs.append((name, payload))
                target_param_was_found = True
            else:
                updated_pairs.append((name, value))

        if not target_param_was_found:
            updated_pairs.append((target.param_name, payload))

        attack_url = urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                urlencode(updated_pairs),
                parsed_url.fragment,
            )
        )
        return target.method, attack_url, None, dict(target.request_headers)

    def _mutate_body(self, target: FuzzTarget, payload: str) -> tuple[str, str, str, dict]:
        body_pairs = []

        for param in target.record.get("params", []):
            if self._param_location(param) != "body":
                continue

            name = str(param.get("name", ""))
            sample_value = self._param_sample(param)
            value = payload if name == target.param_name else sample_value
            body_pairs.append((name, value))

        if not any(name == target.param_name for name, _ in body_pairs):
            body_pairs.append((target.param_name, payload))

        headers = dict(target.request_headers)
        headers["content-type"] = "application/x-www-form-urlencoded"
        return target.method, target.url, urlencode(body_pairs), headers

    def _mutate_json(self, target: FuzzTarget, payload: str) -> tuple[str, str, str, dict]:
        json_data = {}

        for param in target.record.get("params", []):
            if self._param_location(param) != "json":
                continue

            name = str(param.get("name", ""))
            sample_value = self._param_sample(param)
            json_data[name] = payload if name == target.param_name else sample_value

        if target.param_name not in json_data:
            json_data[target.param_name] = payload

        headers = dict(target.request_headers)
        headers["content-type"] = "application/json"
        return target.method, target.url, json.dumps(json_data), headers

    def _param_location(self, param: dict) -> str:
        return str(param.get("in") or param.get("location") or "")

    def _param_sample(self, param: dict) -> str:
        if "sample" in param:
            return str(param.get("sample", ""))
        sample_values = param.get("sample_values", [])
        return str(sample_values[0]) if sample_values else ""
