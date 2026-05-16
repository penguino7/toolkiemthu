from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from typing import Dict, List, Tuple
from urllib.parse import urljoin

from ..http_client import fetch_url
from ..normalizer import absolute_url, make_record
from ..scope import in_scope


class LinkFormParser(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__()
        self.page_url = page_url
        self.links: List[str] = []
        self.forms: List[Dict] = []
        self._current_form: Dict | None = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and attrs_dict.get("href"):
            self.links.append(urljoin(self.page_url, attrs_dict["href"]))
        elif tag == "form":
            self._current_form = {
                "method": attrs_dict.get("method", "GET").upper(),
                "action": urljoin(self.page_url, attrs_dict.get("action") or self.page_url),
                "inputs": [],
            }
        elif tag in {"input", "textarea", "select"} and self._current_form is not None:
            name = attrs_dict.get("name")
            if name:
                self._current_form["inputs"].append(
                    {
                        "name": name,
                        "type": attrs_dict.get("type", tag),
                        "value": attrs_dict.get("value", ""),
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _body_from_form(form: Dict) -> str:
    pairs = []
    for item in form.get("inputs", []):
        pairs.append(f"{item.get('name', '')}={item.get('value', '')}")
    return "&".join(pairs)


def crawl_static(config: dict) -> list:
    base_url = config["base_url"]
    options = config.get("static", {})
    max_pages = int(options.get("max_pages", 50))
    max_depth = int(options.get("max_depth", 3))
    timeout = int(options.get("timeout_seconds", 10))
    headers = config.get("headers", {})
    auth_context = config.get("auth_context", "anonymous")
    seeds = [absolute_url(seed, base_url) for seed in config.get("seeds", ["/"])]

    queue = deque((seed, 0, None) for seed in seeds)
    visited = set()
    records = []

    while queue and len(visited) < max_pages:
        url, depth, parent = queue.popleft()
        if url in visited or depth > max_depth or not in_scope(url, config):
            continue
        visited.add(url)

        try:
            result = fetch_url(url, headers=headers, timeout=timeout)
        except RuntimeError:
            continue

        content_type = result.headers.get("content-type", "")
        page_record = make_record(
            "GET",
            result.url,
            "static_html_crawler",
            base_url=base_url,
            auth_context=auth_context,
            status=result.status,
            response_content_type=content_type,
            response_text=result.text,
            discovered_from=parent,
        )
        records.append(page_record)

        if "html" not in content_type.lower():
            continue

        parser = LinkFormParser(result.url)
        parser.feed(result.text)

        for form in parser.forms:
            method = form.get("method", "GET").upper()
            body = _body_from_form(form) if method != "GET" else None
            form_record = make_record(
                method,
                form.get("action", result.url),
                "form_parser",
                base_url=base_url,
                auth_context=auth_context,
                request_content_type="application/x-www-form-urlencoded" if method != "GET" else "",
                body=body,
                discovered_from=result.url,
                forms=[form],
            )
            if method == "GET":
                for item in form.get("inputs", []):
                    from ..models import Param
                    from ..normalizer import infer_type

                    param = Param(item["name"], "query", infer_type(item.get("value", "")))
                    param.add_value(item.get("value", ""))
                    form_record.add_param(param)
            records.append(form_record)

        for link in parser.links:
            normalized = absolute_url(link, base_url)
            if normalized not in visited and in_scope(normalized, config):
                queue.append((normalized, depth + 1, result.url))

    return records
