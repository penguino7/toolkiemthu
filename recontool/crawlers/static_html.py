from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from typing import Dict, List, Tuple
from urllib.parse import urlencode, urljoin

from ..http_client import HttpSession
from ..models import EndpointRecord, Param
from ..normalizer import ReconNormalizer
from ..scope import ScopePolicy


class HtmlDiscoveryParser(HTMLParser):
    """Parser nhỏ để lấy link và form từ HTML.

    `HTMLParser` là thư viện chuẩn của Python, đủ dùng cho recon cơ bản mà
    không cần thêm dependency.
    """

    def __init__(self, page_url: str):
        super().__init__()
        self.page_url = page_url
        self.links: List[str] = []
        self.forms: List[Dict] = []
        self._current_form: Dict | None = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): (value or "") for key, value in attrs}
        if tag == "a" and attrs_dict.get("href"):
            self.links.append(urljoin(self.page_url, attrs_dict["href"]))
        elif tag == "form":
            self._start_form(attrs_dict)
        elif tag in {"input", "textarea", "select"} and self._current_form is not None:
            self._add_form_input(tag, attrs_dict)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def _start_form(self, attrs: Dict[str, str]) -> None:
        self._current_form = {
            "method": attrs.get("method", "GET").upper(),
            "action": urljoin(self.page_url, attrs.get("action") or self.page_url),
            "inputs": [],
        }

    def _add_form_input(self, tag: str, attrs: Dict[str, str]) -> None:
        name = attrs.get("name")
        if not name:
            return
        self._current_form["inputs"].append(
            {
                "name": name,
                "type": attrs.get("type", tag),
                "value": attrs.get("value", ""),
            }
        )


class StaticHtmlCrawler:
    """Crawler HTML tĩnh.

    Crawler này chỉ request URL đã tìm thấy để đọc HTML/link/form. Nó không chạy
    JavaScript và không tự sinh giá trị kiểm thử.
    """

    SOURCE_PAGE = "static_html_crawler"
    SOURCE_FORM = "form_parser"

    def __init__(
        self,
        config: dict,
        normalizer: ReconNormalizer | None = None,
        scope_policy: ScopePolicy | None = None,
        session: HttpSession | None = None,
    ) -> None:
        self.config = config
        self.normalizer = normalizer or ReconNormalizer()
        self.scope_policy = scope_policy or ScopePolicy(config)

        options = config.get("static", {})
        timeout = int(options.get("timeout_seconds", 10))
        self.session = session or config.get("_http_session") or HttpSession(headers=config.get("headers", {}), timeout=timeout)

        self.base_url = config["base_url"]
        self.auth_context = config.get("auth_context", "anonymous")
        self.max_pages = int(options.get("max_pages", 50))
        self.max_depth = int(options.get("max_depth", 3))

    def crawl(self) -> List[EndpointRecord]:
        seeds = [self.normalizer.absolute_url(seed, self.base_url) for seed in self.config.get("seeds", ["/"])]
        queue = deque((seed, 0, None) for seed in seeds)
        visited = set()
        records: List[EndpointRecord] = []

        while queue and len(visited) < self.max_pages:
            url, depth, parent = queue.popleft()
            if self._should_skip(url, depth, visited):
                continue

            visited.add(url)
            page_records, links = self._crawl_one_page(url, parent)
            records.extend(page_records)
            self._enqueue_links(queue, links, visited, depth, parent_url=url)

        return records

    def _should_skip(self, url: str, depth: int, visited: set[str]) -> bool:
        return url in visited or depth > self.max_depth or not self.scope_policy.allows(url)

    def _crawl_one_page(self, url: str, parent: str | None) -> tuple[List[EndpointRecord], List[str]]:
        try:
            result = self.session.get(url)
        except RuntimeError:
            return [], []

        content_type = result.headers.get("content-type", "")
        records = [self._make_page_record(result.url, result.status, content_type, result.text, parent)]

        if "html" not in content_type.lower():
            return records, []

        parser = HtmlDiscoveryParser(result.url)
        parser.feed(result.text)
        records.extend(self._make_form_records(parser.forms, result.url))
        return records, parser.links

    def _make_page_record(
        self,
        url: str,
        status: int,
        content_type: str,
        response_text: str,
        parent: str | None,
    ) -> EndpointRecord:
        return self.normalizer.make_record(
            "GET",
            url,
            self.SOURCE_PAGE,
            base_url=self.base_url,
            auth_context=self.auth_context,
            status=status,
            response_content_type=content_type,
            response_text=response_text,
            discovered_from=parent,
        )

    def _make_form_records(self, forms: List[Dict], page_url: str) -> List[EndpointRecord]:
        records = []
        for form in forms:
            method = form.get("method", "GET").upper()
            body = self._body_from_form(form) if method != "GET" else None
            record = self.normalizer.make_record(
                method,
                form.get("action", page_url),
                self.SOURCE_FORM,
                base_url=self.base_url,
                auth_context=self.auth_context,
                request_content_type="application/x-www-form-urlencoded" if method != "GET" else "",
                body=body,
                discovered_from=page_url,
                forms=[form],
            )
            if method == "GET":
                self._add_get_form_params(record, form)
            records.append(record)
        return records

    def _add_get_form_params(self, record: EndpointRecord, form: Dict) -> None:
        for item in form.get("inputs", []):
            param = Param(item["name"], "query", self.normalizer.infer_type(item.get("value", "")))
            param.add_value(item.get("value", ""))
            record.add_param(param)

    def _enqueue_links(self, queue, links: List[str], visited: set[str], depth: int, parent_url: str) -> None:
        for link in links:
            normalized = self.normalizer.absolute_url(link, self.base_url)
            if normalized not in visited and self.scope_policy.allows(normalized):
                queue.append((normalized, depth + 1, parent_url))

    def _body_from_form(self, form: Dict) -> str:
        pairs = []
        for item in form.get("inputs", []):
            name = item.get("name", "")
            if name:
                pairs.append((name, item.get("value", "")))
        return urlencode(pairs)


def crawl_static(config: dict) -> list:
    return StaticHtmlCrawler(config).crawl()
