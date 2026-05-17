from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import List

from ..models import EndpointRecord
from ..normalizer import ReconNormalizer
from ..scope import ScopePolicy


class DynamicCrawler:
    """Crawler chạy browser thật bằng Playwright.

    Dùng cho SPA hoặc trang có JavaScript gọi API. Crawler nghe response của
    browser rồi chuyển từng request/response thành EndpointRecord.
    """

    SOURCE = "playwright_dynamic_crawler"
    TEXT_CONTENT_MARKERS = ["text/", "html", "json", "javascript", "xml"]

    def __init__(
        self,
        config: dict,
        normalizer: ReconNormalizer | None = None,
        scope_policy: ScopePolicy | None = None,
    ) -> None:
        self.config = config
        self.normalizer = normalizer or ReconNormalizer()
        self.scope_policy = scope_policy or ScopePolicy(config)

        options = config.get("dynamic", {})
        self.base_url = config["base_url"]
        self.max_pages = int(options.get("max_pages", 20))
        self.timeout_ms = int(options.get("timeout_ms", 15000))
        self.headless = bool(options.get("headless", True))
        self.auth_context = config.get("auth_context", "anonymous")
        self.headers = config.get("headers", {})
        self.auth_profile = config.get("_auth_profile", {"name": self.auth_context, "type": "none"})
        self.options = options
        self.records: List[EndpointRecord] = []

    def crawl(self) -> List[EndpointRecord]:
        sync_playwright = self._load_playwright()
        seeds = [self.normalizer.absolute_url(seed, self.base_url) for seed in self.config.get("seeds", ["/"])]

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=self.headless)
            context = browser.new_context(**self._context_kwargs())
            page = context.new_page()
            page.on("response", self._on_response)

            self._login_with_form(page)
            self._crawl_pages(page, seeds)

            context.close()
            browser.close()

        return self.records

    def _load_playwright(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as error:
            raise RuntimeError(
                "Playwright chưa được cài. Chạy: pip install playwright && python -m playwright install chromium"
            ) from error
        return sync_playwright

    def _context_kwargs(self) -> dict:
        kwargs = {"extra_http_headers": self.headers}
        storage_state = self.options.get("storage_state")
        if storage_state and Path(storage_state).exists():
            kwargs["storage_state"] = storage_state
        return kwargs

    def _login_with_form(self, page) -> None:
        if self.auth_profile.get("type") != "form":
            return

        login_url = self.normalizer.absolute_url(self.auth_profile["login_url"], self.base_url)
        page.goto(login_url, wait_until="networkidle", timeout=self.timeout_ms)

        for name, value in self.auth_profile.get("data", {}).items():
            try:
                page.fill(f'[name="{name}"]', str(value), timeout=3000)
            except Exception:
                pass

        submit = self.auth_profile.get("submit_selector") or 'button[type="submit"], input[type="submit"], button'
        try:
            page.click(submit, timeout=5000)
            page.wait_for_load_state("networkidle", timeout=self.timeout_ms)
        except Exception:
            pass

        success = self.auth_profile.get("success_check") or {}
        if success.get("url"):
            page.goto(self.normalizer.absolute_url(success["url"], self.base_url), wait_until="networkidle")

    def _crawl_pages(self, page, seeds: List[str]) -> None:
        queue = deque(seeds)
        visited = set()

        while queue and len(visited) < self.max_pages:
            url = queue.popleft()
            if url in visited or not self.scope_policy.allows(url):
                continue

            visited.add(url)
            try:
                page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
            except Exception:
                continue

            self._run_safe_actions(page)
            self._enqueue_page_links(page, queue, visited)

    def _run_safe_actions(self, page) -> None:
        selectors = self.options.get("click_selectors", [])
        limit = int(self.options.get("max_clicks_per_page", 0))
        if not selectors or limit <= 0:
            return

        clicked = 0
        for selector in selectors:
            try:
                count = page.locator(selector).count()
            except Exception:
                continue
            for index in range(min(count, limit - clicked)):
                if clicked >= limit:
                    return
                try:
                    page.locator(selector).nth(index).click(timeout=1500)
                    page.wait_for_load_state("networkidle", timeout=5000)
                    clicked += 1
                except Exception:
                    continue

    def _enqueue_page_links(self, page, queue, visited: set[str]) -> None:
        try:
            links = page.eval_on_selector_all("a[href]", "els => els.map(a => a.href)")
        except Exception:
            links = []

        for link in links:
            normalized = self.normalizer.absolute_url(link, self.base_url)
            if normalized not in visited and self.scope_policy.allows(normalized):
                queue.append(normalized)

    def _on_response(self, response) -> None:
        request = response.request
        response_content_type = response.headers.get("content-type", "")
        response_text = self._response_text(response, response_content_type)
        record = self.normalizer.make_record(
            request.method,
            request.url,
            self.SOURCE,
            base_url=self.base_url,
            auth_context=self.auth_context,
            status=response.status,
            request_content_type=request.headers.get("content-type", ""),
            response_content_type=response_content_type,
            body=request.post_data or None,
            response_text=response_text,
        )
        self.records.append(record)

    def _response_text(self, response, content_type: str) -> str:
        if not any(token in content_type.lower() for token in self.TEXT_CONTENT_MARKERS):
            return ""
        try:
            return response.text()
        except Exception:
            return ""


def crawl_dynamic(config: dict) -> list:
    return DynamicCrawler(config).crawl()
