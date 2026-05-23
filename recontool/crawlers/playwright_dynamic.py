from __future__ import annotations

from collections import deque
from typing import List

from ..models import EndpointRecord
from ..normalizer import ReconNormalizer
from ..scope import ScopePolicy


class DynamicCrawler:
    """Crawler chạy browser thật bằng Playwright.

    Dùng cho SPA hoặc trang có JavaScript gọi API. Crawler nghe response của
    browser rồi chuyển request/response quan trọng thành EndpointRecord.
    """

    SOURCE = "playwright_dynamic_crawler"
    DEFAULT_RESOURCE_TYPES = {"document", "xhr", "fetch"}

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
        self.headers = config.get("headers", {})
        self.options = options
        self.records: List[EndpointRecord] = []

        # Chỉ giữ các loại request có giá trị cho recon endpoint.
        self.resource_types = {
            str(item).lower()
            for item in options.get("resource_types", sorted(self.DEFAULT_RESOURCE_TYPES))
        }
        self.debug = bool(options.get("debug", False))
        self.auto_scroll_enabled = bool(options.get("auto_scroll", False))
        self.scroll_steps = int(options.get("scroll_steps", 0))
        if self.auto_scroll_enabled and self.scroll_steps <= 0:
            self.scroll_steps = 3
        self.scroll_delay_ms = int(options.get("scroll_delay_ms", 300))
        self.current_page_url = ""
        self.stats = {
            "responses_seen": 0,
            "records_kept": 0,
            "skipped_out_of_scope": 0,
            "skipped_resource_type": 0,
            "navigation_errors": 0,
        }

    def crawl(self) -> List[EndpointRecord]:
        sync_playwright = self._load_playwright()
        seeds = [self.normalizer.absolute_url(seed, self.base_url) for seed in self.config.get("seeds", ["/"])]

        with sync_playwright() as playwright:
            # Bước 1: mở browser context với headers cấu hình sẵn.
            browser = playwright.chromium.launch(headless=self.headless)
            context = browser.new_context(**self._context_kwargs())
            page = context.new_page()

            # Bước 2: mỗi response của browser sẽ chạy qua _on_response().
            page.on("response", self._on_response)

            # Bước 3: crawl seed pages.
            self._crawl_pages(page, seeds)

            context.close()
            browser.close()

        self._print_summary()
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
        return {"extra_http_headers": self.headers}

    def _crawl_pages(self, page, seeds: List[str]) -> None:
        crawl_queue = deque(seeds)
        visited_urls = set()

        while crawl_queue and len(visited_urls) < self.max_pages:
            page_url = crawl_queue.popleft()
            if page_url in visited_urls or not self.scope_policy.allows(page_url):
                continue

            visited_urls.add(page_url)
            self.current_page_url = page_url
            try:
                page.goto(page_url, wait_until="networkidle", timeout=self.timeout_ms)
            except Exception:
                self.stats["navigation_errors"] += 1
                continue

            # Các thao tác này giúp SPA/lazy-load gọi thêm API nếu config bật.
            self._auto_scroll(page)
            self._run_safe_actions(page)
            self._auto_scroll(page)
            self._enqueue_page_links(page, crawl_queue, visited_urls)

    def _auto_scroll(self, page) -> None:
        """Scroll để kích hoạt lazy-load API nếu được bật trong config."""
        if self.scroll_steps <= 0:
            return

        for _ in range(self.scroll_steps):
            try:
                page.evaluate("window.scrollBy(0, Math.max(document.body.scrollHeight, window.innerHeight))")
                page.wait_for_timeout(self.scroll_delay_ms)
            except Exception:
                return

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
                locator = page.locator(selector).nth(index)
                if self._should_skip_click(locator):
                    continue
                try:
                    locator.click(timeout=1500)
                    page.wait_for_load_state("networkidle", timeout=5000)
                    clicked += 1
                except Exception:
                    continue

    def _should_skip_click(self, locator) -> bool:
        """Tránh click nhầm các nút nguy hiểm như logout/delete/submit."""
        deny_texts = [
            text.lower()
            for text in self.options.get("deny_click_texts", ["logout", "delete", "remove", "submit", "sign out"])
        ]
        try:
            text = locator.inner_text(timeout=500).strip().lower()
        except Exception:
            text = ""
        return bool(text and any(deny in text for deny in deny_texts))

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
        self.stats["responses_seen"] += 1
        request = response.request

        # Bước 1: bỏ qua ảnh/font/css nếu config chỉ muốn document/xhr/fetch.
        if not self._is_allowed_resource_type(request):
            self.stats["skipped_resource_type"] += 1
            return

        # Bước 2: chỉ giữ request nằm trong scope.
        request_url = self.normalizer.absolute_url(request.url, self.base_url)
        if not self.scope_policy.allows(request_url):
            self.stats["skipped_out_of_scope"] += 1
            return

        # Bước 3: lấy request/response metadata và đưa về EndpointRecord.
        response_headers = dict(response.headers)
        request_headers = dict(request.headers)
        response_content_type = response_headers.get("content-type", "")

        record = self.normalizer.make_record(
            request.method,
            request.url,
            self.SOURCE,
            base_url=self.base_url,
            status=response.status,
            request_content_type=request_headers.get("content-type", ""),
            response_content_type=response_content_type,
            request_headers=request_headers,
            response_headers=response_headers,
            body=request.post_data or None,
            discovered_from=self.current_page_url or None,
        )
        record.evidence["resource_type"] = request.resource_type
        self.records.append(record)
        self.stats["records_kept"] += 1

    def _is_allowed_resource_type(self, request) -> bool:
        if not self.resource_types:
            return True
        return request.resource_type.lower() in self.resource_types

    def _print_summary(self) -> None:
        if not self.debug:
            return
        print(
            "[*] Dynamic summary: "
            f"seen={self.stats['responses_seen']} "
            f"kept={self.stats['records_kept']} "
            f"out_of_scope={self.stats['skipped_out_of_scope']} "
            f"resource_filtered={self.stats['skipped_resource_type']} "
            f"navigation_errors={self.stats['navigation_errors']}"
        )
