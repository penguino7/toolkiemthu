from __future__ import annotations

from hashlib import sha1
from typing import List

from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator


class DomXssScanner:
    """DOM XSS scanner tùy chọn bằng Playwright."""

    def __init__(self, config: dict, mutator: RequestMutator | None = None) -> None:
        self.config = config
        self.mutator = mutator or RequestMutator()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        if target.param_location != "query":
            return []

        try:
            from playwright.sync_api import sync_playwright
        except ImportError as error:
            raise RuntimeError("Playwright chưa được cài, không thể chạy DOM XSS scanner") from error

        marker = self._marker(target)
        _, url, _, _ = self.mutator.mutate(target, marker)
        timeout_ms = int(self.config.get("xss", {}).get("dom_timeout_ms", 8000))
        headless = bool(self.config.get("xss", {}).get("dom_headless", True))

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=headless)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            html = page.content()
            browser.close()

        if marker not in html:
            return []

        return [
            Finding(
                vuln_type="xss",
                subtype="dom",
                severity="medium",
                target=target,
                payload=marker,
                evidence="marker_rendered_in_dom",
                request_url=url,
                status=None,
                details={"scanner": "playwright_dom"},
            )
        ]

    def _marker(self, target: FuzzTarget) -> str:
        seed = f"dom|{target.method}|{target.path}|{target.param_location}|{target.param_name}"
        digest = sha1(seed.encode("utf-8")).hexdigest()[:8]
        return f"FUZZDOM_{digest}"
