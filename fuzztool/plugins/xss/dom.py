from __future__ import annotations

from hashlib import sha1
from typing import List

from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .payload_factory import XssPayloadFactory


class DomXssScanner:
    """DOM XSS scanner tùy chọn bằng Playwright.

    Scanner này dùng payload thật và bắt `alert()` qua sự kiện dialog.
    """

    def __init__(self, config: dict, mutator: RequestMutator | None = None) -> None:
        self.config = config
        self.mutator = mutator or RequestMutator()
        self.payload_factory = XssPayloadFactory()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        if target.param_location != "query":
            return []

        try:
            from playwright.sync_api import sync_playwright
        except ImportError as error:
            raise RuntimeError("Playwright chưa được cài, không thể chạy DOM XSS scanner") from error

        marker = self._marker(target)
        timeout_ms = int(self.config.get("xss", {}).get("dom_timeout_ms", 8000))
        headless = bool(self.config.get("xss", {}).get("dom_headless", True))
        payloads = self.payload_factory.proof_payloads(marker)
        findings: List[Finding] = []

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=headless)
            page = browser.new_page()
            dialogs: List[str] = []

            def on_dialog(dialog) -> None:
                dialogs.append(dialog.message)
                dialog.dismiss()

            page.on("dialog", on_dialog)

            for payload in payloads:
                _, url, _, _ = self.mutator.mutate(target, payload)
                dialogs.clear()
                page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                html = page.content()
                executed = any(marker in message for message in dialogs)
                rendered = marker in html
                if executed or rendered:
                    findings.append(
                        Finding(
                            vuln_type="xss",
                            subtype="dom",
                            severity="high" if executed else "medium",
                            target=target,
                            payload=payload,
                            evidence="alert_dialog_executed" if executed else "marker_rendered_in_dom",
                            request_url=url,
                            status=None,
                            details={
                                "marker": marker,
                                "dialog_messages": list(dialogs),
                                "scanner": "playwright_dom",
                            },
                        )
                    )

            browser.close()

        return findings

    def _marker(self, target: FuzzTarget) -> str:
        seed = f"dom|{target.method}|{target.path}|{target.param_location}|{target.param_name}"
        digest = sha1(seed.encode("utf-8")).hexdigest()[:8]
        return f"FUZZDOM_{digest}"
