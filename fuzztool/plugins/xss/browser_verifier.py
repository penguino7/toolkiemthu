from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class BrowserXssResult:
    """Ket qua xac minh XSS bang trinh duyet that."""

    executed: bool
    rendered: bool
    final_url: str
    dialog_messages: List[str] = field(default_factory=list)
    error: str | None = None


class BrowserXssVerifier:
    """Mo Chromium bang Playwright va bat dialog de xac nhan XSS thuc thi.

    HTTP response co chua payload chua du de ket luan XSS. Class nay chi tra
    ve executed=True khi browser that su chay payload va tao dialog co marker.
    """

    def __init__(self, config: dict) -> None:
        xss_config = config.get("xss", {})
        self.timeout_ms = int(xss_config.get("dom_timeout_ms", 8000))
        self.headless = bool(xss_config.get("dom_headless", True))
        self.post_load_wait_ms = int(xss_config.get("post_load_wait_ms", 500))
        self._playwright = None
        self._browser = None

    def __enter__(self) -> "BrowserXssVerifier":
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def start(self) -> None:
        if self._browser is not None:
            return
        sync_playwright = self._load_playwright()
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=self.headless)

    def close(self) -> None:
        if self._browser is not None:
            self._browser.close()
            self._browser = None
        if self._playwright is not None:
            self._playwright.stop()
            self._playwright = None

    def verify_url(self, url: str, marker: str) -> BrowserXssResult:
        self.start()
        page = self._browser.new_page()
        dialogs: List[str] = []
        html = ""
        final_url = url
        error_message = None

        def on_dialog(dialog) -> None:
            dialogs.append(dialog.message)
            dialog.dismiss()

        page.on("dialog", on_dialog)
        try:
            try:
                page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
                if self.post_load_wait_ms > 0:
                    page.wait_for_timeout(self.post_load_wait_ms)
                html = page.content()
                final_url = page.url
            except Exception as error:  # Playwright errors should not stop the whole fuzz run.
                error_message = str(error)
                final_url = page.url
        finally:
            page.close()

        return BrowserXssResult(
            executed=any(marker in message for message in dialogs),
            rendered=marker in html,
            final_url=final_url,
            dialog_messages=dialogs,
            error=error_message,
        )

    def _load_playwright(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as error:
            raise RuntimeError(
                "Can Playwright de xac nhan XSS thuc thi. Cai bang: "
                "pip install playwright && python -m playwright install chromium"
            ) from error
        return sync_playwright
