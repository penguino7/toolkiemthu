from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha1
from pathlib import Path
from typing import Callable, List
from urllib.parse import urljoin

from .http_client import FuzzHttpClient, RequestBudgetExceeded
from .models import Finding, FuzzTarget
from .mutator import RequestMutator


@dataclass
class BrowserXssResult:
    """Ket qua xac minh XSS bang trinh duyet that."""

    executed: bool
    rendered: bool
    final_url: str
    dialog_messages: List[str] = field(default_factory=list)
    error: str | None = None


class BrowserXssVerifier:
    """Mo Chromium bang Playwright va bat alert/dialog co marker."""

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
            except Exception as error:
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


class XssScanner:
    """Scanner XSS gom reflected, stored va DOM-based trong mot file.

    Moi loai XSS van co ham rieng de de hoc va de debug:
    - scan_reflected_xss()
    - scan_stored_xss()
    - scan_dom_xss()
    """

    def __init__(
        self,
        client: FuzzHttpClient,
        config: dict,
        mutator: RequestMutator | None = None,
        on_finding: Callable[[Finding], None] | None = None,
    ) -> None:
        self.client = client
        self.config = config
        self.mutator = mutator or RequestMutator()
        self.on_finding = on_finding

    def run(self, targets: List[FuzzTarget]) -> List[Finding]:
        options = self.config.get("xss", {})
        findings: List[Finding] = []

        if options.get("reflected", True):
            findings.extend(self._scan_targets(targets, self.scan_reflected_xss))

        if options.get("stored", False):
            findings.extend(self._scan_targets(targets, self.scan_stored_xss))

        if options.get("dom", False):
            for target in targets:
                findings.extend(self.scan_dom_xss(target))

        return findings

    def scan_reflected_xss(self, target: FuzzTarget) -> List[Finding]:
        """Reflect payload vao response, sau do mo browser de xac minh alert."""

        if target.param_location != "query":
            return []

        marker = self._marker("FUZZXSS", target)
        payloads = self._payloads_for_current_mode(marker)
        findings: List[Finding] = []

        with BrowserXssVerifier(self.config) as verifier:
            for payload in payloads:
                method, url, body, headers = self.mutator.mutate(target, payload)
                response = self.client.send(method, url, body=body, headers=headers)

                content_type = response.headers.get("content-type", "")
                is_reflected, reflection_context = self._reflection_evidence(response.text, marker, content_type)
                if not is_reflected:
                    continue

                browser_result = verifier.verify_url(url, marker)
                if not browser_result.executed:
                    continue

                finding = Finding(
                    vuln_type="xss",
                    subtype="reflected",
                    severity="high",
                    target=target,
                    payload=payload,
                    evidence="alert_dialog_executed_after_reflection",
                    request_url=browser_result.final_url,
                    status=response.status,
                    details={
                        "context": reflection_context,
                        "marker": marker,
                        "dialog_messages": browser_result.dialog_messages,
                        "rendered_in_browser": browser_result.rendered,
                        "browser_error": browser_result.error,
                        "elapsed_seconds": round(response.elapsed_seconds, 4),
                    },
                )
                findings.append(self._record_finding(finding))

        return findings

    def scan_stored_xss(self, target: FuzzTarget) -> List[Finding]:
        """Submit payload vao body/json roi mo lai cac trang check."""

        if target.param_location not in {"body", "json"}:
            return []

        marker = self._marker("FUZZSTORED", target)
        payload = self._proof_payloads(marker)[0]
        findings: List[Finding] = []

        method, url, body, headers = self.mutator.mutate(target, payload)
        submit_response = self.client.send(method, url, body=body, headers=headers)

        check_paths = self.config.get("xss", {}).get("stored_check_paths", [])
        with BrowserXssVerifier(self.config) as verifier:
            for path in check_paths:
                check_url = urljoin(self.config.get("base_url", target.url), path)
                browser_result = verifier.verify_url(check_url, marker)
                if not browser_result.executed:
                    continue

                finding = Finding(
                    vuln_type="xss",
                    subtype="stored",
                    severity="high",
                    target=target,
                    payload=payload,
                    evidence="stored_alert_dialog_executed",
                    request_url=browser_result.final_url,
                    status=submit_response.status,
                    details={
                        "marker": marker,
                        "submit_status": submit_response.status,
                        "check_url": check_url,
                        "dialog_messages": browser_result.dialog_messages,
                        "rendered_in_browser": browser_result.rendered,
                        "browser_error": browser_result.error,
                    },
                )
                findings.append(self._record_finding(finding))

        return findings

    def scan_dom_xss(self, target: FuzzTarget) -> List[Finding]:
        """Mo URL co payload bang browser, khong can response reflect payload."""

        if target.param_location != "query":
            return []

        marker = self._marker("FUZZDOM", target)
        findings: List[Finding] = []

        with BrowserXssVerifier(self.config) as verifier:
            for payload in self._proof_payloads(marker):
                _, attack_url, _, _ = self.mutator.mutate(target, payload)
                browser_result = verifier.verify_url(attack_url, marker)
                if not browser_result.executed:
                    continue

                finding = Finding(
                    vuln_type="xss",
                    subtype="dom",
                    severity="high",
                    target=target,
                    payload=payload,
                    evidence="alert_dialog_executed",
                    request_url=browser_result.final_url,
                    status=None,
                    details={
                        "marker": marker,
                        "dialog_messages": browser_result.dialog_messages,
                        "rendered_in_browser": browser_result.rendered,
                        "browser_error": browser_result.error,
                        "scanner": "playwright_dom",
                    },
                )
                findings.append(self._record_finding(finding))

        return findings

    def _scan_targets(self, targets: List[FuzzTarget], scan_function) -> List[Finding]:
        findings: List[Finding] = []
        for target in targets:
            try:
                findings.extend(scan_function(target))
            except RequestBudgetExceeded as error:
                print(f"[!] {error}")
                return findings
        return findings

    def _record_finding(self, finding: Finding) -> Finding:
        if self.on_finding:
            self.on_finding(finding)
        return finding

    def _payloads_for_current_mode(self, marker: str) -> List[str]:
        payload_mode = self.config.get("xss", {}).get("payload_mode", "proof")
        if payload_mode == "marker":
            return self._marker_payloads(marker)
        return self._proof_payloads(marker)

    def _proof_payloads(self, marker: str) -> List[str]:
        payload_file = Path(__file__).with_name("payloads") / "xss.txt"
        payloads = []
        for raw_line in payload_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                payloads.append(line.replace("FUZZXSS_MARKER", marker))
        return payloads

    def _marker_payloads(self, marker: str) -> List[str]:
        return [
            marker,
            f'">{marker}',
            f"'{marker}",
        ]

    def _reflection_evidence(self, response_text: str, marker: str, content_type: str = "") -> tuple[bool, str]:
        if marker not in response_text:
            return False, ""
        return True, self._reflection_context(response_text, marker, content_type)

    def _reflection_context(self, response_text: str, marker: str, content_type: str = "") -> str:
        if "json" in (content_type or "").lower():
            return "json"

        marker_index = response_text.find(marker)
        if marker_index == -1:
            return "unknown"

        before = response_text[max(0, marker_index - 40):marker_index].lower()
        after = response_text[marker_index:marker_index + len(marker) + 40].lower()
        if "<script" in before or "</script" in after:
            return "script"
        if "=" in before and ("\"" in before[-5:] or "'" in before[-5:]):
            return "html_attribute"
        if "<" in before and ">" in after:
            return "html_body"
        return "raw"

    def _marker(self, prefix: str, target: FuzzTarget) -> str:
        seed = f"{prefix}|{target.method}|{target.path}|{target.param_location}|{target.param_name}"
        digest = sha1(seed.encode("utf-8")).hexdigest()[:8]
        return f"{prefix}_{digest}"
