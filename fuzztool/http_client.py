from __future__ import annotations

import time
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from socket import timeout as SocketTimeout
from typing import Dict
from urllib.error import HTTPError, URLError
from urllib.request import HTTPCookieProcessor, Request, build_opener

from .models import HttpExchange


class RequestBudgetExceeded(RuntimeError):
    """Dừng fuzz khi đã gửi đủ số request cho phép."""


@dataclass
class FuzzHttpClient:
    """HTTP client dùng chung cho các plugin fuzz."""

    headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 15
    cookie_jar: CookieJar = field(default_factory=CookieJar)
    max_requests: int | None = None
    delay_seconds: float = 0.0
    request_count: int = 0
    error_count: int = 0
    timeout_count: int = 0

    def __post_init__(self) -> None:
        self.opener = build_opener(HTTPCookieProcessor(self.cookie_jar))

    def send(
        self,
        method: str,
        url: str,
        body: str | bytes | None = None,
        headers: Dict[str, str] | None = None,
    ) -> HttpExchange:
        if self.max_requests is not None and self.request_count >= self.max_requests:
            raise RequestBudgetExceeded(f"Reached max_requests={self.max_requests}")
        if self.delay_seconds > 0:
            time.sleep(self.delay_seconds)
        self.request_count += 1

        final_headers = dict(self.headers)
        if headers:
            final_headers.update(headers)

        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            final_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        started = time.perf_counter()
        request = Request(url, data=data, headers=final_headers, method=method.upper())
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return self._exchange(method, response.geturl(), response.status, response.headers.items(), response.read(), started)
        except HTTPError as error:
            return self._exchange(method, error.geturl(), error.code, error.headers.items(), error.read(), started)
        except (TimeoutError, SocketTimeout) as error:
            return self._error_exchange(method, url, started, f"timeout: {error}")
        except URLError as error:
            return self._error_exchange(method, url, started, f"url_error: {error.reason}")

    def _exchange(self, method: str, url: str, status: int, headers, raw: bytes, started: float) -> HttpExchange:
        header_dict = {key.lower(): value for key, value in headers}
        content_type = header_dict.get("content-type", "")
        text = self._decode(raw, content_type)
        return HttpExchange(
            method=method.upper(),
            url=url,
            status=status,
            headers=header_dict,
            text=text,
            elapsed_seconds=time.perf_counter() - started,
        )

    def _error_exchange(self, method: str, url: str, started: float, error: str) -> HttpExchange:
        self.error_count += 1
        if error.startswith("timeout:"):
            self.timeout_count += 1
        return HttpExchange(
            method=method.upper(),
            url=url,
            status=0,
            headers={},
            text="",
            elapsed_seconds=time.perf_counter() - started,
            error=error,
        )

    def _decode(self, raw: bytes, content_type: str) -> str:
        lowered = (content_type or "").lower()
        if lowered and not any(token in lowered for token in ["text/", "html", "json", "javascript", "xml"]):
            return ""
        charset = "utf-8"
        if "charset=" in lowered:
            charset = lowered.split("charset=", 1)[1].split(";", 1)[0].strip()
        return raw.decode(charset, errors="replace")
