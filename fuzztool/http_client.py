from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from http.client import RemoteDisconnected
from socket import timeout as SocketTimeout
from typing import Dict
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlparse, urlunparse
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener

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
    use_environment_proxy: bool = False
    request_count: int = 0
    error_count: int = 0
    timeout_count: int = 0

    def __post_init__(self) -> None:
        handlers = [HTTPCookieProcessor(self.cookie_jar)]
        if not self.use_environment_proxy:
            handlers.insert(0, ProxyHandler({}))
        self.opener = build_opener(*handlers)

    def send(
        self,
        method: str,
        url: str,
        body: str | bytes | None = None,
        headers: Dict[str, str] | None = None,
    ) -> HttpExchange:
        # Bước 1: kiểm soát an toàn, tránh fuzz quá số request cho phép.
        if self.max_requests is not None and self.request_count >= self.max_requests:
            raise RequestBudgetExceeded(f"Reached max_requests={self.max_requests}")
        if self.delay_seconds > 0:
            time.sleep(self.delay_seconds)
        self.request_count += 1

        # Bước 2: chuẩn bị headers/body cho urllib.
        final_headers = dict(self.headers)
        if headers:
            final_headers.update(headers)

        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            final_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        # Bước 3: gửi request. HTTP 4xx/5xx vẫn là response hợp lệ để detector đọc.
        started = time.perf_counter()
        url = self._safe_url(url)
        request = Request(url, data=data, headers=final_headers, method=method.upper())
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return self._exchange(
                    method,
                    response.geturl(),
                    response.status,
                    response.headers.items(),
                    response.read(),
                    started,
                )
        except HTTPError as error:
            return self._exchange(method, error.geturl(), error.code, error.headers.items(), error.read(), started)
        except (TimeoutError, SocketTimeout) as error:
            return self._error_exchange(method, url, started, f"timeout: {error}")
        except URLError as error:
            return self._connection_error_exchange(method, url, started, error)
        except (RemoteDisconnected, socket.error, ConnectionResetError) as error:
            return self._connection_error_exchange(method, url, started, error)

    @staticmethod
    def _safe_url(url: str) -> str:
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return url

        safe_query = "&".join(
            f"{quote(name, safe='')}={quote(value, safe='')}"
            for name, value in parse_qsl(parsed_url.query, keep_blank_values=True)
        )
        return urlunparse(parsed_url._replace(query=safe_query))

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

    def _connection_error_exchange(self, method: str, url: str, started: float, error: Exception) -> HttpExchange:
        reason = getattr(error, "reason", error)
        if isinstance(reason, (TimeoutError, SocketTimeout, socket.timeout)):
            return self._error_exchange(method, url, started, f"timeout: {reason}")
        return self._error_exchange(method, url, started, f"url_error: {reason}")

    def _decode(self, raw: bytes, content_type: str) -> str:
        lowered = (content_type or "").lower()
        if lowered and not any(token in lowered for token in ["text/", "html", "json", "javascript", "xml"]):
            return ""
        charset = "utf-8"
        if "charset=" in lowered:
            charset = lowered.split("charset=", 1)[1].split(";", 1)[0].strip()
        return raw.decode(charset, errors="replace")
