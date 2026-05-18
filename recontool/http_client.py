from __future__ import annotations

from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from typing import Dict
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener


@dataclass
class HttpResult:
    """Kết quả HTTP đã được rút gọn cho crawler dùng."""

    url: str
    status: int
    headers: Dict[str, str]
    text: str


class ResponseDecoder:
    """Giải mã response body thành text nếu content-type phù hợp."""

    TEXT_CONTENT_MARKERS = ["text/", "html", "json", "javascript", "xml", "x-www-form-urlencoded"]

    def should_decode(self, content_type: str) -> bool:
        lowered = (content_type or "").lower()
        return any(marker in lowered for marker in self.TEXT_CONTENT_MARKERS)

    def decode(self, body: bytes, content_type: str) -> str:
        charset = "utf-8"
        if "charset=" in content_type:
            charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
        return body.decode(charset, errors="replace")


@dataclass
class HttpSession:
    """HTTP client có cookie jar.

    Static crawler và form login dùng class này để giữ session giống browser cơ
    bản. Tool vẫn chỉ recon: nó request các URL đã biết để đọc HTML/metadata.
    """

    headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 10
    cookie_jar: CookieJar = field(default_factory=CookieJar)
    decoder: ResponseDecoder = field(default_factory=ResponseDecoder)

    def __post_init__(self) -> None:
        self.opener = build_opener(HTTPCookieProcessor(self.cookie_jar))

    def request(
        self,
        url: str,
        method: str = "GET",
        body: str | bytes | None = None,
        headers: Dict[str, str] | None = None,
    ) -> HttpResult:
        final_headers = dict(self.headers)
        if headers:
            final_headers.update(headers)

        # urllib cần bytes cho request body.
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            final_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        request = Request(url, data=data, headers=final_headers, method=method.upper())
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return self._build_result(response.geturl(), response.status, response.headers.items(), response.read())
        except HTTPError as error:
            # HTTP 404/500 vẫn là response hợp lệ cho recon, nên trả về HttpResult.
            return self._build_result(error.geturl(), error.code, error.headers.items(), error.read())
        except URLError as error:
            raise RuntimeError(f"Request failed for {url}: {error}") from error

    def get(self, url: str) -> HttpResult:
        return self.request(url, "GET")

    def post_form(self, url: str, data: Dict[str, str]) -> HttpResult:
        body = urlencode(data)
        return self.request(url, "POST", body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})

    def _build_result(self, url: str, status: int, headers, raw_body: bytes) -> HttpResult:
        headers_dict = {key.lower(): value for key, value in headers}
        content_type = headers_dict.get("content-type", "")
        text = self.decoder.decode(raw_body, content_type) if self.decoder.should_decode(content_type) else ""
        return HttpResult(url, status, headers_dict, text)
