from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict
import requests


@dataclass
class HttpResult:
    """Kết quả HTTP đã được rút gọn cho crawler dùng."""

    url: str
    status: int
    headers: Dict[str, str]
    text: str


class ResponseDecoder:
    """Quyết định response nào nên đọc body dạng text."""

    TEXT_CONTENT_MARKERS = ["text/", "html", "json", "javascript", "xml", "x-www-form-urlencoded"]

    def should_decode(self, content_type: str) -> bool:
        lowered = (content_type or "").lower()
        return any(marker in lowered for marker in self.TEXT_CONTENT_MARKERS)


@dataclass
class HttpSession:
    """HTTP client dùng requests.Session để giữ cookie khi crawl."""

    headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 10
    decoder: ResponseDecoder = field(default_factory=ResponseDecoder)
    session: requests.Session = field(init=False)

    def __post_init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def request(
        self,
        url: str,
        method: str = "GET",
        body: str | bytes | dict | None = None,
        headers: Dict[str, str] | None = None,
    ) -> HttpResult:
        try:
            with self.session.request(
                method=method.upper(),
                url=url,
                data=body,
                headers=headers,
                timeout=self.timeout,
                stream=True,
                allow_redirects=True,
            ) as response:
                headers_dict = {key.lower(): value for key, value in response.headers.items()}
                content_type = headers_dict.get("content-type", "")

                text = ""
                if self.decoder.should_decode(content_type):
                    if "charset=" not in content_type.lower():
                        response.encoding = "utf-8"
                    text = response.text

                return HttpResult(
                    url=response.url,
                    status=response.status_code,
                    headers=headers_dict,
                    text=text,
                )

        except requests.exceptions.RequestException as error:
            raise RuntimeError(f"Request failed for {url}: {error}") from error

    def get(self, url: str) -> HttpResult:
        return self.request(url, "GET")

    def post_form(self, url: str, data: Dict[str, str]) -> HttpResult:
        return self.request(url, "POST", body=data)
