from __future__ import annotations

from dataclasses import dataclass
from typing import Dict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass
class HttpResult:
    url: str
    status: int
    headers: Dict[str, str]
    text: str


def _decode_body(body: bytes, content_type: str) -> str:
    charset = "utf-8"
    if "charset=" in content_type:
        charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
    return body.decode(charset, errors="replace")


def fetch_url(url: str, headers: Dict[str, str] | None = None, timeout: int = 10) -> HttpResult:
    request = Request(url, headers=headers or {})
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
            headers_dict = {k.lower(): v for k, v in response.headers.items()}
            content_type = headers_dict.get("content-type", "")
            text = _decode_body(raw, content_type) if _should_decode(content_type) else ""
            return HttpResult(response.geturl(), response.status, headers_dict, text)
    except HTTPError as error:
        raw = error.read()
        headers_dict = {k.lower(): v for k, v in error.headers.items()}
        content_type = headers_dict.get("content-type", "")
        text = _decode_body(raw, content_type) if _should_decode(content_type) else ""
        return HttpResult(error.geturl(), error.code, headers_dict, text)
    except URLError as error:
        raise RuntimeError(f"Fetch failed for {url}: {error}") from error


def _should_decode(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return any(token in lowered for token in ["text/", "html", "json", "javascript", "xml", "x-www-form-urlencoded"])
