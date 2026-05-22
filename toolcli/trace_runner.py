from __future__ import annotations

import sys
from typing import Any
from urllib.parse import urlparse


PENDING_PAYLOAD: dict[str, str] = {}


def patch_fuzz_logging() -> None:
    """In payload/request/response khi fuzztool dang chay."""

    from fuzztool.http_client import FuzzHttpClient
    from fuzztool.mutator import RequestMutator

    original_mutate = RequestMutator.mutate
    original_send = FuzzHttpClient.send

    def traced_mutate(self, target, payload):
        method, url, body, headers = original_mutate(self, target, payload)
        PENDING_PAYLOAD["target"] = target.key
        PENDING_PAYLOAD["payload"] = payload
        return method, url, body, headers

    def traced_send(self, method, url, body=None, headers=None):
        payload_info = dict(PENDING_PAYLOAD)
        PENDING_PAYLOAD.clear()

        try:
            response = original_send(self, method, url, body=body, headers=headers)
        except Exception as error:
            print_error("fuzz request", error)
            raise

        print_http_block("FUZZ", method, url, body, response, payload_info)
        return response

    RequestMutator.mutate = traced_mutate
    FuzzHttpClient.send = traced_send


def patch_recon_logging() -> None:
    """In request/response khi recontool dang chay."""

    from recontool.http_client import HttpSession

    original_request = HttpSession.request

    def traced_request(self, url, method="GET", body=None, headers=None):
        try:
            result = original_request(self, url, method=method, body=body, headers=headers)
        except Exception as error:
            print_error("recon request", error)
            raise

        print_recon_block(method, url, body, result)
        return result

    HttpSession.request = traced_request

    from recontool.crawlers.playwright_dynamic import DynamicCrawler

    original_on_response = DynamicCrawler._on_response

    def traced_on_response(self, response):
        request = response.request
        count_before = len(self.records)
        original_on_response(self, response)
        kept = len(self.records) > count_before

        print("")
        print(line("="))
        print(f"BROWSER  {request.method} {short_url(request.url)}")
        print(f"TYPE     {request.resource_type}")
        print(f"RESPONSE status={response.status} kept={kept}")
        print(line("="), flush=True)

    DynamicCrawler._on_response = traced_on_response


def print_http_block(title: str, method: Any, url: Any, body: Any, response: Any, payload: dict[str, str]) -> None:
    print("")
    print(line("="))
    print(f"{title} REQUEST/RESPONSE")
    print(line("-"))

    if payload:
        print(f"PAYLOAD  {payload.get('target', '-')}")
        print(f"VALUE    {short_text(payload.get('payload', ''), 360)}")
        print(line("-"))

    print(f"REQUEST  {str(method).upper()} {short_url(url)}")
    if body:
        print(f"BODY     {short_text(body, 220)}")

    print_response(response)
    print(line("="), flush=True)


def print_recon_block(method: Any, url: Any, body: Any, result: Any) -> None:
    print("")
    print(line("="))
    print("RECON REQUEST/RESPONSE")
    print(line("-"))
    print(f"REQUEST  {str(method).upper()} {short_url(url)}")
    if body:
        print(f"BODY     {short_text(body, 160)}")
    print(
        "RESPONSE status={status} size={size} type={content_type}".format(
            status=getattr(result, "status", "-"),
            size=format_size(len(getattr(result, "text", "") or "")),
            content_type=short_text(getattr(result, "headers", {}).get("content-type", ""), 60),
        )
    )
    print(line("="), flush=True)


def print_response(response: Any) -> None:
    status = getattr(response, "status", "-")
    elapsed = getattr(response, "elapsed_seconds", None)
    elapsed_text = f"{elapsed:.3f}s" if isinstance(elapsed, (int, float)) else "-"
    size_text = format_size(len(getattr(response, "text", "") or ""))
    print(f"RESPONSE status={status} time={elapsed_text} size={size_text}")

    error = getattr(response, "error", None)
    if error:
        print(f"ERROR    {short_text(error, 140)}")


def print_error(where: str, error: Exception) -> None:
    print("")
    print(line("="))
    print(f"ERROR    {where}: {short_text(error, 160)}")
    print(line("="), flush=True)


def short_url(value: Any, limit: int = 150) -> str:
    text = str(value)
    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        if parsed.query:
            base = f"{base}?{parsed.query}"
        return short_text(base, limit)
    return short_text(text, limit)


def short_text(value: Any, limit: int = 240) -> str:
    text = str(value).replace("\n", "\\n").replace("\r", "")
    return text if len(text) <= limit else text[:limit] + "..."


def format_size(value: int) -> str:
    if value < 1024:
        return f"{value}B"
    return f"{value / 1024:.1f}KB"


def line(char: str) -> str:
    return char * 72


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if not args or args[0] not in {"recon", "fuzz"}:
        print("Usage: python -m toolcli.trace_runner recon|fuzz [args...]")
        return 2

    tool_name = args.pop(0)
    if tool_name == "recon":
        patch_recon_logging()
        from recontool.cli import main as recon_main

        return recon_main(args)

    patch_fuzz_logging()
    from fuzztool.cli import main as fuzz_main

    return fuzz_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
