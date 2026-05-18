from __future__ import annotations

import sys
from typing import Any, List
from urllib.parse import parse_qsl, urlparse


PENDING_FUZZ_PAYLOAD: dict[str, str] = {}


def log_event(event: str, **fields: Any) -> None:
    """In log theo format ngắn, dễ nhìn trong terminal."""

    if event == "PAYLOAD":
        print("", flush=True)
        print(f"[PAYLOAD ] {compact_target(fields.get('target', ''))}", flush=True)
        print(f"           value: {short_text(fields.get('payload', ''), 90)}", flush=True)
        return

    if event in {"REQUEST", "BROWSER_REQUEST"}:
        label = "BROWSER " if event == "BROWSER_REQUEST" else "REQUEST "
        method = str(fields.get("method", "")).upper()
        url = summarize_url(fields.get("url", ""))
        print(f"[{label}] {method} {url}", flush=True)
        if fields.get("body"):
            print(f"           body: {short_text(fields.get('body'), 90)}", flush=True)
        if fields.get("resource_type"):
            print(f"           type: {fields.get('resource_type')}", flush=True)
        return

    if event in {"RESPONSE", "BROWSER_RESPONSE"}:
        label = "BROWSER " if event == "BROWSER_RESPONSE" else "RESPONSE"
        status = fields.get("status", "-")
        elapsed = fields.get("elapsed")
        length = format_size(fields.get("length"))
        kept = fields.get("kept")
        parts = [f"[{label}]", f"status={status}"]
        if elapsed:
            parts.append(f"time={elapsed}")
        if length:
            parts.append(f"size={length}")
        if kept not in (None, ""):
            parts.append(f"kept={kept}")
        print(" ".join(parts), flush=True)
        if fields.get("error"):
            print(f"           error: {short_text(fields.get('error'), 120)}", flush=True)
        return

    if event == "ERROR":
        print(f"[ERROR   ] {fields.get('where', '-')}: {short_text(fields.get('error', ''), 140)}", flush=True)
        return

    parts = [f"[{event}]"]
    for key, value in fields.items():
        if value in (None, ""):
            continue
        parts.append(f"{key}={short_text(value)}")
    print(" ".join(parts), flush=True)


def print_transaction(
    method: Any,
    url: Any,
    body: Any,
    response: Any,
    payload_info: dict[str, str] | None = None,
) -> None:
    """In một cặp request/response thành một block riêng."""

    print("")
    print("┌" + "─" * 70, flush=True)
    if payload_info:
        print(f"│ PAYLOAD  {payload_info.get('target', '-')}", flush=True)
        print(f"│          {short_text(payload_info.get('payload', ''), 360)}", flush=True)
        print("│", flush=True)

    print(f"│ REQUEST  {str(method).upper()} {summarize_url(url)}", flush=True)
    if body:
        print(f"│ BODY     {short_text(body, 220)}", flush=True)

    status = getattr(response, "status", "-")
    elapsed = getattr(response, "elapsed_seconds", None)
    elapsed_text = f"{elapsed:.3f}s" if isinstance(elapsed, (int, float)) else "-"
    size_text = format_size(len(getattr(response, "text", "") or ""))
    print(f"│ RESPONSE status={status} time={elapsed_text} size={size_text}", flush=True)

    error = getattr(response, "error", None)
    if error:
        print(f"│ ERROR    {short_text(error, 110)}", flush=True)

    print("└" + "─" * 70, flush=True)


def print_recon_transaction(method: Any, url: Any, body: Any, result: Any) -> None:
    print("")
    print("┌" + "─" * 70, flush=True)
    print(f"│ REQUEST  {str(method).upper()} {summarize_url(url)}", flush=True)
    if body:
        print(f"│ BODY     {short_text(body, 92)}", flush=True)
    print(
        "│ RESPONSE status={status} size={size} type={content_type}".format(
            status=getattr(result, "status", "-"),
            size=format_size(len(getattr(result, "text", "") or "")),
            content_type=short_text(getattr(result, "headers", {}).get("content-type", ""), 45),
        ),
        flush=True,
    )
    print("└" + "─" * 70, flush=True)


def short_text(value: Any, limit: int = 240) -> str:
    text = str(value).replace("\n", "\\n").replace("\r", "")
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def compact_target(value: Any) -> str:
    text = str(value)
    return short_text(text, 96)


def summarize_url(value: Any, limit: int = 110) -> str:
    parsed = urlparse(str(value))
    path = parsed.path or str(value)
    if not parsed.query:
        return short_text(path, limit)

    pairs = []
    for name, raw_value in parse_qsl(parsed.query, keep_blank_values=True):
        pairs.append(f"{name}={short_text(raw_value, 34)}")

    return short_text(f"{path}?{'&'.join(pairs)}", limit)


def format_size(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        size = int(value)
    except (TypeError, ValueError):
        return str(value)
    if size < 1024:
        return f"{size}B"
    return f"{size / 1024:.1f}KB"


def patch_recon_logging() -> None:
    """Bọc HTTP client/crawler của recon để thấy request/response realtime."""

    from recontool.http_client import HttpSession

    original_request = HttpSession.request

    def traced_request(self, url, method="GET", body=None, headers=None):
        try:
            result = original_request(self, url, method=method, body=body, headers=headers)
        except Exception as error:
            log_event("ERROR", tool="recon", where="request", error=error)
            raise
        print_recon_transaction(method, url, body, result)
        return result

    HttpSession.request = traced_request

    from recontool.crawlers.playwright_dynamic import DynamicCrawler

    original_on_response = DynamicCrawler._on_response

    def traced_on_response(self, response):
        request = response.request
        before_count = len(self.records)
        original_on_response(self, response)
        kept = len(self.records) > before_count
        print("")
        print("┌" + "─" * 70, flush=True)
        print(f"│ BROWSER  {request.method} {summarize_url(request.url)}", flush=True)
        print(f"│ TYPE     {request.resource_type}", flush=True)
        print(f"│ RESPONSE status={response.status} kept={kept}", flush=True)
        print("└" + "─" * 70, flush=True)

    DynamicCrawler._on_response = traced_on_response


def patch_fuzz_logging() -> None:
    """Bọc mutator và HTTP client của fuzz để thấy payload/request/response."""

    from fuzztool.http_client import FuzzHttpClient
    from fuzztool.mutator import RequestMutator

    original_mutate = RequestMutator.mutate

    def traced_mutate(self, target, payload):
        method, url, body, headers = original_mutate(self, target, payload)
        PENDING_FUZZ_PAYLOAD["target"] = target.key
        PENDING_FUZZ_PAYLOAD["payload"] = payload
        return method, url, body, headers

    RequestMutator.mutate = traced_mutate

    original_send = FuzzHttpClient.send

    def traced_send(self, method, url, body=None, headers=None):
        if self.max_requests is not None and self.request_count >= self.max_requests:
            log_event("ERROR", tool="fuzz", where="send", error=f"Reached max_requests={self.max_requests}")
            return original_send(self, method, url, body=body, headers=headers)

        payload_info = dict(PENDING_FUZZ_PAYLOAD)
        PENDING_FUZZ_PAYLOAD.clear()
        try:
            response = original_send(self, method, url, body=body, headers=headers)
        except Exception as error:
            log_event("ERROR", tool="fuzz", where="send", error=error)
            raise
        print_transaction(method, url, body, response, payload_info)
        return response

    FuzzHttpClient.send = traced_send


def main(argv: List[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if not args or args[0] not in {"recon", "fuzz"}:
        print("Usage: python -m toolcli.trace_runner recon|fuzz [original args...]")
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
