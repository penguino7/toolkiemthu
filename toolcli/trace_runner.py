from __future__ import annotations

import sys
from typing import Any, List


def log_event(event: str, **fields: Any) -> None:
    """In một dòng log dễ đọc cho terminal launcher."""

    parts = [f"[{event}]"]
    for key, value in fields.items():
        if value in (None, ""):
            continue
        parts.append(f"{key}={short_text(value)}")
    print(" ".join(parts), flush=True)


def short_text(value: Any, limit: int = 240) -> str:
    text = str(value).replace("\n", "\\n").replace("\r", "")
    if len(text) <= limit:
        return text
    return text[:limit] + "...<trimmed>"


def patch_recon_logging() -> None:
    """Bọc HTTP client/crawler của recon để thấy request/response realtime."""

    from recontool.http_client import HttpSession

    original_request = HttpSession.request

    def traced_request(self, url, method="GET", body=None, headers=None):
        log_event("REQUEST", tool="recon", method=method.upper(), url=url, body=body)
        try:
            result = original_request(self, url, method=method, body=body, headers=headers)
        except Exception as error:
            log_event("ERROR", tool="recon", where="request", error=error)
            raise
        log_event(
            "RESPONSE",
            tool="recon",
            status=result.status,
            url=result.url,
            content_type=result.headers.get("content-type", ""),
            length=len(result.text),
        )
        return result

    HttpSession.request = traced_request

    from recontool.crawlers.playwright_dynamic import DynamicCrawler

    original_on_response = DynamicCrawler._on_response

    def traced_on_response(self, response):
        request = response.request
        before_count = len(self.records)
        log_event(
            "BROWSER_REQUEST",
            tool="recon",
            method=request.method,
            url=request.url,
            resource_type=request.resource_type,
        )
        original_on_response(self, response)
        kept = len(self.records) > before_count
        log_event("BROWSER_RESPONSE", tool="recon", status=response.status, kept=kept, url=request.url)

    DynamicCrawler._on_response = traced_on_response


def patch_fuzz_logging() -> None:
    """Bọc mutator và HTTP client của fuzz để thấy payload/request/response."""

    from fuzztool.http_client import FuzzHttpClient
    from fuzztool.mutator import RequestMutator

    original_mutate = RequestMutator.mutate

    def traced_mutate(self, target, payload):
        method, url, body, headers = original_mutate(self, target, payload)
        log_event(
            "PAYLOAD",
            tool="fuzz",
            target=target.key,
            param=f"{target.param_location}:{target.param_name}",
            payload=payload,
        )
        return method, url, body, headers

    RequestMutator.mutate = traced_mutate

    original_send = FuzzHttpClient.send

    def traced_send(self, method, url, body=None, headers=None):
        log_event("REQUEST", tool="fuzz", method=method.upper(), url=url, body=body)
        try:
            response = original_send(self, method, url, body=body, headers=headers)
        except Exception as error:
            log_event("ERROR", tool="fuzz", where="send", error=error)
            raise
        log_event(
            "RESPONSE",
            tool="fuzz",
            status=response.status,
            elapsed=f"{response.elapsed_seconds:.3f}s",
            length=len(response.text),
            error=response.error,
        )
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
