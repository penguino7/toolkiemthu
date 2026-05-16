from __future__ import annotations

from collections import deque
from pathlib import Path

from ..normalizer import absolute_url, make_record
from ..scope import in_scope


def crawl_dynamic(config: dict) -> list:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError(
            "Playwright chưa được cài. Chạy: pip install playwright && python -m playwright install chromium"
        ) from error

    base_url = config["base_url"]
    options = config.get("dynamic", {})
    max_pages = int(options.get("max_pages", 20))
    timeout_ms = int(options.get("timeout_ms", 15000))
    headless = bool(options.get("headless", True))
    auth_context = config.get("auth_context", "anonymous")
    headers = config.get("headers", {})
    seeds = [absolute_url(seed, base_url) for seed in config.get("seeds", ["/"])]
    records = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context_kwargs = {"extra_http_headers": headers}
        storage_state = options.get("storage_state")
        if storage_state and Path(storage_state).exists():
            context_kwargs["storage_state"] = storage_state
        context = browser.new_context(**context_kwargs)
        page = context.new_page()

        def on_response(response):
            request = response.request
            post_data = request.post_data or None
            records.append(
                make_record(
                    request.method,
                    request.url,
                    "playwright_dynamic_crawler",
                    base_url=base_url,
                    auth_context=auth_context,
                    status=response.status,
                    request_content_type=request.headers.get("content-type", ""),
                    response_content_type=response.headers.get("content-type", ""),
                    body=post_data,
                )
            )

        page.on("response", on_response)

        queue = deque(seeds)
        visited = set()
        while queue and len(visited) < max_pages:
            url = queue.popleft()
            if url in visited or not in_scope(url, config):
                continue
            visited.add(url)
            try:
                page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception:
                continue
            try:
                links = page.eval_on_selector_all("a[href]", "els => els.map(a => a.href)")
            except Exception:
                links = []
            for link in links:
                normalized = absolute_url(link, base_url)
                if normalized not in visited and in_scope(normalized, config):
                    queue.append(normalized)

        context.close()
        browser.close()

    return records
