from __future__ import annotations

import argparse
import os
import time

from .api_client import AiApiClient, ChatMessage
from .config import AiConfigLoader


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Test AI provider/API key")
    parser.add_argument("-c", "--config", default="ai.config.example.json", help="File config AI")
    parser.add_argument("--test-prompt", default="Tra loi ngan gon bang dung chu OK.", help="Prompt test")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    config = AiConfigLoader().load(args.config)
    provider = config.get("provider", {})

    print("[*] Testing AI provider")
    print(f"[*] Provider : {provider.get('name', 'openai_compatible')}")
    print(f"[*] Model    : {provider.get('model', '-')}")
    print(f"[*] Base URL : {provider.get('base_url', '-')}")

    api_key_env = str(provider.get("api_key_env", ""))
    if api_key_env:
        if not os.environ.get(api_key_env):
            print(f"[!] Missing API key env: {api_key_env}")
            return 2
        print(f"[*] API key  : loaded from {api_key_env}")

    client = AiApiClient(config)
    started = time.perf_counter()
    try:
        content = client.complete([ChatMessage(role="user", content=args.test_prompt)])
    except Exception as error:
        print(f"[!] Provider test failed: {error}")
        return 1

    preview = content.strip().replace("\n", " ")
    if len(preview) > 300:
        preview = preview[:297] + "..."

    print(f"[+] Provider test OK in {time.perf_counter() - started:.2f}s")
    print(f"[+] Content: {preview or '<empty>'}")
    if client.last_usage:
        print(f"[+] Tokens : {client.last_usage}")
    return 0
