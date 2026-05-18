from __future__ import annotations

from .prompts import SYSTEM_PROMPT
from .providers import ChatMessage, build_provider


class AiClient:
    """Client chung, không phụ thuộc trực tiếp vào Ollama hay provider cụ thể."""

    def __init__(self, config: dict) -> None:
        self.provider = build_provider(config)

    def analyze_prompt(self, prompt: str) -> str:
        messages = [
            ChatMessage(role="system", content=SYSTEM_PROMPT),
            ChatMessage(role="user", content=prompt),
        ]
        return self.provider.complete(messages)

