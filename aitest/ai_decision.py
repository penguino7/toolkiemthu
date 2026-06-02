from __future__ import annotations

import json
from dataclasses import dataclass

from aicore.api_client import AiApiClient, ChatMessage
from fuzztool.models import FuzzTarget

from .prompts import build_payload_prompt, build_verdict_prompt


@dataclass
class AiPayloadDecision:
    payload: str = ""
    attack_type: str = "unknown"
    reason: str = ""
    expected_signal: str = ""
    stop: bool = False
    source: str = "ai"


@dataclass
class AiEvidenceVerdict:
    status: str = "unknown"
    vuln_type: str = "none"
    confidence: str = "low"
    reason: str = ""
    next_step: str = ""
    source: str = "ai"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "vuln_type": self.vuln_type,
            "confidence": self.confidence,
            "reason": self.reason,
            "next_step": self.next_step,
            "source": self.source,
        }


class AiDecisionEngine:
    """Goi AI va parse ket qua. Khong tu sinh payload thay cho AI."""

    def __init__(self, ai_config: dict) -> None:
        self.ai_api = AiApiClient(ai_config)

    def next_payload(
        self,
        target: FuzzTarget,
        marker: str,
        baseline: dict,
        previous_rounds: list[dict],
    ) -> AiPayloadDecision:
        try:
            prompt = build_payload_prompt(target, marker, baseline, previous_rounds)
            raw = self.ai_api.complete([ChatMessage(role="user", content=prompt)])
            decision = self._parse_payload(raw)
            self._validate_focus(target, decision)
            return decision
        except Exception as error:
            return AiPayloadDecision(
                attack_type="stop",
                reason=f"AI error, dung target: {error}",
                stop=True,
                source="ai_error",
            )

    def verdict(
        self,
        target: FuzzTarget,
        marker: str,
        decision: AiPayloadDecision,
        response: dict,
        previous_rounds: list[dict],
    ) -> AiEvidenceVerdict:
        try:
            prompt = build_verdict_prompt(target, marker, decision.__dict__, response, previous_rounds)
            raw = self.ai_api.complete([ChatMessage(role="user", content=prompt)])
            verdict = self._parse_verdict(raw)
            return self._validate_verdict_focus(target, verdict)
        except Exception as error:
            return AiEvidenceVerdict(
                status="unknown",
                reason=f"AI verdict error: {error}",
                source="ai_error",
            )

    def _parse_payload(self, raw_text: str) -> AiPayloadDecision:
        data = self._extract_json(raw_text)
        if isinstance(data.get("payloads"), list) and data["payloads"]:
            data = data["payloads"][0]

        return AiPayloadDecision(
            payload=str(data.get("payload", "")),
            attack_type=str(data.get("attack_type", "unknown")),
            reason=str(data.get("reason", "")),
            expected_signal=str(data.get("expected_signal", "")),
            stop=bool(data.get("stop", False)),
        )

    def _parse_verdict(self, raw_text: str) -> AiEvidenceVerdict:
        data = self._extract_json(raw_text)
        return AiEvidenceVerdict(
            status=self._safe_choice(data.get("status"), {"no_issue", "suspicious", "confirmed"}, "suspicious"),
            vuln_type=self._safe_choice(data.get("vuln_type"), {"none", "sqli", "xss"}, "none"),
            confidence=self._safe_choice(data.get("confidence"), {"low", "medium", "high"}, "low"),
            reason=str(data.get("reason", "")),
            next_step=str(data.get("next_step", "")),
        )

    def _extract_json(self, raw_text: str) -> dict:
        text = (raw_text or "").strip()
        if not text:
            raise ValueError("empty AI response")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start < 0 or end <= start:
                raise ValueError("AI response has no JSON") from None
            return json.loads(text[start : end + 1])

    def _safe_choice(self, value: object, allowed: set[str], default: str) -> str:
        text = str(value or default).lower()
        return text if text in allowed else default

    def _validate_focus(self, target: FuzzTarget, decision: AiPayloadDecision) -> None:
        if decision.stop:
            return

        focus = getattr(target, "aitest_focus", "auto")
        if focus == "xss" and not decision.attack_type.startswith("xss"):
            raise ValueError(f"target XSS nhung AI tra attack_type={decision.attack_type}")
        if focus == "sqli" and not decision.attack_type.startswith("sqli"):
            raise ValueError(f"target SQLi nhung AI tra attack_type={decision.attack_type}")

    def _validate_verdict_focus(self, target: FuzzTarget, verdict: AiEvidenceVerdict) -> AiEvidenceVerdict:
        """Không nhận verdict trái với nhóm lỗ hổng đang kiểm thử."""
        focus = getattr(target, "aitest_focus", "auto")
        wrong_group = (focus == "xss" and verdict.vuln_type == "sqli") or (
            focus == "sqli" and verdict.vuln_type == "xss"
        )
        if not wrong_group:
            return verdict

        return AiEvidenceVerdict(
            status="suspicious",
            vuln_type="none",
            confidence="low",
            reason=(
                f"AI trả verdict {verdict.vuln_type} trong khi target đang kiểm thử {focus}. "
                "Chương trình chỉ giữ đây là tín hiệu phụ và không dùng làm kết luận."
            ),
            next_step=f"Tiếp tục kiểm thử đúng nhóm {focus} hoặc dừng target nếu không còn payload phù hợp.",
            source="ai_scope_guard",
        )
