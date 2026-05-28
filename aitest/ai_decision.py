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
    """Goi AI, parse ket qua va fallback khi API loi."""

    def __init__(self, ai_config: dict, fallback_union_columns: int = 8) -> None:
        self.ai_api = AiApiClient(ai_config)
        self.fallback_union_columns = fallback_union_columns

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
            return self._parse_payload(raw)
        except Exception as error:
            return self._fallback_payload(target, marker, len(previous_rounds) + 1, f"AI fallback: {error}")

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
            return self._parse_verdict(raw)
        except Exception as error:
            verdict = self._fallback_verdict(response)
            verdict.reason = f"AI verdict fallback: {error}; {verdict.reason}"
            verdict.source = "fallback"
            return verdict

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

    def _fallback_payload(
        self,
        target: FuzzTarget,
        marker: str,
        round_number: int,
        reason: str,
    ) -> AiPayloadDecision:
        sample = target.sample_value
        name = target.param_name.lower()
        is_sqli = target.type_hint in {"int", "float"} or name == "id" or name.endswith("_id")

        if is_sqli:
            return self._fallback_sqli_payload(sample, marker, round_number, reason)
        return self._fallback_xss_payload(marker, round_number, reason)

    def _fallback_sqli_payload(self, sample: str, marker: str, round_number: int, reason: str) -> AiPayloadDecision:
        if round_number == 1:
            return AiPayloadDecision(f"{sample}'", "sqli_error", reason, "SQL error", source="fallback")
        if round_number == 2:
            return AiPayloadDecision(f"{sample} ORDER BY 12-- -", "sqli_order_by", reason, "SQL error", source="fallback")
        if round_number == 3:
            columns = ",".join(f"'{marker}_C{index:02d}'" for index in range(1, self.fallback_union_columns + 1))
            return AiPayloadDecision(f"-1 UNION SELECT {columns}-- -", "sqli_union", reason, "marker rendered", source="fallback")
        return AiPayloadDecision(stop=True, attack_type="stop", reason="fallback da thu du vong", source="fallback")

    def _fallback_xss_payload(self, marker: str, round_number: int, reason: str) -> AiPayloadDecision:
        if round_number == 1:
            return AiPayloadDecision(f'"><svg/onload=alert("{marker}")>', "xss_reflection", reason, "marker reflected", source="fallback")
        if round_number == 2:
            return AiPayloadDecision(f'<script>alert("{marker}")</script>', "xss_reflection", reason, "browser alert", source="fallback")
        return AiPayloadDecision(stop=True, attack_type="stop", reason="fallback da thu du vong", source="fallback")

    def _fallback_verdict(self, response: dict) -> AiEvidenceVerdict:
        signals = response.get("signals", {})
        if signals.get("objective_proof"):
            proof_type = signals.get("objective_proof_type", "objective_proof")
            vuln_type = "xss" if proof_type == "xss_alert" else "sqli"
            return AiEvidenceVerdict("confirmed", vuln_type, "high", f"objective proof found: {proof_type}", source="fallback")
        if signals.get("sql_error_confirmed"):
            return AiEvidenceVerdict("suspicious", "sqli", "medium", "SQL error observed, but no exploit proof yet", "try ORDER BY or UNION marker proof", "fallback")
        if signals.get("xss_reflection"):
            return AiEvidenceVerdict("suspicious", "xss", "medium", "marker reflected, but browser execution not confirmed", "try browser-executable XSS payload", "fallback")
        return AiEvidenceVerdict("no_issue", "none", "low", "no useful signal", source="fallback")
