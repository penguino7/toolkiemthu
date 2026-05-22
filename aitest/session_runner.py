from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, List
from uuid import uuid4

from aitool.providers import ChatMessage, build_provider
from fuzztool.http_client import FuzzHttpClient, RequestBudgetExceeded
from fuzztool.models import FuzzTarget
from fuzztool.mutator import RequestMutator

from .payload_guard import PayloadGuard
from .response_summarizer import ResponseSummarizer


@dataclass
class AiPayloadDecision:
    payload: str
    attack_type: str
    reason: str
    expected_signal: str
    stop: bool = False


class AiIterativeSessionRunner:
    """Chạy baseline -> AI payload -> request -> summarize response trong nhiều vòng."""

    def __init__(self, tool_config: dict, ai_config: dict) -> None:
        self.tool_config = tool_config
        self.ai_config = ai_config
        self.provider = build_provider(ai_config)
        self.mutator = RequestMutator()
        self.guard = PayloadGuard()
        self.summarizer = ResponseSummarizer()
        self.client = self._build_client(tool_config)

    def run_targets(self, targets: List[FuzzTarget], rounds: int) -> List[dict]:
        return [self.run_one_target(target, rounds) for target in targets]

    def run_one_target(self, target: FuzzTarget, rounds: int) -> dict:
        marker = f"AITEST_{uuid4().hex[:8]}"
        session = {
            "target": self._target_dict(target),
            "marker": marker,
            "rounds": [],
            "confirmed_signals": [],
        }

        baseline = self._send_baseline(target)
        baseline_summary = self.summarizer.summarize(baseline, marker)
        session["baseline"] = baseline_summary

        previous_rounds: List[dict] = []
        for round_number in range(1, rounds + 1):
            decision = self._ask_ai_for_payload(target, marker, baseline_summary, previous_rounds)
            if decision.stop:
                session["rounds"].append(
                    {
                        "round": round_number,
                        "stopped_by_ai": True,
                        "reason": decision.reason,
                    }
                )
                break

            check = self.guard.check(decision.payload)
            if not check.allowed:
                item = {
                    "round": round_number,
                    "payload": decision.payload,
                    "attack_type": decision.attack_type,
                    "reason": decision.reason,
                    "expected_signal": decision.expected_signal,
                    "guard": f"blocked: {check.reason}",
                }
                session["rounds"].append(item)
                previous_rounds.append(item)
                break

            response_summary = self._send_payload_and_summarize(target, decision.payload, marker)
            item = {
                "round": round_number,
                "payload": decision.payload,
                "attack_type": decision.attack_type,
                "reason": decision.reason,
                "expected_signal": decision.expected_signal,
                "guard": check.reason,
                "response": response_summary,
            }
            session["rounds"].append(item)
            previous_rounds.append(item)

            signals = response_summary.get("signals", {})
            if signals.get("confirmed_signal"):
                session["confirmed_signals"].append(
                    {
                        "round": round_number,
                        "attack_type": decision.attack_type,
                        "signals": signals,
                    }
                )

        return session

    def _build_client(self, config: dict) -> FuzzHttpClient:
        safety = config.get("safety", {})
        return FuzzHttpClient(
            headers=config.get("headers", {}),
            max_requests=int(safety.get("max_requests", 100)),
            delay_seconds=float(safety.get("delay_seconds", 0.05)),
            timeout=int(safety.get("request_timeout_seconds", 15)),
            use_environment_proxy=bool(safety.get("use_environment_proxy", False)),
        )

    def _send_baseline(self, target: FuzzTarget):
        method, url, body, headers = self.mutator.baseline(target)
        return self.client.send(method, url, body=body, headers=headers)

    def _send_payload_and_summarize(self, target: FuzzTarget, payload: str, marker: str) -> dict:
        try:
            method, url, body, headers = self.mutator.mutate(target, payload)
            response = self.client.send(method, url, body=body, headers=headers)
        except RequestBudgetExceeded as error:
            return {
                "status": 0,
                "error": str(error),
                "signals": {"confirmed_signal": False},
            }
        return self.summarizer.summarize(response, marker)

    def _ask_ai_for_payload(
        self,
        target: FuzzTarget,
        marker: str,
        baseline: dict,
        previous_rounds: List[dict],
    ) -> AiPayloadDecision:
        prompt = self._build_prompt(target, marker, baseline, previous_rounds)
        try:
            raw = self.provider.complete(
                [
                    ChatMessage(role="system", content=self._system_prompt()),
                    ChatMessage(role="user", content=prompt),
                ]
            )
        except Exception as error:
            return self._fallback_decision(target, marker, previous_rounds, f"AI provider lỗi: {error}")
        return self._parse_ai_decision(raw, target, marker, previous_rounds)

    def _system_prompt(self) -> str:
        return (
            "Bạn là trợ lý tạo payload kiểm thử web có kiểm soát cho lab được ủy quyền. "
            "Chỉ đề xuất payload không phá hoại. Không dùng DROP/DELETE/UPDATE/INSERT/OUTFILE/LOAD_FILE/RCE. "
            "Trả lời duy nhất bằng JSON hợp lệ."
        )

    def _build_prompt(self, target: FuzzTarget, marker: str, baseline: dict, previous_rounds: List[dict]) -> str:
        payload = {
            "task": "Đề xuất đúng 1 payload tiếp theo cho vòng kiểm thử hiện tại.",
            "rules": [
                "Chỉ trả JSON, không markdown.",
                "Payload phải dùng cho đúng param đang test.",
                "Nếu cần marker, dùng chính xác marker được cung cấp.",
                "Ưu tiên payload proof an toàn: quote/error, ORDER BY, UNION SELECT marker, boolean condition, XSS marker.",
                "Không đề xuất payload phá hoại dữ liệu hoặc đọc file/hệ thống.",
                "Nếu đã đủ bằng chứng hoặc không nên test tiếp, đặt stop=true.",
            ],
            "expected_json": {
                "payload": "string",
                "attack_type": "sqli_error|sqli_boolean|sqli_order_by|sqli_union|xss_reflection|stop",
                "reason": "vì sao chọn payload này",
                "expected_signal": "dấu hiệu mong đợi trong response",
                "stop": False,
            },
            "marker": marker,
            "target": self._target_dict(target),
            "baseline": baseline,
            "previous_rounds": previous_rounds[-4:],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    def _parse_ai_decision(
        self,
        raw_response: str,
        target: FuzzTarget,
        marker: str,
        previous_rounds: List[dict],
    ) -> AiPayloadDecision:
        data = self._extract_json(raw_response)
        if not data:
            return self._fallback_decision(target, marker, previous_rounds, "AI không trả JSON hợp lệ")

        if isinstance(data.get("payloads"), list) and data["payloads"]:
            data = data["payloads"][0]

        if not data.get("payload") and not data.get("stop", False):
            return self._fallback_decision(target, marker, previous_rounds, "AI response thiếu payload hợp lệ")

        return AiPayloadDecision(
            payload=str(data.get("payload", "")),
            attack_type=str(data.get("attack_type", "unknown")),
            reason=str(data.get("reason", "")),
            expected_signal=str(data.get("expected_signal", "")),
            stop=bool(data.get("stop", False)),
        )

    def _extract_json(self, raw_response: str) -> dict:
        text = (raw_response or "").strip()
        if not text:
            return {}

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start < 0 or end <= start:
                return {}
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return {}

    def _fallback_decision(
        self,
        target: FuzzTarget,
        marker: str,
        previous_rounds: List[dict],
        reason: str,
    ) -> AiPayloadDecision:
        sample = target.sample_value
        round_index = len(previous_rounds) + 1
        is_numeric = target.type_hint in {"int", "float"}

        if any("sqli" in test for test in target.candidate_tests):
            if round_index == 1:
                payload = f"{sample}'"
                attack_type = "sqli_error"
            elif round_index == 2 and is_numeric:
                payload = f"{sample} ORDER BY 12-- -"
                attack_type = "sqli_order_by"
            elif round_index == 3 and is_numeric:
                payload = f"-1 UNION SELECT '{marker}','{marker}','{marker}','{marker}','{marker}','{marker}','{marker}','{marker}','{marker}','{marker}','{marker}'-- -"
                attack_type = "sqli_union"
            else:
                return AiPayloadDecision("", "stop", reason, "", True)
            return AiPayloadDecision(payload, attack_type, reason, "SQL error or marker in data field")

        payload = f'"><svg/onload=alert("{marker}")>'
        return AiPayloadDecision(payload, "xss_reflection", reason, "marker reflected in HTML response")

    def _target_dict(self, target: FuzzTarget) -> dict:
        return {
            "method": target.method,
            "url": target.url,
            "path": target.path,
            "auth_context": target.auth_context,
            "param": target.param_name,
            "location": target.param_location,
            "type_hint": target.type_hint,
            "sample_value": target.sample_value,
            "candidate_tests": target.candidate_tests,
        }
