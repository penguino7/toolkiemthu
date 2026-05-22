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

    def __init__(self, tool_config: dict, ai_config: dict, verbose: bool = True) -> None:
        self.tool_config = tool_config
        self.ai_config = ai_config
        self.verbose = verbose
        self.provider = build_provider(ai_config)
        self.mutator = RequestMutator()
        self.guard = PayloadGuard()
        self.summarizer = ResponseSummarizer()
        self.client = self._build_client(tool_config)

    def run_targets(self, targets: List[FuzzTarget], rounds: int) -> List[dict]:
        sessions = []
        total = len(targets)
        for index, target in enumerate(targets, start=1):
            sessions.append(self.run_one_target(target, rounds, index=index, total=total))
        return sessions

    def run_one_target(self, target: FuzzTarget, rounds: int, index: int = 1, total: int = 1) -> dict:
        marker = f"AITEST_{uuid4().hex[:8]}"
        session = {
            "target": self._target_dict(target),
            "marker": marker,
            "rounds": [],
            "confirmed_signals": [],
        }

        self._log("")
        self._log(self._line("="))
        self._log(f"TARGET   {index}/{total}")
        self._log(f"POINT    {target.key}")
        self._log(f"MARKER   {marker}")
        self._log(self._line("="))

        baseline = self._send_baseline(target)
        baseline_summary = self.summarizer.summarize(baseline, marker)
        session["baseline"] = baseline_summary
        self._log_response("BASELINE", baseline)
        self._log(self._line("-"))

        previous_rounds: List[dict] = []
        for round_number in range(1, rounds + 1):
            self._log("")
            self._log(self._line("="))
            self._log(f"ROUND    {round_number}/{rounds}")
            self._log("STEP     Asking AI for next payload")
            self._log(self._line("="))
            decision = self._ask_ai_for_payload(target, marker, baseline_summary, previous_rounds)
            if decision.stop:
                self._log(f"STOP     AI stopped this target: {decision.reason}")
                self._log(self._line("-"))
                session["rounds"].append(
                    {
                        "round": round_number,
                        "stopped_by_ai": True,
                        "reason": decision.reason,
                    }
                )
                break

            self._log(f"AI       attack_type={decision.attack_type}")
            self._log(f"PAYLOAD  {decision.payload}")
            if decision.reason:
                self._log(f"REASON   {decision.reason}")

            check = self.guard.check(decision.payload)
            if not check.allowed:
                self._log(f"GUARD    blocked: {check.reason}")
                self._log(self._line("-"))
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

            self._log(f"GUARD    {check.reason}")
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
            self._log_signals(signals)
            if signals.get("confirmed_signal"):
                self._log("CONFIRM  Signal found in this round")
                session["confirmed_signals"].append(
                    {
                        "round": round_number,
                        "attack_type": decision.attack_type,
                        "signals": signals,
                    }
                )
            self._log(self._line("-"))

        self._log("")
        self._log(self._line("="))
        self._log(f"DONE     Target finished. Confirmed signals: {len(session['confirmed_signals'])}")
        self._log(self._line("="))
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
        self._log_request("BASELINE", method, url, body)
        return self.client.send(method, url, body=body, headers=headers)

    def _send_payload_and_summarize(self, target: FuzzTarget, payload: str, marker: str) -> dict:
        try:
            method, url, body, headers = self.mutator.mutate(target, payload)
            self._log_request("ATTACK", method, url, body)
            response = self.client.send(method, url, body=body, headers=headers)
        except RequestBudgetExceeded as error:
            self._log(f"ERROR    {error}")
            return {
                "status": 0,
                "error": str(error),
                "signals": {"confirmed_signal": False},
            }
        self._log_response("RESPONSE", response)
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
            self._log(f"AI       Provider error, using fallback payload: {error}")
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
            self._log("AI       Invalid JSON response, using fallback payload")
            return self._fallback_decision(target, marker, previous_rounds, "AI không trả JSON hợp lệ")

        if isinstance(data.get("payloads"), list) and data["payloads"]:
            data = data["payloads"][0]

        if not data.get("payload") and not data.get("stop", False):
            self._log("AI       Missing payload in response, using fallback payload")
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

    def _log(self, message: str) -> None:
        if self.verbose:
            print(message, flush=True)

    def _log_request(self, label: str, method: str, url: str, body: str | bytes | None) -> None:
        self._log("")
        self._log(self._line("-"))
        self._log(f"{label:<8} REQUEST")
        self._log(self._line("-"))
        self._log(f"REQUEST  {method.upper()} {url}")
        if body:
            body_text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
            self._log(f"BODY     {body_text}")

    def _log_response(self, label: str, exchange) -> None:
        size = self._format_size(len(exchange.text or ""))
        line = f"RESPONSE status={exchange.status} time={exchange.elapsed_seconds:.3f}s size={size}"
        if exchange.error:
            line += f" error={exchange.error}"
        self._log(line)

    def _log_signals(self, signals: dict) -> None:
        sql_errors = ",".join(signals.get("sql_error_patterns", [])) or "-"
        matched = ",".join(signals.get("matched_paths", [])) or "-"
        ignored = ",".join(signals.get("ignored_paths", [])) or "-"
        self._log(
            "SIGNAL   confirmed={confirmed} sql_error={sql_error} marker_in_data={marker} "
            "matched={matched} ignored={ignored}".format(
                confirmed=signals.get("confirmed_signal", False),
                sql_error=sql_errors,
                marker=signals.get("marker_in_data", False),
                matched=matched,
                ignored=ignored,
            )
        )

    def _format_size(self, size: int) -> str:
        if size >= 1024 * 1024:
            return f"{size / (1024 * 1024):.1f}MB"
        if size >= 1024:
            return f"{size / 1024:.1f}KB"
        return f"{size}B"

    def _line(self, char: str = "-") -> str:
        return char * 72
