from __future__ import annotations

from typing import Callable
from uuid import uuid4

from fuzztool.http_client import FuzzHttpClient, RequestBudgetExceeded
from fuzztool.models import FuzzTarget
from fuzztool.mutator import RequestMutator
from fuzztool.xss_scanner import BrowserXssVerifier

from .ai_decision import AiDecisionEngine, AiPayloadDecision
from .payload_guard import PayloadGuard
from .response_summarizer import ResponseSummarizer


class AiIterativeSessionRunner:
    """Dieu phoi 1 session AI test: baseline -> payload -> response -> AI verdict."""

    def __init__(
        self,
        tool_config: dict,
        ai_config: dict,
        on_round: Callable[[dict], None] | None = None,
    ) -> None:
        safety = tool_config.get("safety", {})
        aitest_config = tool_config.get("aitest", {})

        self.on_round = on_round
        self.tool_config = tool_config
        self.ai = AiDecisionEngine(
            ai_config,
            fallback_union_columns=int(aitest_config.get("fallback_union_columns", 8)),
        )
        self.client = FuzzHttpClient(
            headers=tool_config.get("headers", {}),
            max_requests=int(safety.get("max_requests", 100)),
            delay_seconds=float(safety.get("delay_seconds", 0.05)),
            timeout=int(safety.get("request_timeout_seconds", 15)),
            use_environment_proxy=bool(safety.get("use_environment_proxy", False)),
        )
        self.mutator = RequestMutator()
        self.guard = PayloadGuard()
        self.summarizer = ResponseSummarizer(options=aitest_config)

    def run_targets(self, targets: list[FuzzTarget], rounds: int) -> list[dict]:
        total = len(targets)
        sessions = []
        for index, target in enumerate(targets, start=1):
            sessions.append(self.run_one_target(target, rounds, index, total))
        return sessions

    def run_one_target(self, target: FuzzTarget, rounds: int, index: int, total: int) -> dict:
        marker = f"AITEST_{uuid4().hex[:8]}"
        baseline = self._send_request(target, marker)
        session = self._new_session(target, marker, baseline)
        previous_rounds: list[dict] = []

        for round_number in range(1, rounds + 1):
            decision = self.ai.next_payload(target, marker, baseline, previous_rounds)
            if decision.stop:
                self._record_stop(session, target, index, total, round_number, decision)
                break

            payload_check = self.guard.check(decision.payload)
            if not payload_check.allowed:
                self._record_blocked(session, target, index, total, round_number, decision, payload_check.reason)
                break

            response = self._send_request(target, marker, decision.payload)
            self._verify_xss_if_needed(decision, response, marker)
            verdict = self.ai.verdict(target, marker, decision, response, previous_rounds)

            round_item = self._round_item(round_number, decision, payload_check.reason, response, verdict.to_dict())
            session["rounds"].append(round_item)
            previous_rounds.append(round_item)
            self._save_observations(session, round_number, decision, response, verdict.to_dict())
            self._emit_table_row(
                target,
                index,
                total,
                round_number,
                decision,
                response.get("status", "-"),
                verdict.status == "confirmed",
                f"ai:{verdict.status} | {self._comment(response.get('signals', {}))}",
            )

            if verdict.status == "confirmed":
                break

        return session

    def _new_session(self, target: FuzzTarget, marker: str, baseline: dict) -> dict:
        return {
            "target": self._target_dict(target),
            "marker": marker,
            "baseline": baseline,
            "rounds": [],
            "ai_verdicts": [],
            "tool_observations": [],
            "objective_proofs": [],
        }

    def _record_stop(self, session: dict, target: FuzzTarget, index: int, total: int, round_number: int, decision: AiPayloadDecision) -> None:
        session["rounds"].append(
            {
                "round": round_number,
                "stopped_by_ai": True,
                "attack_type": "stop",
                "payload": "",
                "reason": decision.reason or "AI stopped this target",
                "source": decision.source,
            }
        )
        self._emit_table_row(target, index, total, round_number, decision, "-", False, "stopped_by_ai")

    def _record_blocked(
        self,
        session: dict,
        target: FuzzTarget,
        index: int,
        total: int,
        round_number: int,
        decision: AiPayloadDecision,
        reason: str,
    ) -> None:
        session["rounds"].append(
            {
                "round": round_number,
                "payload": decision.payload,
                "attack_type": decision.attack_type,
                "reason": decision.reason,
                "guard": f"blocked: {reason}",
            }
        )
        self._emit_table_row(target, index, total, round_number, decision, "-", False, f"blocked: {reason}")

    def _round_item(self, round_number: int, decision: AiPayloadDecision, guard: str, response: dict, verdict: dict) -> dict:
        return {
            "round": round_number,
            "payload": decision.payload,
            "attack_type": decision.attack_type,
            "reason": decision.reason,
            "expected_signal": decision.expected_signal,
            "guard": guard,
            "response": response,
            "ai_verdict": verdict,
        }

    def _save_observations(self, session: dict, round_number: int, decision: AiPayloadDecision, response: dict, verdict: dict) -> None:
        signals = response.get("signals", {})
        if signals.get("candidate_signal") or signals.get("objective_proof"):
            session["tool_observations"].append(
                {
                    "round": round_number,
                    "attack_type": decision.attack_type,
                    "signals": signals,
                }
            )
        if verdict.get("status") == "confirmed":
            session["ai_verdicts"].append(
                {
                    "round": round_number,
                    "attack_type": decision.attack_type,
                    "verdict": verdict,
                }
            )
        if signals.get("objective_proof"):
            session["objective_proofs"].append(
                {
                    "round": round_number,
                    "attack_type": decision.attack_type,
                    "proof_type": signals.get("objective_proof_type", "objective_proof"),
                    "signals": signals,
                    "ai_verdict": verdict,
                }
            )

    def _send_request(self, target: FuzzTarget, marker: str, payload: str | None = None) -> dict:
        try:
            if payload is None:
                method, url, body, headers = self.mutator.baseline(target)
            else:
                method, url, body, headers = self.mutator.mutate(target, payload)

            response = self.client.send(method, url, body=body, headers=headers)
            return self.summarizer.summarize(response, marker)
        except RequestBudgetExceeded as error:
            return {"status": 0, "error": str(error), "signals": {"candidate_signal": False, "objective_proof": False}}

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
            signals["objective_proof"] = True
            signals["objective_proof_type"] = "xss_alert"

    def _comment(self, signals: dict) -> str:
        if signals.get("objective_proof_type") == "union_marker":
            columns = ",".join(signals.get("visible_columns", [])) or "-"
            return f"proof:union columns={columns}"
        if signals.get("objective_proof_type") == "xss_alert":
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
        if not self.on_round:
            return
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
