from __future__ import annotations

import json

from fuzztool.models import FuzzTarget


def build_payload_prompt(target: FuzzTarget, marker: str, baseline: dict, previous_rounds: list[dict]) -> str:
    """Build the prompt used to request the next payload from the AI."""
    data = {
        "task": "next_payload",
        "role": "You are an AI assistant for authorized XSS and SQL injection testing in a controlled lab.",
        "goal": "Read the response context and choose exactly one suitable next payload based on the observed evidence.",
        "rules": [
            "Return valid JSON only. Do not use Markdown.",
            "Test only XSS and SQL injection.",
            "Do not use destructive payloads: DROP, DELETE, UPDATE, INSERT, OUTFILE, LOAD_FILE, or RCE.",
            "Generate exactly one short, purposeful payload per round. The payload must fit the target parameter.",
            "Base the payload on baseline, previous_rounds, response_context, and previous ai_verdict values.",
            "Review recommended_next_step from the previous verdict before choosing the next payload. Treat it as guidance, then verify that it still matches the latest response evidence.",
            "Keep the assigned target.test_focus. For focus=sqli, return only an sqli_* attack type. For focus=xss, return only xss_reflection or stop. Never switch vulnerability groups.",
            "Do not follow a fixed sequence. Choose a quote probe, boolean condition, ORDER BY, UNION, or XSS payload according to the latest response.",
            "Do not treat a standalone SQL error as proof of successful exploitation.",
            "For UNION testing, prefer a distinct marker for each column: MARKER_C01, MARKER_C02, and so on.",
            "Do not repeat payloads already present in previous_rounds.",
            "Read response_context.html_text when mode is html_text. If raw_response exists, read it. Otherwise, read signal_windows, raw_head, and raw_tail.",
        ],
        "strategy_options": [
            "If the response is normal and contains no useful signal, try a lightweight SQLi or XSS probe that matches the assigned focus.",
            "If a SQL error appears, choose a boolean, ORDER BY, UNION, or another safe payload based on the error details.",
            "If the marker appears only in debug, sql, request, or echoed parameter fields, try to produce evidence in real response data or rendered HTML.",
            "If an XSS marker is reflected in HTML, try a payload that may trigger a browser alert.",
            "If sufficient evidence already exists or no safe next step remains, return stop=true.",
        ],
        "expected_json": {
            "payload": "string",
            "attack_type": "sqli_error|sqli_order_by|sqli_union|xss_reflection|stop",
            "reason": "brief reason for choosing this payload",
            "expected_signal": "expected evidence in the response",
            "stop": False,
        },
        "marker": marker,
        "target": _target_dict(target),
        "current_state": _state_summary(previous_rounds),
        "session_memory": _session_memory(previous_rounds),
        "recommended_next_step": _recommended_next_step(previous_rounds),
        "baseline": _short_response(baseline),
        "previous_rounds": _short_rounds(previous_rounds[-3:]),
    }
    return json.dumps(data, ensure_ascii=False)


def build_verdict_prompt(
    target: FuzzTarget,
    marker: str,
    payload_decision: dict,
    response: dict,
    previous_rounds: list[dict],
) -> str:
    """Build the prompt used to request an evidence verdict from the AI."""
    data = {
        "task": "evidence_verdict",
        "role": "You are an AI reviewer for authorized XSS and SQL injection testing in a controlled lab.",
        "goal": "Read the actual response evidence and classify the latest payload result as no_issue, suspicious, or confirmed.",
        "important": [
            "Signals are hints extracted by the tool, not mandatory conclusions.",
            "Read response_context, html_text, raw_response, and signal_windows yourself before returning a verdict.",
            "Keep the assigned target.test_focus. For focus=xss, return only vuln_type=xss or none. For focus=sqli, return only vuln_type=sqli or none.",
            "If the response contains a signal outside target.test_focus, treat it only as a secondary observation. Do not switch vulnerability groups.",
            "A standalone SQL error is suspicious evidence, not confirmed exploitation.",
            "Confirm XSS only when alert, dialog, or browser execution evidence exists.",
            "Confirm SQLi only when a marker or UNION column appears in real response data or rendered HTML, not only in sql, debug, request, or echoed parameter fields.",
            "If evidence is insufficient, return suspicious and suggest a next_step.",
        ],
        "expected_json": {
            "status": "no_issue|suspicious|confirmed",
            "vuln_type": "none|sqli|xss",
            "confidence": "low|medium|high",
            "reason": "brief explanation of why the evidence is or is not sufficient",
            "next_step": "recommended payload or testing direction if the issue is not confirmed",
        },
        "marker": marker,
        "target": _target_dict(target),
        "payload_decision": payload_decision,
        "response": _short_response(response),
        "previous_rounds": _short_rounds(previous_rounds[-2:]),
    }
    return json.dumps(data, ensure_ascii=False)


def _target_dict(target: FuzzTarget) -> dict:
    return {
        "method": target.method,
        "url": target.url,
        "path": target.path,
        "param": target.param_name,
        "location": target.param_location,
        "type_hint": target.type_hint,
        "sample_value": target.sample_value,
        "test_focus": getattr(target, "aitest_focus", "auto"),
    }


def _state_summary(rounds: list[dict]) -> dict:
    return {
        "has_sql_error": any(_signals(item).get("sql_error_confirmed") for item in rounds),
        "has_xss_reflection": any(_signals(item).get("xss_reflection") for item in rounds),
        "has_objective_proof": any(_signals(item).get("objective_proof") for item in rounds),
        "has_ai_confirmed": any(item.get("ai_verdict", {}).get("status") == "confirmed" for item in rounds),
        "tried_attack_types": [item.get("attack_type", "") for item in rounds],
        "tried_payloads": [item.get("payload", "") for item in rounds],
    }


def _session_memory(rounds: list[dict]) -> dict:
    if not rounds:
        return {
            "tested_payloads": [],
            "last_verdict": {},
            "important_observations": [],
            "last_suggested_next_step": "",
        }

    observations = []
    for item in rounds:
        signals = _signals(item)
        verdict = item.get("ai_verdict", {})
        if signals.get("sql_error_confirmed"):
            observations.append("SQL error observed")
        if signals.get("xss_reflection"):
            observations.append("XSS marker reflected")
        if signals.get("objective_proof"):
            observations.append(f"objective proof: {signals.get('objective_proof_type', '')}")
        if verdict.get("status"):
            observations.append(f"AI verdict round {item.get('round')}: {verdict.get('status')}")

    last = rounds[-1]
    return {
        "tested_payloads": [item.get("payload", "") for item in rounds],
        "last_verdict": last.get("ai_verdict", {}),
        "important_observations": observations[-6:],
        "last_suggested_next_step": last.get("ai_verdict", {}).get("next_step", ""),
    }


def _recommended_next_step(rounds: list[dict]) -> str:
    """Expose the latest AI recommendation clearly for the next round."""
    if not rounds:
        return ""
    return str(rounds[-1].get("ai_verdict", {}).get("next_step", ""))


def _short_rounds(rounds: list[dict]) -> list[dict]:
    output = []
    for item in rounds:
        output.append(
            {
                "round": item.get("round"),
                "payload": item.get("payload"),
                "attack_type": item.get("attack_type"),
                "reason": item.get("reason"),
                "ai_verdict": item.get("ai_verdict", {}),
                "response": _short_response(item.get("response", {})),
            }
        )
    return output


def _short_response(response: dict) -> dict:
    return {
        "status": response.get("status"),
        "url": response.get("url"),
        "content_type": response.get("content_type"),
        "response_length": response.get("response_length"),
        "error": response.get("error"),
        "signals": response.get("signals", {}),
        "response_context": response.get("response_context", {}),
    }


def _signals(round_item: dict) -> dict:
    return round_item.get("response", {}).get("signals", {})
