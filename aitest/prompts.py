from __future__ import annotations

import json

from fuzztool.models import FuzzTarget


def build_payload_prompt(target: FuzzTarget, marker: str, baseline: dict, previous_rounds: list[dict]) -> str:
    """Prompt de AI sinh payload tiep theo."""
    data = {
        "task": "next_payload",
        "role": "Ban la AI ho tro test XSS/SQLi trong lab duoc phep kiem thu.",
        "goal": "Doc ngu canh response va chon dung 1 payload tiep theo phu hop voi nhung gi da quan sat.",
        "rules": [
            "Chi tra ve JSON hop le, khong markdown.",
            "Chi kiem thu XSS va SQL injection.",
            "Khong dung payload pha hoai du lieu/he thong: DROP, DELETE, UPDATE, INSERT, OUTFILE, LOAD_FILE, RCE.",
            "Moi vong chi sinh 1 payload ngan, ro muc dich, phu hop voi param.",
            "Payload phai dua tren baseline, previous_rounds, response_context va ai_verdict truoc do.",
            "Neu target.test_focus la sqli, uu tien SQLi. Neu la xss, uu tien XSS va khong chuyen sang ORDER BY/UNION neu chua co SQL signal ro.",
            "Khong chay theo thu tu co dinh. Hay chon quote, boolean, ORDER BY, UNION hoac XSS tuy theo response vua thay.",
            "Khong dung SQL error don le lam ket luan thanh cong.",
            "Neu test UNION, payload nen dung marker theo tung cot: MARKER_C01, MARKER_C02...",
            "Khong lap lai payload da thu trong previous_rounds.",
            "Doc response_context.html_text neu mode la html_text. Neu co raw_response thi doc raw_response; neu khong thi doc signal_windows, raw_head va raw_tail.",
        ],
        "strategy_options": [
            "Neu response binh thuong va chua co signal, co the thu payload nhe de probe SQLi hoac XSS.",
            "Neu co SQL error, co the thu boolean, ORDER BY, UNION hoac payload khac tuy noi dung loi.",
            "Neu marker chi nam trong debug/sql/request/echo param, hay tim cach tao bang chung trong data/html that.",
            "Neu XSS marker reflect trong HTML, co the thu payload co kha nang kich hoat browser alert.",
            "Neu da du bang chung hoac khong con huong test an toan, tra stop=true.",
        ],
        "expected_json": {
            "payload": "string",
            "attack_type": "sqli_error|sqli_order_by|sqli_union|xss_reflection|stop",
            "reason": "ly do ngan gon vi sao chon payload nay",
            "expected_signal": "dau hieu mong doi trong response",
            "stop": False,
        },
        "marker": marker,
        "target": _target_dict(target),
        "current_state": _state_summary(previous_rounds),
        "session_memory": _session_memory(previous_rounds),
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
    """Prompt de AI doc evidence va dua verdict rieng."""
    data = {
        "task": "evidence_verdict",
        "role": "Ban la AI review bang chung XSS/SQLi trong lab duoc phep kiem thu.",
        "goal": "Doc response that va ket luan payload vua gui la no_issue, suspicious hay confirmed.",
        "important": [
            "signals la goi y do tool trich xuat, khong phai ket luan bat buoc.",
            "Hay tu doc response_context/html_text/raw_response/signal_windows de dua verdict.",
            "SQL error don le chi la suspicious, khong phai confirmed.",
            "XSS confirmed khi co bang chung alert/dialog hoac browser execution.",
            "SQLi confirmed khi marker/UNION column hien trong data/html that, khong chi nam trong sql/debug/request/echo param.",
            "Neu chua du bang chung thi tra suspicious va de xuat next_step.",
        ],
        "expected_json": {
            "status": "no_issue|suspicious|confirmed",
            "vuln_type": "none|sqli|xss",
            "confidence": "low|medium|high",
            "reason": "giai thich ngan gon bang chung nao du/khong du",
            "next_step": "nen thu tiep payload/huong nao neu chua confirmed",
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
