from __future__ import annotations

import json
from pathlib import Path
from typing import List


class AiTestReporter:
    """Ghi session AI iterative ra JSON ngan gon, de doc."""

    def export(self, sessions: List[dict], output_dir: str | Path) -> None:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        self.export_json(self._compact_sessions(sessions), output / "sessions.json")

    def export_json(self, sessions: List[dict], path: str | Path) -> None:
        Path(path).write_text(json.dumps(sessions, indent=2, ensure_ascii=False), encoding="utf-8")

    def _compact_sessions(self, sessions: List[dict]) -> List[dict]:
        return [self._compact_session(session) for session in sessions]

    def _compact_session(self, session: dict) -> dict:
        if session.get("error"):
            return {
                "target": session.get("target", {}),
                "error": session.get("error", ""),
            }

        return {
            "target": session.get("target", {}),
            "marker": session.get("marker", ""),
            "baseline": self._compact_response(session.get("baseline", {})),
            "rounds": [self._compact_round(item) for item in session.get("rounds", [])],
            "proofs": self._compact_proofs(session.get("objective_proofs", [])),
        }

    def _compact_round(self, item: dict) -> dict:
        if item.get("stopped_by_ai"):
            return {
                "round": item.get("round"),
                "attack": "stop",
                "reason": item.get("reason", ""),
            }

        response = item.get("response", {})
        verdict = item.get("ai_verdict", {})
        return {
            "round": item.get("round"),
            "attack": item.get("attack_type", ""),
            "payload": item.get("payload", ""),
            "reason": item.get("reason", ""),
            "response": self._compact_response(response),
            "signal": self._signal_summary(response.get("signals", {})),
            "verdict": self._compact_verdict(verdict),
        }

    def _compact_response(self, response: dict) -> dict:
        return {
            "status": response.get("status"),
            "url": response.get("url"),
            "time": response.get("elapsed_seconds"),
            "length": response.get("response_length"),
            "error": response.get("error"),
        }

    def _signal_summary(self, signals: dict) -> dict:
        return {
            key: value
            for key, value in {
                "sql_error": signals.get("sql_error_confirmed"),
                "sql_patterns": signals.get("sql_error_patterns"),
                "xss_reflection": signals.get("xss_reflection"),
                "xss_executed": signals.get("xss_executed"),
                "union_marker": signals.get("union_marker_in_output"),
                "visible_columns": signals.get("visible_columns"),
                "objective_proof": signals.get("objective_proof"),
                "proof_type": signals.get("objective_proof_type"),
            }.items()
            if value
        }

    def _compact_verdict(self, verdict: dict) -> dict:
        return {
            key: value
            for key, value in {
                "source": verdict.get("source"),
                "status": verdict.get("status"),
                "type": verdict.get("vuln_type"),
                "confidence": verdict.get("confidence"),
                "reason": verdict.get("reason"),
                "next": verdict.get("next_step"),
            }.items()
            if value
        }

    def _compact_proofs(self, proofs: list[dict]) -> list[dict]:
        output = []
        for proof in proofs:
            output.append(
                {
                    "round": proof.get("round"),
                    "attack": proof.get("attack_type"),
                    "proof_type": proof.get("proof_type"),
                    "signal": self._signal_summary(proof.get("signals", {})),
                    "verdict": self._compact_verdict(proof.get("ai_verdict", {})),
                }
            )
        return output
