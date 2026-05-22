from __future__ import annotations

import json
from pathlib import Path
from typing import List


class AiTestReporter:
    """Ghi session AI iterative ra JSON và Markdown riêng."""

    def export(self, sessions: List[dict], output_dir: str | Path) -> None:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        self.export_json(sessions, output / "sessions.json")
        self.export_markdown(sessions, output / "sessions.md")

    def export_json(self, sessions: List[dict], path: str | Path) -> None:
        Path(path).write_text(json.dumps(sessions, indent=2, ensure_ascii=False), encoding="utf-8")

    def export_markdown(self, sessions: List[dict], path: str | Path) -> None:
        lines = ["# AI Iterative Test Sessions", "", f"Tổng session: **{len(sessions)}**", ""]

        for index, session in enumerate(sessions, start=1):
            target = session.get("target", {})
            lines.extend(
                [
                    f"## {index}. {target.get('method')} {target.get('path')} `{target.get('location')}:{target.get('param')}`",
                    "",
                    f"- Marker: `{session.get('marker')}`",
                    f"- Confirmed signals: `{session.get('confirmed_signals')}`",
                    "",
                ]
            )

            for item in session.get("rounds", []):
                lines.extend(
                    [
                        f"### Round {item.get('round')}",
                        "",
                        f"- Payload: `{item.get('payload', '-')}`",
                        f"- Attack type: `{item.get('attack_type', '-')}`",
                        f"- Guard: `{item.get('guard', '-')}`",
                        f"- Status: `{item.get('response', {}).get('status', '-')}`",
                        f"- Signals: `{item.get('response', {}).get('signals', {})}`",
                        f"- AI reason: {item.get('reason', '-')}",
                        "",
                    ]
                )

        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
