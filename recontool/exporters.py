from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from .models import EndpointRecord


def ensure_dir(path: str | Path) -> Path:
    output = Path(path)
    output.mkdir(parents=True, exist_ok=True)
    return output


def export_json(records: Iterable[EndpointRecord], output_path: str | Path) -> None:
    data = [record.to_dict() for record in records]
    Path(output_path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _md_escape(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def export_markdown(records: List[EndpointRecord], output_path: str | Path) -> None:
    lines = [
        "# Recon Inventory",
        "",
        f"Tổng endpoint sau dedupe: **{len(records)}**",
        "",
        "## Bảng Endpoint",
        "",
        "| Method | Path | Params | Auth | Status | Content-Type | Candidate Tests | Sources |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for record in records:
        params = ", ".join(f"{p.location}:{p.name}" for p in record.params.values()) or "-"
        lines.append(
            "| {method} | `{path}` | {params} | {auth} | {status} | {ctype} | {tests} | {sources} |".format(
                method=record.method,
                path=_md_escape(record.canonical_path),
                params=_md_escape(params),
                auth=_md_escape(record.auth_context),
                status=_md_escape(",".join(str(s) for s in record.statuses) or "-"),
                ctype=_md_escape(record.response_content_type or "-"),
                tests=_md_escape(", ".join(record.candidate_tests) or "-"),
                sources=_md_escape(", ".join(record.source_tools) or "-"),
            )
        )

    lines.extend(["", "## Chi Tiết", ""])
    for index, record in enumerate(records, start=1):
        lines.extend(
            [
                f"### {index}. {record.method} {record.canonical_path}",
                "",
                f"- URL mẫu: `{record.examples[0] if record.examples else record.url}`",
                f"- Auth context: `{record.auth_context}`",
                f"- Số lần thấy: `{record.seen_count}`",
                f"- Nguồn phát hiện: `{', '.join(record.source_tools)}`",
                f"- Candidate tests: `{', '.join(record.candidate_tests) or '-'}`",
                "",
            ]
        )
        if record.params:
            lines.extend(["Params:", ""])
            for param in sorted(record.params.values(), key=lambda p: p.key):
                sample = ", ".join(param.sample_values[:3]) or "-"
                reflected = "yes" if param.reflected else "no"
                tests = ", ".join(param.candidate_tests) or "-"
                lines.append(
                    f"- `{param.location}:{param.name}` type=`{param.type_hint}` reflected=`{reflected}` samples=`{_md_escape(sample)}` tests=`{tests}`"
                )
            lines.append("")
        if record.forms:
            lines.extend(["Forms:", ""])
            for form in record.forms:
                lines.append(f"- `{form.get('method', 'GET')}` `{form.get('action', '')}` inputs={form.get('inputs', [])}")
            lines.append("")
        if record.evidence:
            lines.extend(["Evidence:", ""])
            for key, value in record.evidence.items():
                lines.append(f"- `{key}`: `{value}`")
            lines.append("")

    Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def export_params(records: Iterable[EndpointRecord], output_path: str | Path) -> None:
    lines = []
    for record in records:
        for param in sorted(record.params.values(), key=lambda p: p.key):
            lines.append(f"{record.method} {record.canonical_path} {param.location}:{param.name} {param.type_hint}")
    Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def export_all(records: List[EndpointRecord], output_dir: str | Path) -> None:
    output = ensure_dir(output_dir)
    export_json(records, output / "inventory.json")
    export_markdown(records, output / "inventory.md")
    export_params(records, output / "params.txt")
