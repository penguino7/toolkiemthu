from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from .models import EndpointRecord


class ReconExporter:
    """Xuất kết quả recon ra file.

    Tách exporter thành class để CLI chỉ cần gọi `export_all`, không phải biết
    chi tiết cách tạo JSON/Markdown.
    """

    def ensure_dir(self, path: str | Path) -> Path:
        output = Path(path)
        output.mkdir(parents=True, exist_ok=True)
        return output

    def export_all(self, records: List[EndpointRecord], output_dir: str | Path) -> None:
        output = self.ensure_dir(output_dir)
        self.export_json(records, output / "inventory.json")
        self.export_markdown(records, output / "inventory.md")
        self.export_params(records, output / "params.txt")
        self.export_test_plan(records, output / "test_plan.md")

    def export_json(self, records: Iterable[EndpointRecord], output_path: str | Path) -> None:
        data = [record.to_dict() for record in records]
        Path(output_path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def export_markdown(self, records: List[EndpointRecord], output_path: str | Path) -> None:
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
            lines.append(self._endpoint_table_row(record))

        lines.extend(["", "## Chi Tiết", ""])
        for index, record in enumerate(records, start=1):
            self._append_record_detail(lines, index, record)

        Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def export_params(self, records: Iterable[EndpointRecord], output_path: str | Path) -> None:
        lines = []
        for record in records:
            for param in sorted(record.params.values(), key=lambda p: p.key):
                lines.append(f"{record.method} {record.canonical_path} {param.location}:{param.name} {param.type_hint}")
        Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def export_test_plan(self, records: List[EndpointRecord], output_path: str | Path) -> None:
        groups = self._group_test_candidates(records)
        lines = ["# Recon Test Plan", ""]

        for title, items in groups.items():
            lines.extend([f"## {title}", ""])
            if not items:
                lines.extend(["Không có candidate.", ""])
                continue
            for record in items:
                self._append_test_plan_record(lines, record)

        Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _endpoint_table_row(self, record: EndpointRecord) -> str:
        params = ", ".join(f"{p.location}:{p.name}" for p in record.params.values()) or "-"
        return "| {method} | `{path}` | {params} | {auth} | {status} | {ctype} | {tests} | {sources} |".format(
            method=record.method,
            path=self._md_escape(record.canonical_path),
            params=self._md_escape(params),
            auth=self._md_escape(record.auth_context),
            status=self._md_escape(",".join(str(s) for s in record.statuses) or "-"),
            ctype=self._md_escape(record.response_content_type or "-"),
            tests=self._md_escape(", ".join(record.candidate_tests) or "-"),
            sources=self._md_escape(", ".join(record.source_tools) or "-"),
        )

    def _append_record_detail(self, lines: List[str], index: int, record: EndpointRecord) -> None:
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
        self._append_param_detail(lines, record)
        self._append_form_detail(lines, record)
        self._append_evidence_detail(lines, record)

    def _append_param_detail(self, lines: List[str], record: EndpointRecord) -> None:
        if not record.params:
            return
        lines.extend(["Params:", ""])
        for param in sorted(record.params.values(), key=lambda p: p.key):
            sample = ", ".join(param.sample_values[:3]) or "-"
            reflected = "yes" if param.reflected else "no"
            tests = ", ".join(param.candidate_tests) or "-"
            lines.append(
                f"- `{param.location}:{param.name}` type=`{param.type_hint}` "
                f"reflected=`{reflected}` samples=`{self._md_escape(sample)}` tests=`{tests}`"
            )
        lines.append("")

    def _append_form_detail(self, lines: List[str], record: EndpointRecord) -> None:
        if not record.forms:
            return
        lines.extend(["Forms:", ""])
        for form in record.forms:
            lines.append(f"- `{form.get('method', 'GET')}` `{form.get('action', '')}` inputs={form.get('inputs', [])}")
        lines.append("")

    def _append_evidence_detail(self, lines: List[str], record: EndpointRecord) -> None:
        if not record.evidence:
            return
        lines.extend(["Evidence:", ""])
        for key, value in record.evidence.items():
            lines.append(f"- `{key}`: `{value}`")
        lines.append("")

    def _group_test_candidates(self, records: List[EndpointRecord]) -> dict[str, List[EndpointRecord]]:
        groups = {
            "SQLi": [],
            "Reflected XSS": [],
            "Stored XSS": [],
            "API/DOM XSS Source": [],
            "Forms": [],
        }
        for record in records:
            tests = set(record.candidate_tests)
            if any(test.startswith("sqli") or test == "sqli_error_evidence" for test in tests):
                groups["SQLi"].append(record)
            if "reflected_xss_candidate" in tests or "reflection_detected" in tests:
                groups["Reflected XSS"].append(record)
            if "stored_xss_candidate" in tests:
                groups["Stored XSS"].append(record)
            if "api_xss_source" in tests:
                groups["API/DOM XSS Source"].append(record)
            if "form_endpoint" in tests:
                groups["Forms"].append(record)
        return groups

    def _append_test_plan_record(self, lines: List[str], record: EndpointRecord) -> None:
        params = ", ".join(f"{p.location}:{p.name}" for p in record.params.values()) or "-"
        lines.extend(
            [
                f"### {record.method} {record.canonical_path}",
                "",
                f"- URL mẫu: `{record.examples[0] if record.examples else record.url}`",
                f"- Auth: `{record.auth_context}`",
                f"- Params: `{params}`",
                f"- Candidate tests: `{', '.join(record.candidate_tests)}`",
                "",
            ]
        )
        for param in sorted(record.params.values(), key=lambda p: p.key):
            if param.candidate_tests:
                lines.append(f"- Test `{param.location}:{param.name}` với `{', '.join(param.candidate_tests)}`")
        lines.append("")

    def _md_escape(self, value) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ")


def ensure_dir(path: str | Path) -> Path:
    return ReconExporter().ensure_dir(path)


def export_json(records: Iterable[EndpointRecord], output_path: str | Path) -> None:
    ReconExporter().export_json(records, output_path)


def export_markdown(records: List[EndpointRecord], output_path: str | Path) -> None:
    ReconExporter().export_markdown(records, output_path)


def export_params(records: Iterable[EndpointRecord], output_path: str | Path) -> None:
    ReconExporter().export_params(records, output_path)


def export_test_plan(records: List[EndpointRecord], output_path: str | Path) -> None:
    ReconExporter().export_test_plan(records, output_path)


def export_all(records: List[EndpointRecord], output_dir: str | Path) -> None:
    ReconExporter().export_all(records, output_dir)
