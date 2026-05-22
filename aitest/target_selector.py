from __future__ import annotations

from typing import List

from fuzztool.inventory_loader import InventoryLoader
from fuzztool.models import FuzzTarget


class AiTestTargetSelector:
    """Chọn một số target nhỏ từ inventory để AI test nhiều vòng."""

    def __init__(self, config: dict) -> None:
        self.config = config

    def select(self, inventory_path: str, max_targets: int, include_post: bool = False) -> List[FuzzTarget]:
        targets = InventoryLoader(self.config).targets_for(inventory_path, {"xss", "sqli"})
        if not include_post:
            targets = [target for target in targets if target.param_location == "query"]

        unique_targets = self._dedupe_targets(targets)
        return sorted(unique_targets, key=self._priority)[:max_targets]

    def _dedupe_targets(self, targets: List[FuzzTarget]) -> List[FuzzTarget]:
        seen = set()
        result = []
        for target in targets:
            if target.key in seen:
                continue
            seen.add(target.key)
            result.append(target)
        return result

    def _priority(self, target: FuzzTarget) -> tuple[int, int, int, str]:
        name = target.param_name.lower()
        tests = set(target.candidate_tests)
        sqli_first = 0 if any(test.startswith("sqli") for test in tests) else 1
        id_like = 0 if name == "id" or name.endswith("_id") else 1
        query_first = 0 if target.param_location == "query" else 1
        return sqli_first, id_like, query_first, target.key
