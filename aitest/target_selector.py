from __future__ import annotations

from typing import List

from fuzztool.inventory_loader import InventoryLoader
from fuzztool.models import FuzzTarget


class AiTestTargetSelector:
    """Chon cac target phu hop de AI kiem thu SQL Injection."""

    SQLI_NAMES = {
        "id",
        "news_id",
        "category_id",
        "user_id",
        "article_id",
        "q",
        "query",
        "keyword",
        "author",
        "sort",
        "search",
    }

    def __init__(self, config: dict) -> None:
        self.config = config

    def select(self, inventory_path: str, max_targets: int) -> List[FuzzTarget]:
        targets = InventoryLoader(self.config).targets_for(inventory_path)
        targets = self._remove_duplicate_targets(targets)
        return self._pick_sqli_targets(targets, max_targets)

    def _remove_duplicate_targets(self, targets: List[FuzzTarget]) -> List[FuzzTarget]:
        seen = set()
        result = []
        for target in targets:
            if target.key in seen:
                continue
            seen.add(target.key)
            result.append(target)
        return result

    def _pick_sqli_targets(self, targets: List[FuzzTarget], limit: int) -> List[FuzzTarget]:
        result = []
        for target in sorted(targets, key=self._sqli_priority):
            if not self._is_sqli_target(target):
                continue
            target.aitest_focus = "sqli"
            result.append(target)
            if len(result) == limit:
                break
        return result

    def _is_sqli_target(self, target: FuzzTarget) -> bool:
        name = target.param_name.lower()
        return target.type_hint in {"int", "float"} or name in self.SQLI_NAMES or name.endswith("_id")

    def _sqli_priority(self, target: FuzzTarget) -> tuple[int, str]:
        """Uu tien tham so so/id truoc vi thuong on dinh hon khi test SQLi."""
        name = target.param_name.lower()
        if target.type_hint in {"int", "float"} or name.endswith("_id") or name == "id":
            return (0, target.key)
        return (1, target.key)
