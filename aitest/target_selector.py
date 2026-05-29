from __future__ import annotations

from typing import List

from fuzztool.inventory_loader import InventoryLoader
from fuzztool.models import FuzzTarget


class AiTestTargetSelector:
    """Chon nhanh 3 target SQLi va 3 target XSS tu inventory."""

    SQLI_NAMES = {"id", "news_id", "category_id", "user_id", "article_id"}
    XSS_NAMES = {"q", "keyword", "search", "content", "comment", "author_name", "username", "bio"}

    def __init__(self, config: dict) -> None:
        self.config = config

    def select(self, inventory_path: str, max_targets: int) -> List[FuzzTarget]:
        targets = InventoryLoader(self.config).targets_for(inventory_path)
        targets = self._remove_duplicate_targets(targets)

        sqli_targets = self._pick_targets(targets, focus="sqli", limit=3)
        xss_targets = self._pick_targets(targets, focus="xss", limit=3)

        selected = [*sqli_targets, *xss_targets]
        return selected[:max_targets]

    def _remove_duplicate_targets(self, targets: List[FuzzTarget]) -> List[FuzzTarget]:
        seen = set()
        result = []
        for target in targets:
            if target.key in seen:
                continue
            seen.add(target.key)
            result.append(target)
        return result

    def _pick_targets(self, targets: List[FuzzTarget], focus: str, limit: int) -> List[FuzzTarget]:
        result = []
        for target in targets:
            if focus == "sqli" and not self._is_sqli_target(target):
                continue
            if focus == "xss" and not self._is_xss_target(target):
                continue

            target.aitest_focus = focus
            result.append(target)

            if len(result) == limit:
                break

        return result

    def _is_sqli_target(self, target: FuzzTarget) -> bool:
        name = target.param_name.lower()
        return target.type_hint in {"int", "float"} or name in self.SQLI_NAMES or name.endswith("_id")

    def _is_xss_target(self, target: FuzzTarget) -> bool:
        name = target.param_name.lower()
        return target.type_hint == "string" and name in self.XSS_NAMES
