from __future__ import annotations

from copy import deepcopy
from typing import Dict, Iterable, List

from .http_client import HttpSession
from .normalizer import ReconNormalizer


class AuthManager:
    """Chuẩn bị config/session cho từng auth profile.

    Auth trong recon chỉ để crawler nhìn thấy nội dung sau đăng nhập. Class này
    không test lỗ hổng, chỉ đăng nhập theo cấu hình rồi đưa session cho crawler.
    """

    def __init__(self, config: dict, normalizer: ReconNormalizer | None = None) -> None:
        self.config = config
        self.normalizer = normalizer or ReconNormalizer()

    def enabled_profiles(self) -> List[dict]:
        profiles = self.config.get("auth_profiles")
        if profiles:
            enabled = [profile for profile in profiles if profile.get("enabled", True)]
            return enabled or [self._anonymous_profile()]
        return [self._anonymous_profile()]

    def select_profiles(self, names: list[str]) -> List[dict]:
        profiles = self.enabled_profiles()
        if not names:
            return profiles

        wanted = set(names)
        selected = [profile for profile in profiles if profile.get("name", "anonymous") in wanted]
        found = {profile.get("name", "anonymous") for profile in selected}
        missing = sorted(wanted - found)
        if missing:
            raise ValueError(f"Unknown auth profile: {', '.join(missing)}. Available: {self.profile_names(profiles)}")
        return selected

    def config_for_profile(self, profile: dict) -> dict:
        cloned = deepcopy(self.config)
        cloned["auth_context"] = profile.get("name", "anonymous")
        cloned["_auth_profile"] = profile

        timeout = int(cloned.get("static", {}).get("timeout_seconds", 10))
        headers = dict(cloned.get("headers", {}))
        headers.update(profile.get("headers", {}))
        cloned["headers"] = headers

        session = HttpSession(headers=headers, timeout=timeout)
        if profile.get("type") == "form":
            self.login_with_form(session, cloned, profile)

        cloned["_http_session"] = session
        return cloned

    def login_with_form(self, session: HttpSession, config: dict, profile: dict) -> None:
        login_url = self.normalizer.absolute_url(profile["login_url"], config.get("base_url"))
        method = profile.get("method", "POST").upper()
        data: Dict[str, str] = {str(k): str(v) for k, v in profile.get("data", {}).items()}

        if method == "POST":
            session.post_form(login_url, data)
        else:
            session.get(login_url)

        self._run_success_check(session, config, profile)

    def profile_names(self, profiles: Iterable[dict]) -> str:
        return ", ".join(profile.get("name", "anonymous") for profile in profiles)

    def _run_success_check(self, session: HttpSession, config: dict, profile: dict) -> None:
        success = profile.get("success_check") or {}
        check_url = success.get("url")
        contains = success.get("contains")
        if not check_url or not contains:
            return

        result = session.get(self.normalizer.absolute_url(check_url, config.get("base_url")))
        if contains not in result.text:
            print(f"[!] Auth profile {profile.get('name')} may have failed success_check")

    def _anonymous_profile(self) -> dict:
        return {"name": self.config.get("auth_context", "anonymous"), "type": "none"}


def auth_profiles(config: dict) -> List[dict]:
    return AuthManager(config).enabled_profiles()


def config_for_profile(config: dict, profile: dict) -> dict:
    return AuthManager(config).config_for_profile(profile)


def login_static(session: HttpSession, config: dict, profile: dict) -> None:
    AuthManager(config).login_with_form(session, config, profile)


def profile_names(profiles: Iterable[dict]) -> str:
    return AuthManager({}).profile_names(profiles)
