from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class RecipeRequest:
    text: str


class RecipeAdvisor:
    def suggest_definition(self, request: RecipeRequest) -> dict[str, object]:
        text = request.text.lower()
        desktop = "ubuntu_minimal"
        if "unity" in text:
            desktop = "unity"
        elif "xfce" in text or "vieux pc" in text or "light" in text:
            desktop = "xubuntu"
        packages = ["htop"]
        if "dev" in text or "python" in text:
            packages.extend(["git", "python3-venv", "build-essential"])
        french = "fr" in text or "francais" in text or "français" in text
        return {
            "source_mode": "bootstrap"
            if "from scratch" in text or "minimal" in text
            else "iso",
            "packages": sorted(set(packages)),
            "customization": {
                "desktop": desktop,
                "autologin_user": "ubuntu" if "autologin" in text else None,
                "locale": "fr_FR.UTF-8" if french else None,
                "timezone": "Europe/Paris" if french or "paris" in text else None,
            },
            "sanitize": {"apt_lists": True},
            "qa": {"scenarios": ["live-bios"]},
        }

    def render_json(self, text: str) -> str:
        return json.dumps(self.suggest_definition(RecipeRequest(text)), indent=2)
