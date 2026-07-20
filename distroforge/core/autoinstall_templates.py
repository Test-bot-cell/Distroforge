from __future__ import annotations

import json

TEMPLATES: dict[str, dict[str, object]] = {
    "direct": {"storage": {"layout": {"name": "direct"}}},
    "encrypted": {"storage": {"layout": {"name": "direct"}, "swap": {"size": 0}}, "encrypted": True},
    "oem": {"identity": {"username": "ubuntu"}, "oem": {"install": True}},
    "lab": {"packages": ["openssh-server"], "late-commands": ["curtin in-target -- apt-get update"]},
}


def render_template(name: str) -> str:
    return json.dumps(TEMPLATES[name], indent=2)
