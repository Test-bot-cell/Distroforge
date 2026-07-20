from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .brand_identity import BrandIdentity
from .branding import BrandingOptions
from .definition import write_definition
from .profiles import RemixProfile, get_profile
from .project import Project


@dataclass(frozen=True)
class ProfilePlan:
    profile: RemixProfile
    install: tuple[str, ...]
    remove: tuple[str, ...]
    identity: BrandIdentity

    def render_text(self) -> str:
        lines = [
            f"Profile: {self.profile.key}",
            f"Label: {self.profile.label}",
            self.profile.description,
            "",
            "Install:",
            *[f"- {package}" for package in self.install],
            "",
            "Remove:",
            *[f"- {package}" for package in self.remove],
            "",
            "Identity:",
            f"- {self.identity.product_name}",
            f"- {self.identity.vendor}",
            f"- {self.identity.os_id}",
        ]
        return "\n".join(lines) + "\n"

    def definition(self) -> dict[str, object]:
        return {
            "packages": list(self.install),
            "remove_packages": list(self.remove),
            "branding": self.identity.to_branding_options().__dict__,
            "metadata": {
                "profile": self.profile.key,
                "profile_label": self.profile.label,
            },
        }


class DistroProfileService:
    def plan(self, project: Project, key: str, branding: BrandingOptions | None = None) -> ProfilePlan:
        profile = get_profile(key)
        options = branding or BrandingOptions(name=project.name)
        identity = BrandIdentity.from_project_options(project, options)
        return ProfilePlan(
            profile=profile,
            install=profile.install,
            remove=profile.remove,
            identity=identity,
        )

    def write_definition(
        self,
        project: Project,
        key: str,
        target: Path,
        branding: BrandingOptions | None = None,
    ) -> ProfilePlan:
        plan = self.plan(project, key, branding)
        write_definition(plan.definition(), target)
        return plan

    def render_json(self, project: Project, key: str, branding: BrandingOptions | None = None) -> str:
        return json.dumps(self.plan(project, key, branding).definition(), indent=2) + "\n"
