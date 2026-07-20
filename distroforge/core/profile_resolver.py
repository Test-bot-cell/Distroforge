from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .profile_validation import load_profile_resolver_spec
from .profiles import get_profile
from .project import Project


@dataclass(frozen=True)
class ProfileLayer:
    name: str
    priority: str
    install: tuple[str, ...]
    remove: tuple[str, ...]


@dataclass(frozen=True)
class ProfileResolution:
    project: Path
    layers: tuple[ProfileLayer, ...]
    install: tuple[str, ...]
    remove: tuple[str, ...]
    conflicts: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "distroforge.profile-resolution.v1",
            "project": str(self.project),
            "priority": [layer.priority for layer in self.layers],
            "layers": [
                {
                    "name": layer.name,
                    "priority": layer.priority,
                    "install": list(layer.install),
                    "remove": list(layer.remove),
                }
                for layer in self.layers
            ],
            "resolved": {
                "install": list(self.install),
                "remove": list(self.remove),
                "packages": list(self.install),
                "remove_packages": list(self.remove),
            },
            "conflicts": list(self.conflicts),
            "build_contract": _build_contract(
                layers=[layer.name for layer in self.layers],
                install=tuple(self.install),
                remove=tuple(self.remove),
                conflicts=tuple(self.conflicts),
            ),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    def priority_chain(self) -> list[str]:
        return [layer.priority for layer in self.layers]

    def profile_name(self) -> str:
        for layer in self.layers[1:]:
            if layer.priority.startswith("10-base"):
                return layer.name
        return "project"

    def layer_names(self) -> list[str]:
        return [layer.name for layer in self.layers]

    def render_text(self) -> str:
        lines = [
            "Resolved DistroForge profile",
            f"Project: {self.project}",
            "",
            "Layer priority:",
            *[f"- {layer.priority}: {layer.name}" for layer in self.layers],
            "",
            "Install:",
            *([f"- {package}" for package in self.install] or ["- none"]),
            "",
            "Remove:",
            *([f"- {package}" for package in self.remove] or ["- none"]),
            "",
            "Conflicts:",
            *([f"- {package}" for package in self.conflicts] or ["- none"]),
        ]
        return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class ProfileComparison:
    left: ProfileResolution
    right: ProfileResolution | None
    schema: str = "distroforge.profile-diff.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "project": str(self.left.project),
            "left": {
                "profile": self.left_profile_name(),
                "priority": self.left.priority_chain(),
                "resolution": self.left.to_dict()["resolved"],
                "conflicts": self.left.conflicts,
                "replay_command": _replay_command(self.left),
            },
            "right": self._right_payload(),
            "compare": {
                "install_only_in_left": list(_diff_packages(self.left.install, self.right.install if self.right else ())),
                "install_only_in_right": list(_diff_packages(self.right.install if self.right else (), self.left.install)),
                "remove_only_in_left": list(_diff_packages(self.left.remove, self.right.remove if self.right else ())),
                "remove_only_in_right": list(_diff_packages(self.right.remove if self.right else (), self.left.remove)),
            },
            "build_contract": _build_contract(
                layers=[layer.name for layer in self.left.layers],
                install=self.left.install,
                remove=self.left.remove,
                conflicts=self.left.conflicts,
                target=self.left_target_label(),
            ),
            "replay": self._replay_payload(),
        }

    def left_profile_name(self) -> str:
        return self.left.profile_name()

    def left_target_label(self) -> str:
        if self.right is None:
            return self.left_profile_name()
        return self.right.profile_name()

    def right_profile_name(self) -> str:
        if not self.right:
            return "project"
        return self.right.profile_name()

    def _right_payload(self) -> dict[str, object] | None:
        if self.right is None:
            return None
        return {
            "profile": self.right_profile_name(),
            "priority": self.right.priority_chain(),
            "resolution": self.right.to_dict()["resolved"],
            "conflicts": self.right.conflicts,
            "replay_command": _replay_command(self.right),
        }

    def _replay_payload(self) -> dict[str, object]:
        payload = {
            "left_command": _replay_command(self.left),
            "left_target": self.left_profile_name(),
        }
        if self.right:
            payload.update(
                {
                    "right_command": _replay_command(self.right),
                    "right_target": self.right_profile_name(),
                }
            )
        return payload

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    def render_text(self) -> str:
        lines = [
            "Profile comparison",
            f"Project: {self.left.project}",
            f"Left: {self.left_profile_name()}",
            f"Right: {self.right_profile_name()}",
            "",
            "Install only in left:",
            *([f"- {package}" for package in _diff_packages(self.left.install, self.right.install if self.right else ())] or ["- none"]),
            "",
            "Install only in right:",
            *([f"- {package}" for package in _diff_packages(self.right.install if self.right else (), self.left.install)] or ["- none"]),
            "",
            "Remove only in left:",
            *([f"- {package}" for package in _diff_packages(self.left.remove, self.right.remove if self.right else ())] or ["- none"]),
            "",
            "Remove only in right:",
            *([f"- {package}" for package in _diff_packages(self.right.remove if self.right else (), self.left.remove)] or ["- none"]),
            "",
            "Priority chain (left):",
            *[f"- {layer.priority}: {layer.name}" for layer in self.left.layers],
        ]
        if self.right is not None:
            lines.extend(["", "Priority chain (right):"])
            lines.extend(f"- {layer.priority}: {layer.name}" for layer in self.right.layers)
        return "\n".join(lines) + "\n"


def resolve_profiles(
    project: Project,
    *,
    base: str | None = None,
    layers: list[str] | None = None,
    overrides: list[str] | None = None,
    config: Path | None = None,
) -> ProfileResolution:
    spec = load_profile_resolver_spec(config) if config else {}
    resolved_base = base or _optional_str(spec.get("base"))
    resolved_layers = list(spec.get("layers", [])) if isinstance(spec.get("layers", []), list) else []
    resolved_layers.extend(layers or [])
    resolved_overrides = list(spec.get("overrides", [])) if isinstance(spec.get("overrides", []), list) else []
    resolved_overrides.extend(overrides or [])

    composed_layers: list[ProfileLayer] = [
        _profile_layer("project", project.packages, project.remove_packages, "00-project")
    ]
    if resolved_base:
        composed_layers.append(_profile_layer(resolved_base, get_profile(resolved_base).install, get_profile(resolved_base).remove, "10-base"))
    for index, layer in enumerate(resolved_layers, start=1):
        composed_layers.append(_profile_layer(layer, _profile_sequence(layer).install, _profile_sequence(layer).remove, f"20-layer-{index:02d}"))
    for index, override in enumerate(resolved_overrides, start=1):
        composed_layers.append(_profile_layer(override, _profile_sequence(override).install, _profile_sequence(override).remove, f"30-override-{index:02d}"))

    install, remove, conflicts = _merge_layers(composed_layers)
    return ProfileResolution(
        project=project.root,
        layers=tuple(composed_layers),
        install=tuple(install),
        remove=tuple(remove),
        conflicts=tuple(conflicts),
    )


def diff_profiles(
    project: Project,
    left: str,
    right: str | None,
    *,
    config: Path | None = None,
    layers: list[str] | None = None,
    overrides: list[str] | None = None,
    right_base: str | None = None,
    right_config: Path | None = None,
    right_layers: list[str] | None = None,
    right_overrides: list[str] | None = None,
) -> ProfileComparison:
    left_resolution = resolve_profiles(
        project,
        base=left,
        layers=layers,
        overrides=overrides,
        config=config,
    )
    right_resolution = resolve_profiles(
        project,
        base=right_base if right_base is not None else right,
        layers=right_layers,
        overrides=right_overrides,
        config=right_config,
    )
    return ProfileComparison(left=left_resolution, right=right_resolution)


def resolve_profile_show(profile: str) -> str:
    loaded = get_profile(profile)
    return json.dumps(
        {
            "schema": "distroforge.profile-definition.v1",
            "profile": loaded.key,
            "label": loaded.label,
            "description": loaded.description,
            "package_plan": {
                "install": list(loaded.install),
                "remove": list(loaded.remove),
            },
            "install": list(loaded.install),
            "remove": list(loaded.remove),
            "priority": ["10-profile"],
        },
        indent=2,
    ) + "\n"


def render_profile_show(profile: str, *, json_output: bool = False) -> str:
    loaded = get_profile(profile)
    payload = {
        "profile": loaded.key,
        "schema": "distroforge.profile-definition.v1",
        "label": loaded.label,
        "description": loaded.description,
        "install": list(loaded.install),
        "remove": list(loaded.remove),
        "layer": {
            "name": loaded.key,
            "priority": "project-lookup",
            "install": list(loaded.install),
            "remove": list(loaded.remove),
        },
    }
    if json_output:
        return json.dumps(payload, indent=2) + "\n"
    lines = [
        f"Profile: {loaded.key}",
        f"Label: {loaded.label}",
        loaded.description,
        "",
        "Install:",
        *([f"- {package}" for package in loaded.install] or ["- none"]),
        "",
        "Remove:",
        *([f"- {package}" for package in loaded.remove] or ["- none"]),
        "",
        "Priority layer:",
        "- 00-project (project metadata)",
        f"- 10-profile {loaded.key}",
    ]
    return "\n".join(lines) + "\n"


def _profile_sequence(name: str):
    return get_profile(name)


def _profile_layer(profile_name: str, install: tuple[str, ...] | None = None, remove: tuple[str, ...] | None = None, priority: str = "10-profile") -> ProfileLayer:
    if install is not None and remove is not None:
        return ProfileLayer(profile_name, priority, install, remove)
    profile = get_profile(profile_name)
    return ProfileLayer(profile.key, priority, profile.install, profile.remove)


def _merge_layers(layers: list[ProfileLayer]) -> tuple[list[str], list[str], list[str]]:
    install: list[str] = []
    remove: list[str] = []
    conflicts: list[str] = []
    for layer in layers:
        for package in layer.install:
            if package in remove:
                remove.remove(package)
                conflicts.append(f"{package}: reinstalled by {layer.priority}")
            if package not in install:
                install.append(package)
        for package in layer.remove:
            if package in install:
                install.remove(package)
                conflicts.append(f"{package}: removed by {layer.priority} after earlier install")
            if package not in remove:
                remove.append(package)
    return install, remove, conflicts


def _build_contract(
    *,
    layers: list[str],
    install: tuple[str, ...],
    remove: tuple[str, ...],
    conflicts: tuple[str, ...],
    target: str = "",
) -> dict[str, object]:
    return {
        "kind": "distroforge-profile-resolution",
        "version": 2,
        "inputs": ["project", "profile layers"],
        "outputs": ["resolved packages", "resolved removals", "conflicts"],
        "replayable": True,
        "priority_chain": layers,
        "target": target,
        "package_count": len(install),
        "remove_count": len(remove),
        "conflict_count": len(conflicts),
    }


def _diff_packages(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
    right_set = set(right)
    return tuple(package for package in left if package not in right_set)


def _optional_str(value: object) -> str | None:
    return str(value) if value else None


def _replay_command(resolution: ProfileResolution | None) -> str | None:
    if resolution is None:
        return None
    base = resolution.base_profile_name()
    layers = [layer.name for layer in resolution.layers if layer.priority.startswith("20-layer")]
    overrides = [layer.name for layer in resolution.layers if layer.priority.startswith("30-override")]
    args = [
        "distroforge",
        "profile",
        "resolve",
        str(resolution.project),
        "--json",
    ]
    if base != "project":
        args.extend(["--base", base])
    for layer in layers:
        args.extend(["--layer", layer])
    for override in overrides:
        args.extend(["--override", override])
    return " ".join(args)


def _base_profile_name(resolution: ProfileResolution) -> str:
    for layer in resolution.layers:
        if layer.priority.startswith("10-base"):
            return layer.name
    return "project"


ProfileResolution.base_profile_name = _base_profile_name  # type: ignore[attr-defined]
