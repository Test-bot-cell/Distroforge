from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .build import BuildOptions
from .host_artifacts import write_host_artifact
from .project import Project


@dataclass(frozen=True)
class RecipeExport:
    data: dict[str, Any]

    def write(self, target: Path) -> None:
        write_host_artifact(target, json.dumps(self.data, indent=2), "Write recipe export")


def export_recipe(project: Project, options: BuildOptions | None = None) -> RecipeExport:
    data: dict[str, Any] = {
        "name": project.name,
        "release": project.release.version,
        "source_mode": project.source_mode,
        "source_iso": str(project.source_iso) if project.source_iso else None,
        "packages": list(project.packages),
        "remove_packages": list(project.remove_packages),
        "repositories": list(project.repositories),
        "customization": project.customization.to_dict(),
    }
    if options:
        data["build"] = {
            "preview": options.run_preview,
            "synaptic": options.run_synaptic,
            "sanitize": {
                "enabled": options.sanitize.enabled,
                "apt_lists": options.sanitize.apt_lists,
                "ssh_host_keys": options.sanitize.ssh_host_keys,
                "package_autoremove": options.sanitize.package_autoremove,
            },
            "release_track": {
                "mode": options.release_track.mode,
                "devel_suite": options.release_track.devel_suite,
                "backports": options.release_track.enable_backports,
                "proposed": options.release_track.enable_proposed,
            },
            "apt_cache": {
                "enabled": options.apt_cache.enabled,
                "cache_dir": str(options.apt_cache.cache_dir) if options.apt_cache.cache_dir else None,
                "proxy_url": options.apt_cache.proxy_url,
            },
        }
    return RecipeExport(data)


def load_recipe(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
