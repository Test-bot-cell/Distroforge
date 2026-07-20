from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .command import CommandRunner
from .host_artifacts import HostArtifactWriter
from .project import Project

SBOM_FORMATS: tuple[str, ...] = ("native", "spdx", "cyclonedx")
SPDX_FILENAME = "distroforge-sbom.spdx.json"
CYCLONEDX_FILENAME = "distroforge-sbom.cdx.json"


@dataclass
class ProvenanceOptions:
    enabled: bool = True
    include_commands: bool = True
    sbom_format: str = "native"


class ProvenanceService:
    def __init__(self, runner: CommandRunner, project: Project, options: ProvenanceOptions) -> None:
        self.runner = runner
        self.project = project
        self.options = options

    def write(self, output_iso: Path | None = None, packages: Iterable[str] | None = None) -> None:
        if not self.options.enabled:
            return
        pkgset = self._package_set(packages)
        targets: list[tuple[Path, object]] = [
            (self.project.output_dir / "distroforge-provenance.json", self.payload(output_iso))
        ]
        sbom_format = self.options.sbom_format if self.options.sbom_format in SBOM_FORMATS else "native"
        if sbom_format == "spdx":
            targets.append((self.project.output_dir / SPDX_FILENAME, self.spdx_document(pkgset)))
        elif sbom_format == "cyclonedx":
            targets.append((self.project.output_dir / CYCLONEDX_FILENAME, self.cyclonedx_document(pkgset)))
        writer = HostArtifactWriter(self.runner)
        for target, document in targets:
            writer.write_text(target, json.dumps(document, indent=2), "Write SBOM/provenance")

    def payload(self, output_iso: Path | None = None) -> dict[str, object]:
        data: dict[str, object] = {
            "generated_at": datetime.now(UTC).isoformat(),
            "project": self.project.to_dict(),
            "output_iso": str(output_iso) if output_iso else None,
            "sbom_format": self.options.sbom_format,
        }
        if self.options.include_commands:
            data["commands"] = [spec.display() for spec in self.runner.history]
        return data

    def spdx_document(self, packages: Iterable[str] | None = None) -> dict[str, object]:
        pkgset = self._package_set(packages)
        created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        doc_name = f"{self.project.name}-{self.project.release.version}"
        spdx_packages = []
        relationships = []
        for index, name in enumerate(pkgset):
            spdx_id = f"SPDXRef-Package-{index}"
            spdx_packages.append(
                {
                    "name": name,
                    "SPDXID": spdx_id,
                    "downloadLocation": "NOASSERTION",
                    "versionInfo": "NOASSERTION",
                    "filesAnalyzed": False,
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": self._purl(name),
                        }
                    ],
                }
            )
            relationships.append(
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": spdx_id,
                    "relationshipType": "DESCRIBES",
                }
            )
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": doc_name,
            "documentNamespace": f"https://distroforge.invalid/spdx/{doc_name}-{created}",
            "creationInfo": {
                "created": created,
                "creators": ["Tool: DistroForge"],
            },
            "packages": spdx_packages,
            "relationships": relationships,
        }

    def cyclonedx_document(self, packages: Iterable[str] | None = None) -> dict[str, object]:
        pkgset = self._package_set(packages)
        components = [
            {
                "type": "library",
                "name": name,
                "version": "NOASSERTION",
                "purl": self._purl(name),
            }
            for name in pkgset
        ]
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools": [{"vendor": "DistroForge", "name": "distroforge"}],
                "component": {
                    "type": "operating-system",
                    "name": self.project.name,
                    "version": self.project.release.version,
                },
            },
            "components": components,
        }

    def _package_set(self, packages: Iterable[str] | None) -> list[str]:
        source = packages if packages is not None else self.project.packages
        return sorted({str(name).strip() for name in source if str(name).strip()})

    def _purl(self, name: str) -> str:
        family = (self.project.release.family or "debian").lower()
        return f"pkg:deb/{family}/{name}"
