from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .evidence_run import (
    canonical_sha256,
    critical_artifact_identity,
    evidence_run_path,
    observed_toolchain_identity,
    write_immutable_text,
    write_text_alias,
)
from .hashing import sha256_file
from .host_artifacts import HostArtifactWriter
from .project import Project

SBOM_FORMATS: tuple[str, ...] = ("native", "spdx", "cyclonedx")
SPDX_FILENAME = "distroforge-sbom.spdx.json"
CYCLONEDX_FILENAME = "distroforge-sbom.cdx.json"
PROVENANCE_SCHEMA = "distroforge.provenance.v2"


@dataclass
class ProvenanceOptions:
    enabled: bool = True
    include_commands: bool = True
    sbom_format: str = "native"


class ProvenanceService:
    def __init__(
        self,
        runner: CommandRunner,
        project: Project,
        options: ProvenanceOptions,
        evidence_context: dict[str, object] | None = None,
    ) -> None:
        self.runner = runner
        self.project = project
        self.options = options
        self.evidence_context = evidence_context

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
        for target, document in targets:
            self._write_document(target, document)

    def payload(self, output_iso: Path | None = None) -> dict[str, object]:
        data: dict[str, object] = {
            "schema": PROVENANCE_SCHEMA,
            "attestation_kind": "build",
            "generated_at": datetime.now(UTC).isoformat(),
            "project": self.project.to_dict(),
            "output_iso": str(output_iso) if output_iso else None,
            "output_iso_sha256": (
                sha256_file(output_iso) if output_iso and output_iso.is_file() else None
            ),
            "artifacts": critical_artifact_identity(self.project, output_iso),
            "sbom_format": self.options.sbom_format,
        }
        if self.evidence_context:
            data["run"] = self.evidence_context
            data["run_id"] = self.evidence_context.get("run_id")
        if self.options.include_commands:
            command_records = [
                {
                    "argv": list(spec.argv),
                    "cwd": str(spec.cwd) if spec.cwd else None,
                    "needs_root": spec.needs_root,
                    "description": spec.description,
                    "has_stdin": spec.stdin is not None,
                    "env_keys": sorted(spec.env),
                    "env_sha256": canonical_sha256(dict(spec.env)),
                }
                for spec in self.runner.history
            ]
            data["commands"] = [spec.display() for spec in self.runner.history]
            data["command_records"] = command_records
            data["commands_sha256"] = canonical_sha256(command_records)
            data["observed_toolchain"] = observed_toolchain_identity(self.runner.history)
            executed = list(self.runner.execution_identities)
            data["executed_host_entrypoints"] = executed
            data["executed_host_entrypoints_sha256"] = canonical_sha256(executed)
        return data

    def _write_document(self, target: Path, document: object) -> None:
        if not self.evidence_context:
            HostArtifactWriter(self.runner).write_text(
                target,
                json.dumps(document, indent=2),
                "Write SBOM/provenance",
            )
            return
        run_id = str(self.evidence_context["run_id"])
        executed = self.evidence_context.get("mode") == "execute" and not self.runner.dry_run
        immutable = evidence_run_path(
            self.project.output_dir,
            run_id,
            target.name,
            executed=executed,
        )
        content = json.dumps(document, indent=2) + "\n"
        for path, description in (
            (immutable, "Write immutable SBOM/provenance"),
            (target, "Write latest SBOM/provenance alias"),
        ):
            self.runner.run(
                CommandSpec(
                    argv=("write-file", str(path)),
                    description=description,
                )
            )
        if self.runner.dry_run:
            return
        write_immutable_text(immutable, content)
        write_text_alias(target, content)

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
            # SPDX 2.3 wants a unique absolute URI here, under a namespace the creator
            # controls, so that two documents can never collide. It need not resolve,
            # which is why .invalid survived here for so long -- but an SBOM published
            # with an archive should not point at a domain guaranteed never to exist.
            # The repository is the one namespace this project actually controls; the
            # alias domain would not be, it belongs to the forwarding provider.
            "documentNamespace": (
                f"https://github.com/Test-bot-cell/Distroforge/spdx/{doc_name}-{created}"
            ),
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
