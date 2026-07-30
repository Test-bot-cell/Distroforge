from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .artifact_verification import (
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .hashing import (
    MAX_SHA256_SUMS_BYTES,
    sha256_from_sums_bytes,
)
from .qemu_smoke import QemuSmokePlanner


@dataclass(frozen=True)
class ReleaseReadinessItem:
    name: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass
class ReleaseReadinessReport:
    iso: Path
    output_dir: Path
    items: list[ReleaseReadinessItem] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(item.status == "blocked" for item in self.items)

    def to_dict(self) -> dict[str, object]:
        return {
            "iso": str(self.iso),
            "output_dir": str(self.output_dir),
            "blocked": self.blocked,
            "items": [item.to_dict() for item in self.items],
        }

    def render_text(self) -> str:
        lines = [
            "Release readiness",
            f"ISO: {self.iso}",
            f"Output: {self.output_dir}",
            f"Status: {'blocked' if self.blocked else 'review required'}",
            "",
        ]
        lines.extend(f"[{item.status}] {item.name}: {item.detail}" for item in self.items)
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class ReleaseReadinessService:
    def check(
        self,
        iso: Path,
        output_dir: Path,
        *,
        verify_checksum: bool = True,
        session: ArtifactVerificationSession | None = None,
        qemu_report: Path | None = None,
        use_default_qemu_alias: bool = True,
    ) -> ReleaseReadinessReport:
        """Capture the release evidence available for ``iso``.

        ``verify_checksum=False`` reports the digest SHA256SUMS already records
        rather than re-reading the ISO. The sha256 item is evidence, never a
        blocker (an existing ISO is always "captured"), so the light form cannot
        change ``blocked`` -- it only spares callers that just want the verdict.
        """
        iso = Path(os.path.abspath(iso))
        output_dir = Path(os.path.abspath(output_dir))
        report = ReleaseReadinessReport(iso=iso, output_dir=output_dir)
        if iso.parent != output_dir:
            report.items.append(
                ReleaseReadinessItem(
                    "product-path",
                    "blocked",
                    "output_dir must be the canonical parent of the selected ISO",
                )
            )
            return report
        owned_session = session is None
        active_session = session or ArtifactVerificationSession(
            Path("/"),
            label="release readiness artifact session",
        )
        try:
            try:
                iso.lstat()
            except FileNotFoundError:
                iso_present = False
            else:
                iso_present = True
            if iso_present:
                size = active_session.file_path(
                    iso.absolute(),
                    label="release readiness ISO",
                ).identity.size
                report.items.append(ReleaseReadinessItem("iso", "captured", f"{size} bytes"))
                report.items.append(
                    ReleaseReadinessItem(
                        "sha256",
                        "captured",
                        _digest(
                            iso,
                            output_dir,
                            verify_checksum,
                            active_session,
                        ),
                    )
                )
            else:
                report.items.append(
                    ReleaseReadinessItem(
                        "iso",
                        "blocked",
                        "ISO path does not exist",
                    )
                )
                report.items.append(
                    ReleaseReadinessItem(
                        "sha256",
                        "blocked",
                        "No ISO to checksum",
                    )
                )
            for name in (
                "SHA256SUMS",
                "BUILDINFO",
                "INTEGRITY",
                "PROVENANCE.json",
            ):
                path = output_dir / name
                try:
                    path.lstat()
                except FileNotFoundError:
                    status = "needs review"
                    detail = f"Missing {name}"
                except OSError as exc:
                    status = "blocked"
                    detail = f"Cannot inspect {name}: {exc}"
                else:
                    try:
                        identity = active_session.file_path(
                            path.absolute(),
                            label=f"release readiness {name}",
                            allow_empty=True,
                        ).identity
                    except ArtifactVerificationError as exc:
                        status = "blocked"
                        detail = f"Unsafe {name}: {exc}"
                    else:
                        status = "captured"
                        detail = f"{path} ({identity.size} bytes)"
                report.items.append(ReleaseReadinessItem(name.lower(), status, detail))
            selected_qemu = (
                qemu_report
                if qemu_report is not None
                else output_dir / "qemu-lab-report.json"
                if use_default_qemu_alias
                else None
            )
            if selected_qemu is not None:
                qemu_name = selected_qemu.name
                try:
                    selected_qemu.lstat()
                except FileNotFoundError:
                    status = "needs review"
                    detail = f"Missing {qemu_name}"
                except OSError as exc:
                    status = "blocked"
                    detail = f"Cannot inspect {qemu_name}: {exc}"
                else:
                    try:
                        identity = active_session.file_path(
                            selected_qemu.absolute(),
                            label="release readiness immutable QEMU report",
                            allow_empty=True,
                        ).identity
                    except ArtifactVerificationError as exc:
                        status = "blocked"
                        detail = f"Unsafe {qemu_name}: {exc}"
                    else:
                        status = "captured"
                        detail = f"{selected_qemu} ({identity.size} bytes)"
                report.items.append(ReleaseReadinessItem(qemu_name.lower(), status, detail))
            qemu_plan = QemuSmokePlanner().plan(iso)
            report.items.append(
                ReleaseReadinessItem(
                    "qemu-smoke",
                    "needs review",
                    f"{len(qemu_plan.scenarios)} planned scenarios",
                )
            )
            report.items.append(
                ReleaseReadinessItem(
                    "trademark",
                    "needs review",
                    "Review derivative/vendor identity, artwork, and redistribution "
                    "policy before publication",
                )
            )
            report.items.append(
                ReleaseReadinessItem(
                    "repo-trust",
                    "needs review",
                    "APT repositories should use signed-by keyrings and pinned provenance",
                )
            )
        except (ArtifactVerificationError, OSError, UnicodeError, ValueError) as exc:
            report.items.append(
                ReleaseReadinessItem(
                    "artifact-session",
                    "blocked",
                    f"Readiness evidence is unsafe or unreadable: {exc}",
                )
            )
        finally:
            if owned_session:
                try:
                    active_session.seal()
                except ArtifactVerificationError as exc:
                    if not any(item.name == "artifact-session" for item in report.items):
                        report.items.append(
                            ReleaseReadinessItem(
                                "artifact-session",
                                "blocked",
                                f"Readiness evidence did not seal: {exc}",
                            )
                        )
        return report


def _digest(
    iso: Path,
    output_dir: Path,
    verify_checksum: bool,
    session: ArtifactVerificationSession,
) -> str:
    if verify_checksum:
        return session.file_path(
            iso.absolute(),
            label="release readiness ISO",
        ).digest()
    sums = output_dir / "SHA256SUMS"
    recorded = (
        sha256_from_sums_bytes(
            session.file_path(
                sums.absolute(),
                label="release readiness SHA256SUMS",
                max_bytes=MAX_SHA256_SUMS_BYTES,
            ).read_bytes(),
            iso.name,
        )
        if _path_is_present(sums)
        else None
    )
    return recorded or "not checksummed yet"


def _path_is_present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True
