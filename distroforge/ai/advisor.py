from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from distroforge.core.manifest import PackageEntry


@dataclass(frozen=True)
class Advice:
    level: str
    title: str
    detail: str
    packages: tuple[str, ...] = ()


class ManifestAdvisor:
    """Dependency-free baseline advisor.

    The class intentionally starts with transparent heuristics. A future
    embedding or classifier backend can implement the same public method and be
    selected from settings without making the app depend on cloud AI.
    """

    HEAVY_DESKTOP_HINTS = {
        "libreoffice": "office suite",
        "thunderbird": "mail client",
        "evolution": "groupware client",
        "gnome-games": "games",
    }
    SECURITY_HINTS = {
        "openssh-server": "remote shell enabled",
        "telnetd": "insecure remote service",
        "rsh-server": "legacy remote shell",
        "vsftpd": "ftp service",
    }
    BUILD_HINTS = {
        "build-essential": "compiler toolchain",
        "gcc": "compiler toolchain",
        "make": "build tool",
        "cmake": "build tool",
    }

    def advise(self, manifest: dict[str, PackageEntry]) -> list[Advice]:
        names = set(manifest)
        advice: list[Advice] = []

        heavy = self._matching_prefixes(names, self.HEAVY_DESKTOP_HINTS)
        if heavy:
            advice.append(
                Advice(
                    level="info",
                    title="Desktop payload can be slimmed",
                    detail=(
                        "Some large default applications are present. Keep them for a general desktop, "
                        "remove them for a kiosk, lab or minimal remix."
                    ),
                    packages=tuple(sorted(heavy)),
                )
            )

        exposed = self._matching_prefixes(names, self.SECURITY_HINTS)
        if exposed:
            advice.append(
                Advice(
                    level="warning",
                    title="Review network-facing services",
                    detail=(
                        "Server daemons in a live image should be deliberate, documented and hardened "
                        "before publishing the ISO."
                    ),
                    packages=tuple(sorted(exposed)),
                )
            )

        build_tools = self._matching_prefixes(names, self.BUILD_HINTS)
        if build_tools:
            advice.append(
                Advice(
                    level="info",
                    title="Build tooling detected",
                    detail=(
                        "Developer images benefit from compilers; end-user images usually do not need "
                        "them installed by default."
                    ),
                    packages=tuple(sorted(build_tools)),
                )
            )

        families = Counter(name.split("-", 1)[0] for name in names)
        snap_related = [name for name in names if name.startswith("snap")]
        if snap_related:
            advice.append(
                Advice(
                    level="info",
                    title="Snap stack present",
                    detail=(
                        "Decide early whether the remix embraces Snap packages or prefers deb-only workflows, "
                        "because that affects defaults and documentation."
                    ),
                    packages=tuple(sorted(snap_related)),
                )
            )

        if families.get("linux", 0) > 12:
            advice.append(
                Advice(
                    level="warning",
                    title="Many kernel packages detected",
                    detail=(
                        "Multiple kernel package generations can inflate the ISO. Clean old kernel packages "
                        "before the final squashfs build."
                    ),
                )
            )

        return advice

    @staticmethod
    def _matching_prefixes(names: set[str], hints: dict[str, str]) -> set[str]:
        matched: set[str] = set()
        for name in names:
            if any(name == hint or name.startswith(f"{hint}-") for hint in hints):
                matched.add(name)
        return matched
