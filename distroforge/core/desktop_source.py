from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner, CommandSpec, sudo
from .integrity import IntegrityOptions, IntegrityService


@dataclass(frozen=True)
class DesktopSourceProfile:
    key: str
    label: str
    upstream: str
    current_version: str
    build_system: str
    notes: str = ""


@dataclass(frozen=True)
class DesktopSourceComponent:
    name: str
    version: str
    source_url: str
    sha256: str | None = None
    build_system: str = "meson"
    package_name: str | None = None
    configure_args: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str, default_build_system: str = "meson") -> DesktopSourceComponent:
        parts = [part.strip() for part in value.split("|")]
        if len(parts) < 3:
            raise ValueError(
                "Desktop source component must be name|version|url[|sha256|build_system|package]"
            )
        return cls(
            name=parts[0],
            version=parts[1],
            source_url=parts[2],
            sha256=parts[3] if len(parts) > 3 and parts[3] else None,
            build_system=parts[4] if len(parts) > 4 and parts[4] else default_build_system,
            package_name=parts[5] if len(parts) > 5 and parts[5] else None,
        )

    def spec(self) -> str:
        return "|".join(
            [
                self.name,
                self.version,
                self.source_url,
                self.sha256 or "",
                self.build_system,
                self.package_name or "",
            ]
        )


@dataclass
class DesktopSourceOptions:
    enabled: bool = False
    desktop: str | None = None
    version: str | None = None
    components: list[DesktopSourceComponent] = field(default_factory=list)
    install_debs: bool = True
    jobs: int = 0
    local_suffix: str = "dforge"
    build_dependencies: list[str] = field(default_factory=list)
    require_sha256: bool = False

    def summary(self) -> str:
        if not self.enabled:
            return "disabled"
        target = self.desktop or "selected desktop"
        version = self.version or "catalog-current"
        return f"{target} upstream .deb ({version}, {len(self.components)} component override(s))"


class DesktopSourceService:
    def __init__(
        self,
        runner: CommandRunner,
        root: Path,
        workdir: Path,
        options: DesktopSourceOptions,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.root = root
        self.workdir = workdir
        self.options = options
        self.use_sudo = use_sudo

    def run(self) -> None:
        if not self.options.enabled:
            self.runner.run(
                CommandSpec(
                    argv=("desktop-source-skip", str(self.root)),
                    description="Desktop upstream source phase disabled",
                )
            )
            return
        profile = self._profile()
        components = self.options.components or self._catalog_components(profile)
        self._install_build_dependencies(profile)
        for component in components:
            archive = self._archive_path(component)
            source_dir = self._source_dir(component)
            self._fetch(component, archive)
            self._verify(component, archive)
            self._extract(archive, source_dir)
            self._build_deb(component, source_dir)
        self._install_debs()

    def _profile(self) -> DesktopSourceProfile:
        desktop = self.options.desktop
        profiles = load_desktop_source_profiles()
        if not desktop or desktop not in profiles:
            known = ", ".join(sorted(profiles))
            raise ValueError(f"Unknown desktop source profile {desktop!r}. Known: {known}")
        return profiles[desktop]

    def _catalog_components(self, profile: DesktopSourceProfile) -> list[DesktopSourceComponent]:
        version = self.options.version or profile.current_version
        self.runner.run(
            CommandSpec(
                argv=("desktop-source-catalog", profile.key, profile.upstream, version),
                description=profile.notes or f"Use curated upstream source profile for {profile.label}",
            )
        )
        return [
            DesktopSourceComponent(
                name=f"{profile.key}-session",
                version=version,
                source_url=f"catalog://{profile.key}/{version}",
                build_system=profile.build_system,
                package_name=f"distroforge-{profile.key}-session",
            )
        ]

    def _install_build_dependencies(self, profile: DesktopSourceProfile) -> None:
        packages = [
            "build-essential",
            "debhelper",
            "devscripts",
            "fakeroot",
            "dh-make",
            "dpkg-dev",
            "ca-certificates",
            "curl",
            "xz-utils",
            "meson",
            "ninja-build",
            "cmake",
            "pkg-config",
            "autoconf",
            "automake",
            "libtool",
            *self.options.build_dependencies,
        ]
        if profile.build_system == "gnome":
            packages.extend(["gi-docgen", "gobject-introspection", "libglib2.0-dev"])
        ChrootService(self.runner, self.root, self.use_sudo).run(
            "apt-get",
            "-y",
            "install",
            *sorted(set(packages)),
        )

    def _fetch(self, component: DesktopSourceComponent, archive: Path) -> None:
        if component.source_url.startswith("catalog://"):
            self.runner.run(
                CommandSpec(
                    argv=("desktop-source-resolve", component.source_url, str(archive)),
                    description=(
                        f"Resolve curated upstream source for {component.name}. "
                        "Override with explicit component URLs for execution."
                    ),
                )
            )
            if not self.runner.dry_run:
                raise ValueError(f"Component {component.name} requires an explicit source URL")
            return
        if not self.runner.dry_run:
            archive.parent.mkdir(parents=True, exist_ok=True)
        self.runner.run(
            CommandSpec(
                argv=sudo(("curl", "-L", "-o", str(archive), component.source_url), self.use_sudo),
                needs_root=self.use_sudo,
                description=f"Fetch upstream desktop source {component.name}",
            )
        )

    def _verify(self, component: DesktopSourceComponent, archive: Path) -> None:
        IntegrityService(
            self.runner,
            IntegrityOptions(
                require_sha256=self.options.require_sha256,
                use_sudo=self.use_sudo,
            ),
        ).verify_sha256(
            archive,
            component.sha256,
            f"upstream desktop source {component.name}",
        )

    def _extract(self, archive: Path, source_dir: Path) -> None:
        self.runner.run(
            CommandSpec(
                argv=sudo(("mkdir", "-p", str(source_dir.parent)), self.use_sudo),
                needs_root=self.use_sudo,
                description="Prepare desktop source workspace",
            )
        )
        self.runner.run(
            CommandSpec(
                argv=sudo(("tar", "-xf", str(archive), "-C", str(source_dir.parent)), self.use_sudo),
                needs_root=self.use_sudo,
                description=f"Extract desktop source {archive.name}",
            )
        )

    def _build_deb(self, component: DesktopSourceComponent, source_dir: Path) -> None:
        build_dir = self._target_path(source_dir)
        package = component.package_name or f"distroforge-{component.name}"
        jobs = self.options.jobs if self.options.jobs > 0 else "$(nproc)"
        if component.build_system in {"debuild", "debian"}:
            command = f"cd {build_dir} && dpkg-buildpackage -us -uc -b -j{jobs}"
        elif component.build_system == "cmake":
            command = (
                f"cd {build_dir} && cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/usr "
                "&& cmake --build build "
                f"&& cpack -G DEB -B ../distroforge-desktop-debs"
            )
        elif component.build_system == "autotools":
            command = (
                f"cd {build_dir} && ./configure --prefix=/usr "
                f"{' '.join(component.configure_args)} "
                f"&& make -j{jobs} "
                f"&& make install DESTDIR=$PWD/build/root "
                f"&& distroforge-debwrap --name {package} "
                f"--version {component.version}+{self.options.local_suffix} "
                "--root build/root --output ../distroforge-desktop-debs"
            )
        else:
            command = (
                f"cd {build_dir} && meson setup build --prefix=/usr "
                f"--buildtype=release {' '.join(component.configure_args)} "
                f"&& ninja -C build -j{jobs} "
                f"&& distroforge-debwrap --name {package} "
                f"--version {component.version}+{self.options.local_suffix} "
                "--root build --output ../distroforge-desktop-debs"
            )
        ChrootService(self.runner, self.root, self.use_sudo).run("/bin/bash", "-lc", command)

    def _install_debs(self) -> None:
        if not self.options.install_debs:
            self.runner.run(
                CommandSpec(
                    argv=("desktop-source-install-skip", str(self._deb_dir())),
                    description="Desktop source .deb installation disabled",
                )
            )
            return
        target = self._target_path(self._deb_dir())
        command = (
            f"set -e; debs=$(find {target} -maxdepth 1 -name '*.deb' -print | sort); "
            'test -n "$debs"; dpkg -i $debs || apt-get -f -y install'
        )
        ChrootService(self.runner, self.root, self.use_sudo).run("/bin/bash", "-lc", command)

    def _archive_path(self, component: DesktopSourceComponent) -> Path:
        return self.root / "usr" / "src" / "distroforge-desktops" / f"{component.name}-{component.version}.tar.xz"

    def _source_dir(self, component: DesktopSourceComponent) -> Path:
        return self.root / "usr" / "src" / "distroforge-desktops" / f"{component.name}-{component.version}"

    def _deb_dir(self) -> Path:
        return self.root / "usr" / "src" / "distroforge-desktops" / "distroforge-desktop-debs"

    def _target_path(self, path: Path) -> str:
        try:
            relative = path.resolve().relative_to(self.root.resolve())
            return "/" + str(relative).replace("\\", "/")
        except Exception:
            return str(path).replace("\\", "/")


@lru_cache(maxsize=1)
def load_desktop_source_profiles() -> dict[str, DesktopSourceProfile]:
    path = files("distroforge.data").joinpath("desktop_sources.toml")
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    profiles: dict[str, DesktopSourceProfile] = {}
    for key, data in raw["desktop_sources"].items():
        profiles[key] = DesktopSourceProfile(
            key=key,
            label=data["label"],
            upstream=data["upstream"],
            current_version=str(data["current_version"]),
            build_system=data.get("build_system", "meson"),
            notes=data.get("notes", ""),
        )
    return profiles
