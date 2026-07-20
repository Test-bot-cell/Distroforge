from __future__ import annotations

import hashlib
import json

from distroforge.core.apt import AptService, PackagePlan, parse_repository_line
from distroforge.core.apt_cache import AptCacheOptions, AptCacheService
from distroforge.core.bootstrap import BootstrapService
from distroforge.core.build import BuildOptions, BuildReport
from distroforge.core.build_reports import BuildReportArtifactService
from distroforge.core.command import CommandError, CommandResult, CommandRunner, CommandSpec, sudo
from distroforge.core.demo_iso import run_demo_iso
from distroforge.core.iso_acceptance import accept_iso
from distroforge.core.iso_build import run_iso_build
from distroforge.core.iso_doctor import diagnose_iso_build
from distroforge.core.iso_toolchain import check_iso_toolchain
from distroforge.core.network import NetworkOptions, NetworkService
from distroforge.core.policy import CompatibilityReport
from distroforge.core.ppa import PpaOptions, PpaService, PpaSpec
from distroforge.core.project import Project
from distroforge.core.snapshots import SnapshotOptions, SnapshotService
from distroforge.core.squashfs import SquashfsService
from distroforge.core.validate import format_issues, validate_for_build


class RecordingExecuteRunner(CommandRunner):
    def __init__(self) -> None:
        super().__init__(dry_run=False)

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        return CommandResult(spec=spec, returncode=0, stdout="", stderr="")


def test_repository_parser_preserves_signed_by_option() -> None:
    repository = parse_repository_line(
        "deb [signed-by=/usr/share/keyrings/example.gpg] https://example.invalid/ubuntu noble main universe"
    )

    assert repository.uri == "https://example.invalid/ubuntu"
    assert repository.suite == "noble"
    assert repository.components == ("main", "universe")
    assert repository.signed_by == "/usr/share/keyrings/example.gpg"
    assert repository.source_line() == (
        "deb [signed-by=/usr/share/keyrings/example.gpg] "
        "https://example.invalid/ubuntu noble main universe"
    )


def test_package_plan_normalized_removes_install_from_remove() -> None:
    plan = PackagePlan(install=["git", "curl", "git"], remove=["git", "nano"], purge=True)

    normalized = plan.normalized()

    assert normalized.install == ["curl", "git"]
    assert normalized.remove == ["nano"]
    assert normalized.purge is True


def test_project_create_and_validate_bootstrap_dry_run(tmp_path) -> None:
    project = Project.create("AuditSmoke", tmp_path / "audit-smoke", "26.04")
    project.source_mode = "bootstrap"
    project.save()

    loaded = Project.load(project.root)
    issues = validate_for_build(loaded, CommandRunner(dry_run=True), execute=False)

    assert format_issues(issues) == "Validation OK"
    assert json.loads((project.root / "project.json").read_text(encoding="utf-8"))["source_mode"] == "bootstrap"


def test_iso_doctor_points_missing_source_iso_to_build_command(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.iso_doctor.CommandRunner.has_binary", lambda *args: True)
    project = Project.create("NeedIso", tmp_path / "need-iso", "26.04")

    report = diagnose_iso_build(project, BuildOptions())

    assert report.status == "blocked"
    assert {finding.code for finding in report.findings} >= {"source-iso-missing", "not-built-yet"}
    assert report.next_command.startswith("distroforge build")
    assert "--source-iso /path/to/source.iso" in report.next_command


def test_iso_toolchain_reports_single_install_command(monkeypatch) -> None:
    monkeypatch.setattr("distroforge.core.command.CommandRunner.has_binary", staticmethod(lambda name: name in {"chroot", "apt-get"}))

    report = check_iso_toolchain()

    assert report.status == "blocked"
    assert "xorriso" in report.packages
    assert "squashfs-tools" in report.packages
    assert "mmdebstrap" in report.packages
    assert report.install_command.startswith("sudo apt update")


def test_iso_build_dry_run_writes_iso_build_report(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.iso_doctor.CommandRunner.has_binary", lambda *args: True)
    project = Project.create("IsoPath", tmp_path / "iso-path", "26.04")
    project.source_mode = "bootstrap"

    report = run_iso_build(project, BuildOptions(), execute=False, boot_proof_backend="auto")

    assert report.status == "planned"
    assert report.execute is False
    assert report.output_iso == project.output_dir / "IsoPath.iso"
    assert (project.output_dir / "ISO-BUILD.json").exists()


def test_iso_build_execute_requires_real_output_iso(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.iso_doctor.CommandRunner.has_binary", lambda *args: True)

    class NoOutputBuild:
        def __init__(self, project, runner, options) -> None:
            self.report = BuildReport()

        def run(self) -> BuildReport:
            return self.report

    monkeypatch.setattr("distroforge.core.iso_build.BuildOrchestrator", NoOutputBuild)
    project = Project.create("NoIso", tmp_path / "no-iso", "26.04")
    project.source_mode = "bootstrap"

    report = run_iso_build(project, BuildOptions(), execute=True)

    assert report.status == "blocked"
    assert report.output_exists is False
    assert report.output_sha256 == ""


def test_iso_build_execute_rejects_empty_output_iso(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.iso_doctor.CommandRunner.has_binary", lambda *args: True)

    class EmptyIsoBuild:
        def __init__(self, project, runner, options) -> None:
            self.options = options
            self.report = BuildReport()

        def run(self) -> BuildReport:
            self.options.output_iso.parent.mkdir(parents=True, exist_ok=True)
            self.options.output_iso.touch()
            return self.report

    monkeypatch.setattr("distroforge.core.iso_build.BuildOrchestrator", EmptyIsoBuild)
    project = Project.create("EmptyIso", tmp_path / "empty-iso", "26.04")
    project.source_mode = "bootstrap"

    report = run_iso_build(project, BuildOptions(), execute=True)

    assert report.status == "blocked"
    assert report.output_exists is True
    assert report.output_size == 0
    assert report.output_sha256 == ""


def test_iso_build_execute_records_output_iso_sha256(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.iso_doctor.CommandRunner.has_binary", lambda *args: True)

    class WritesIsoBuild:
        def __init__(self, project, runner, options) -> None:
            self.options = options
            self.report = BuildReport()

        def run(self) -> BuildReport:
            self.options.output_iso.parent.mkdir(parents=True, exist_ok=True)
            self.options.output_iso.write_bytes(b"iso")
            return self.report

    monkeypatch.setattr("distroforge.core.iso_build.BuildOrchestrator", WritesIsoBuild)
    project = Project.create("HasIso", tmp_path / "has-iso", "26.04")
    project.source_mode = "bootstrap"

    report = run_iso_build(project, BuildOptions(), execute=True)
    payload = json.loads((project.output_dir / "ISO-BUILD.json").read_text(encoding="utf-8"))

    assert report.status == "built"
    assert report.output_exists is True
    assert report.output_size == 3
    assert report.output_sha256
    assert payload["output_exists"] is True
    assert payload["output_size"] == 3
    assert payload["output_sha256"] == report.output_sha256


def test_iso_accept_blocks_missing_iso(tmp_path) -> None:
    project = Project.create("AcceptMissing", tmp_path / "accept-missing", "26.04")
    project.source_mode = "bootstrap"

    report = accept_iso(project, BuildOptions())

    assert report.status == "blocked"
    assert report.next_command.startswith("distroforge iso-build")
    assert (project.output_dir / "ISO-ACCEPTANCE.json").exists()


def test_iso_accept_accepts_built_iso_with_evidence(tmp_path) -> None:
    project = Project.create("AcceptIso", tmp_path / "accept-iso", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "AcceptIso.iso"
    iso.parent.mkdir(parents=True, exist_ok=True)
    iso.write_bytes(b"accepted iso")
    sha = hashlib.sha256(iso.read_bytes()).hexdigest()
    (project.output_dir / "ISO-BUILD.json").write_text(json.dumps({
        "project": str(project.root),
        "output_iso": str(iso),
        "status": "built",
        "output_exists": True,
        "output_size": iso.stat().st_size,
        "output_sha256": sha,
    }), encoding="utf-8")
    (project.output_dir / "SHA256SUMS").write_text(f"{sha}  {iso.name}\n", encoding="utf-8")
    (project.output_dir / "BUILDINFO").write_text("build\n", encoding="utf-8")
    (project.output_dir / "distroforge-provenance.json").write_text("{}\n", encoding="utf-8")
    (project.output_dir / "report.html").write_text("<html></html>\n", encoding="utf-8")
    (project.output_dir / "boot-proof.json").write_text(json.dumps({
        "status": "ready",
        "selected_backend": "iso-scan",
        "proof_level": "structural",
    }), encoding="utf-8")

    report = accept_iso(project, BuildOptions())

    assert report.status == "accepted"
    assert report.next_command.startswith("distroforge publish-bundle")


def test_demo_iso_creates_minimal_bootstrap_project(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.iso_doctor.CommandRunner.has_binary", lambda *args: True)

    report = run_demo_iso(tmp_path / "demo", execute=False)
    project = Project.load(report.project)

    assert report.status == "planned"
    assert report.created is True
    assert project.source_mode == "bootstrap"
    assert report.output_iso == project.output_dir / f"{project.name}.iso"
    assert (project.output_dir / "DEMO-ISO.json").exists()


def test_virtual_commands_do_not_execute_as_host_binaries() -> None:
    runner = CommandRunner(dry_run=False)

    result = runner.run(CommandSpec(argv=("compatibility-report", "26.04", "resolute")))

    assert result.returncode == 0
    assert runner.history[-1].argv[0] == "compatibility-report"


def test_compatibility_report_writes_real_artifact_in_execute_mode(tmp_path) -> None:
    project = Project.create("CompatSmoke", tmp_path / "compat-smoke", "26.04")
    runner = CommandRunner(dry_run=False)

    BuildReportArtifactService(runner, project, BuildOptions()).write_compatibility_report(
        CompatibilityReport(
            release="26.04",
            codename="resolute",
            supported=True,
            messages=[],
        )
    )

    report = project.output_dir / "compatibility-report.txt"
    assert report.exists()
    assert "Release supported by DistroForge" in report.read_text(encoding="utf-8")


def test_bootstrap_copies_locked_boot_artifacts_with_sudo_install(tmp_path) -> None:
    project = Project.create("BootCopy", tmp_path / "boot-copy", "26.04")
    boot = project.squashfs_root / "boot"
    boot.mkdir(parents=True)
    (boot / "vmlinuz-locked").write_text("kernel", encoding="utf-8")
    (boot / "initrd.img-locked").write_text("initrd", encoding="utf-8")
    runner = RecordingExecuteRunner()

    BootstrapService(
        runner,
        project.release,
        project.squashfs_root,
        project.iso_root,
        use_sudo=True,
    ).create_iso_tree()

    commands = [spec.argv for spec in runner.history]
    assert any(
        command in commands
        for command in (
            (
                "sudo",
                "install",
                "-D",
                "-m",
                "0644",
                str(boot / "vmlinuz-locked"),
                str(project.iso_root / project.release.livefs / "vmlinuz"),
            ),
            (
                "sudo",
                "-A",
                "install",
                "-D",
                "-m",
                "0644",
                str(boot / "vmlinuz-locked"),
                str(project.iso_root / project.release.livefs / "vmlinuz"),
            ),
        )
    )
    grub = project.iso_root / "boot" / "grub" / "grub.cfg"
    assert "terminal_output console serial" in grub.read_text(encoding="utf-8")
    assert "console=ttyS0,115200n8" in grub.read_text(encoding="utf-8")


def test_apt_sources_uses_privileged_write_for_protected_rootfs(tmp_path) -> None:
    project = Project.create("AptWrite", tmp_path / "apt-write", "26.04")
    apt_dir = project.squashfs_root / "etc" / "apt"
    apt_dir.mkdir(parents=True)
    apt_dir.chmod(0o555)
    runner = RecordingExecuteRunner()

    try:
        AptService(runner, project.squashfs_root, project.release, use_sudo=True).write_sources()
    finally:
        apt_dir.chmod(0o755)

    commands = [spec.argv for spec in runner.history]
    assert any(command[:4] == ("sudo", "-A", "sh", "-c") or command[:3] == ("sudo", "sh", "-c") for command in commands)


def test_snapshot_create_prepares_directory_and_publishes_atomically(tmp_path) -> None:
    project = Project.create("SnapshotSmoke", tmp_path / "snapshot-smoke", "26.04")
    root = project.squashfs_root
    root.mkdir(parents=True)
    (root / "etc").mkdir()
    (root / "etc" / "os-release").write_text("ID=ubuntu\n", encoding="utf-8")
    snapshots_dir = project.workdir / "snapshots"

    SnapshotService(
        CommandRunner(dry_run=False),
        root,
        snapshots_dir,
        SnapshotOptions(enabled=True, phases=("after-apt",)),
        use_sudo=False,
    ).create("after-apt")

    assert (snapshots_dir / "after-apt.tar.zst").exists()
    assert not (snapshots_dir / "after-apt.tar.zst.part").exists()


def test_snapshot_dry_run_records_directory_tar_and_publish(tmp_path) -> None:
    project = Project.create("SnapshotDryRun", tmp_path / "snapshot-dry-run", "26.04")
    runner = CommandRunner(dry_run=True)

    SnapshotService(
        runner,
        project.squashfs_root,
        project.workdir / "snapshots",
        SnapshotOptions(enabled=True, phases=("after-apt",)),
        use_sudo=False,
    ).create("after-apt")

    commands = [spec.argv for spec in runner.history]
    assert commands[0] == ("mkdir", "-p", str(project.workdir / "snapshots"))
    tar_command = commands[1]
    assert tar_command[:5] == (
        "tar",
        "--zstd",
        "--one-file-system",
        "-cpf",
        str(project.workdir / "snapshots" / "after-apt.tar.zst.part"),
    )
    assert commands[2] == (
        "mv",
        "-f",
        str(project.workdir / "snapshots" / "after-apt.tar.zst.part"),
        str(project.workdir / "snapshots" / "after-apt.tar.zst"),
    )


def test_snapshot_rootfs_tar_uses_privilege_helper_in_dry_run(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DISTROFORGE_PRIVILEGE", "sudo")
    project = Project.create("SnapshotPrivilege", tmp_path / "snapshot-privilege", "26.04")
    runner = CommandRunner(dry_run=True)

    SnapshotService(
        runner,
        project.squashfs_root,
        project.workdir / "snapshots",
        SnapshotOptions(enabled=True, phases=("after-apt",)),
        use_sudo=True,
    ).create("after-apt")

    assert runner.history[1].needs_root is True
    assert runner.history[1].argv[:2] in (("sudo", "tar"), ("sudo", "-A"))


def test_snapshot_creation_skips_runtime_mountpoints_when_present(tmp_path) -> None:
    project = Project.create("SnapshotExcludes", tmp_path / "snapshot-excludes", "26.04")
    root = project.squashfs_root
    for entry in ("proc", "sys", "dev", "run", "tmp"):
        (root / entry).mkdir(parents=True, exist_ok=True)
    runner = CommandRunner(dry_run=True)

    SnapshotService(
        runner,
        root,
        project.workdir / "snapshots",
        SnapshotOptions(enabled=True, phases=("after-apt",)),
        use_sudo=True,
    ).create("after-apt")

    tar_command = runner.history[1].argv
    for excluded in ("./proc", "./sys", "./dev", "./run", "./tmp"):
        index = tar_command.index(excluded)
        assert tar_command[index - 1] == "--exclude"


def test_squashfs_dry_run_is_pure_and_records_commands(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)
    source = tmp_path / "rootfs"
    squashfs_image = tmp_path / "dist" / "filesystem.squashfs"
    destination = tmp_path / "extract" / "squashfs-root"

    service = SquashfsService(runner, use_sudo=False)
    service.pack(source, squashfs_image)
    service.unpack(squashfs_image, destination)

    assert not squashfs_image.parent.exists()
    assert not destination.parent.exists()

    commands = [spec.argv for spec in runner.history]
    assert commands[0][0] == "mksquashfs"
    assert commands[0][2] == str(squashfs_image)
    assert commands[1][0] == "unsquashfs"
    assert commands[1][3] == str(destination)


def test_bootstrap_reuses_existing_valid_rootfs(tmp_path) -> None:
    project = Project.create("ReuseRootfs", tmp_path / "reuse-rootfs", "26.04")
    (project.squashfs_root / "var/lib/dpkg").mkdir(parents=True)
    (project.squashfs_root / "var/lib/dpkg/status").write_text("", encoding="utf-8")
    (project.squashfs_root / "etc").mkdir()
    (project.squashfs_root / "etc/os-release").write_text("ID=ubuntu\n", encoding="utf-8")
    runner = RecordingExecuteRunner()

    BootstrapService(
        runner,
        project.release,
        project.squashfs_root,
        project.iso_root,
    ).create_rootfs()

    assert ("bootstrap-rootfs-reuse", str(project.squashfs_root)) in [spec.argv for spec in runner.history]


def test_bootstrap_reuse_sheds_stale_apt_overlays(tmp_path) -> None:
    # Real regression: a reused rootfs carried a prior run's release-track overlay
    # (`APT::Default-Release "devel"`), so the live-base apt-get install aborted with
    # "E: The value 'devel' is invalid for APT::Default-Release". The reuse path must
    # shed every DistroForge apt overlay before the base install runs apt, while
    # preserving the base sources (the only working repo when a mirror is set).
    project = Project.create("StaleOverlays", tmp_path / "stale-overlays", "26.04")
    root = project.squashfs_root
    (root / "var/lib/dpkg").mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text("", encoding="utf-8")
    (root / "etc").mkdir()
    (root / "etc/os-release").write_text("ID=ubuntu\n", encoding="utf-8")
    apt = root / "etc/apt"
    (apt / "apt.conf.d").mkdir(parents=True)
    (apt / "sources.list.d").mkdir(parents=True)
    (apt / "preferences.d").mkdir(parents=True)
    overlays = {
        apt / "apt.conf.d/90distroforge-release-track": 'APT::Default-Release "devel";\n',
        apt / "apt.conf.d/01distroforge-proxy": 'Acquire::http::Proxy "http://dead.invalid";\n',
        apt / "apt.conf.d/02distroforge-cache": 'Acquire::http::Proxy "http://dead.invalid";\n',
        apt / "sources.list.d/distroforge-track.list": "deb https://archive.ubuntu.com/ubuntu devel main\n",
        apt / "sources.list.d/distroforge-graphics.list": "deb https://ppa.invalid noble main\n",
        apt / "preferences.d/distroforge-proposed": "Package: *\n",
    }
    for path, text in overlays.items():
        path.write_text(text, encoding="utf-8")
    # The deb822 base sources a mirror run leaves -- the only working repo then.
    mirror_sources = apt / "sources.list.d/distroforge.sources"
    mirror_sources.write_text("Types: deb\nURIs: https://mirror.invalid/ubuntu\n", encoding="utf-8")

    BootstrapService(
        RecordingExecuteRunner(),
        project.release,
        root,
        project.iso_root,
    ).create_rootfs()

    for path in overlays:
        assert not path.exists(), path
    assert mirror_sources.exists()


def test_apt_cache_disabled_sheds_a_prior_runs_config(tmp_path) -> None:
    # Same class as the release-track regression: configure() runs before
    # system_sync's apt-get update, so a disabled run must remove a previous run's
    # cache/proxy pin rather than leave a dead cache host to fail the new build.
    project = Project.create("StaleCache", tmp_path / "stale-cache", "26.04")
    conf = project.squashfs_root / "etc/apt/apt.conf.d/02distroforge-cache"
    conf.parent.mkdir(parents=True)
    conf.write_text('Acquire::http::Proxy "http://dead.invalid";\n', encoding="utf-8")

    AptCacheService(
        RecordingExecuteRunner(),
        project.squashfs_root,
        AptCacheOptions(enabled=False),
        use_sudo=False,
    ).configure()

    assert not conf.exists()


def test_network_without_proxy_sheds_a_prior_runs_apt_proxy(tmp_path) -> None:
    project = Project.create("StaleProxy", tmp_path / "stale-proxy", "26.04")
    conf = project.squashfs_root / "etc/apt/apt.conf.d/01distroforge-proxy"
    conf.parent.mkdir(parents=True)
    conf.write_text('Acquire::http::Proxy "http://dead.invalid";\n', encoding="utf-8")

    NetworkService(
        RecordingExecuteRunner(),
        project.squashfs_root,
        NetworkOptions(),
        use_sudo=False,
    ).apply()

    assert not conf.exists()


def test_ppa_reconfigure_sheds_a_dropped_ppas_residue(tmp_path) -> None:
    # Last variant of the add-only apt-overlay class: a reused iso/rootfs tree
    # (unsquashfs -f does not prune extras) carried a previous run's PPA source and
    # keyring. configure() must drop the PPA the current options no longer request
    # so it cannot resurrect, keep a still-requested PPA, and never touch the release
    # track's distroforge-track.list (which a PPA slug, always "owner-name", can never
    # collide with) -- the release track service owns and re-derives that one.
    project = Project.create("StalePpa", tmp_path / "stale-ppa", "26.04")
    root = project.squashfs_root
    sources = root / "etc/apt/sources.list.d"
    keyrings = root / "usr/share/keyrings"
    sources.mkdir(parents=True)
    keyrings.mkdir(parents=True)
    dropped_source = sources / "distroforge-graphics-team.list"
    dropped_keyring = keyrings / "distroforge-graphics-team.gpg"
    kept_source = sources / "distroforge-keep-tools.list"
    track_list = sources / "distroforge-track.list"
    for path in (dropped_source, kept_source, track_list):
        path.write_text("deb https://ppa.invalid noble main\n", encoding="utf-8")
    dropped_keyring.write_bytes(b"stale-key")

    PpaService(
        RecordingExecuteRunner(),
        root,
        project.release,
        PpaOptions(ppas=[PpaSpec(owner="keep", name="tools", fingerprint="DEADBEEF")]),
        use_sudo=False,
    ).configure()

    assert not dropped_source.exists()
    assert not dropped_keyring.exists()
    assert kept_source.exists()
    assert track_list.exists()


def test_bootstrap_rejects_incomplete_nonempty_rootfs(tmp_path) -> None:
    project = Project.create("DirtyRootfs", tmp_path / "dirty-rootfs", "26.04")
    project.squashfs_root.mkdir(parents=True, exist_ok=True)
    (project.squashfs_root / "partial").write_text("", encoding="utf-8")

    try:
        BootstrapService(
            RecordingExecuteRunner(),
            project.release,
            project.squashfs_root,
            project.iso_root,
        ).create_rootfs()
    except ValueError as exc:
        assert "non-empty but incomplete" in str(exc)
    else:
        raise AssertionError("Expected incomplete rootfs to be rejected")


def test_pkexec_uses_absolute_program_path(monkeypatch) -> None:
    monkeypatch.setenv("DISTROFORGE_PRIVILEGE", "pkexec")

    argv = sudo(("install", "-D", "source", "target"), True)

    assert argv[:3] == ("pkexec", "/usr/bin/install", "-D")


def test_sudo_uses_askpass_when_no_terminal(monkeypatch) -> None:
    monkeypatch.setenv("DISTROFORGE_PRIVILEGE", "sudo")
    monkeypatch.setenv("SUDO_ASKPASS", "/usr/bin/ssh-askpass")

    argv = sudo(("apt-get", "update"), True)

    assert argv[:3] == ("sudo", "-A", "apt-get")


def test_pkexec_126_error_is_actionable() -> None:
    result = CommandResult(
        spec=CommandSpec(argv=("pkexec", "/usr/bin/install")),
        returncode=126,
        stdout="",
        stderr="not authorized",
    )

    message = str(CommandError(result))

    assert "Polkit authorization did not complete" in message
    assert "not authorized" in message
