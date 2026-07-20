from __future__ import annotations

import ast
from pathlib import Path

from distroforge.core.command import CommandRunner
from distroforge.core.doctor import DoctorItem, install_missing
from distroforge.core.mirrors import MirrorOptions, MirrorService
from distroforge.core.packaging import build_debian_package
from distroforge.core.project import Project

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "distroforge"

# Direct subprocess use is intentionally rare. Most host commands must flow
# through CommandRunner so dry-run, logging and virtual command handling stay
# centralized. Adding a module here is a release-safety decision, not a style
# cleanup.
APPROVED_SUBPROCESS_MODULES = {
    "distroforge/ai/backend.py": "optional local model CLI narration; degrades to offline",
    "distroforge/core/boot_proof.py": "read-only ISO metadata helper with timeout",
    "distroforge/core/capture.py": "read-only installed-system capture probes",
    "distroforge/core/command.py": "central CommandRunner execution boundary",
    "distroforge/core/packaging.py": "local packaging evidence capture without shell or privilege escalation",
    "distroforge/core/terminal.py": "interactive PTY terminal process boundary",
}

APPROVED_EXECUTION_GATES = {
    "distroforge/commands/build.py": (
        "CommandRunner(dry_run=not args.execute",
        "validate_for_build(project, runner, execute=args.execute)",
    ),
    "distroforge/commands/doctor.py": (
        "CommandRunner(dry_run=not install)",
        "install_missing(",
    ),
    "distroforge/commands/mirrors.py": (
        'CommandRunner(dry_run=args.mirrors_command != "apply" and args.mirrors_command != "restore")',
    ),
    "distroforge/commands/debrand.py": (
        'CommandRunner(dry_run=args.debrand_command != "apply")',
    ),
    "distroforge/commands/artifacts.py": (
        "execute=not dry_run",
        "CommandRunner(dry_run=not execute)",
        "execute_signing",
    ),
    "distroforge/commands/packaging.py": (
        "build_debian_package(root, execute=execute)",
        "HermeticBuildPlan(",
    ),
}


def _source_files() -> list[Path]:
    return sorted(
        path
        for path in SOURCE_ROOT.rglob("*.py")
        if "__pycache__" not in path.parts
    )


def _calls(tree: ast.AST) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def _call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    if isinstance(func, ast.Name):
        return func.id
    return ""


def test_no_shell_true_or_os_shell_helpers_in_source() -> None:
    offenders: list[str] = []
    for path in _source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for call in _calls(tree):
            name = _call_name(call)
            if name in {"os.system", "os.popen"}:
                offenders.append(f"{path.relative_to(ROOT)}:{call.lineno}: {name}")
            for keyword in call.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    offenders.append(f"{path.relative_to(ROOT)}:{call.lineno}: shell=True")

    assert offenders == []


def test_direct_subprocess_calls_stay_inside_reviewed_boundaries() -> None:
    offenders: list[str] = []
    observed: set[str] = set()
    direct_calls = {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}
    for path in _source_files():
        relative = str(path.relative_to(ROOT))
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for call in _calls(tree):
            name = _call_name(call)
            if name in direct_calls:
                observed.add(relative)
                if relative not in APPROVED_SUBPROCESS_MODULES:
                    offenders.append(f"{relative}:{call.lineno}: {name}")

    assert offenders == []
    assert observed <= set(APPROVED_SUBPROCESS_MODULES)


def test_risky_cli_surfaces_keep_explicit_execution_gates() -> None:
    missing: list[str] = []
    for relative, snippets in APPROVED_EXECUTION_GATES.items():
        source = (ROOT / relative).read_text(encoding="utf-8")
        for snippet in snippets:
            if snippet not in source:
                missing.append(f"{relative}: {snippet}")

    assert missing == []


def test_doctor_install_plan_records_apt_without_executing() -> None:
    runner = CommandRunner(dry_run=True)
    items = [DoctorItem("xorriso", False, "ISO extraction and rebuild")]

    install_missing(runner, items, use_sudo=False)

    commands = [spec.argv for spec in runner.history]
    assert ("apt-get", "update") in commands
    assert ("apt-get", "install", "-y", "xorriso") in commands


def test_mirror_apply_and_restore_dry_run_do_not_touch_apt_tree(tmp_path) -> None:
    project = Project.create("MirrorDry", tmp_path / "mirror-dry", "26.04")
    runner = CommandRunner(dry_run=True)
    service = MirrorService(runner, project, MirrorOptions(enabled=True), use_sudo=False)

    service.apply()
    service.restore()

    commands = [spec.argv for spec in runner.history]
    assert ("mirror-backup", str(project.squashfs_root / "etc/apt")) in commands
    assert ("write-file", str(project.squashfs_root / "etc/apt/sources.list.d/distroforge.sources")) in commands
    assert ("mirror-restore", str(project.workdir / "apt-sources.backup")) in commands
    assert not (project.squashfs_root / "etc/apt").exists()
    assert not (project.workdir / "apt-sources.backup").exists()


def test_debian_package_build_defaults_to_plan_mode(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()

    report = build_debian_package(root)

    assert report.status == "planned"
    assert report.build.status == "planned"
    assert all(check.status == "skipped" for check in report.checks)
