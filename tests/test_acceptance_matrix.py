from __future__ import annotations

import json
import os
import socket
import subprocess
import urllib.request
from pathlib import Path

import pytest

from distroforge.cli import main
from distroforge.core.command import CommandRunner, CommandSpec
from distroforge.core.project import Project

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ESCAPE_BINARIES = {
    "pkexec",
    "qemu-system-aarch64",
    "qemu-system-x86_64",
    "sudo",
}


def _run_cli(capsys, argv: list[str], *, expected_code: int = 0) -> str:
    try:
        main(argv)
    except SystemExit as exc:
        assert exc.code == expected_code
    else:
        assert expected_code == 0
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    return captured.out


def _block_runtime_escapes(monkeypatch: pytest.MonkeyPatch, allowed_root: Path) -> None:
    original_run = CommandRunner.run
    original_run_streaming = CommandRunner.run_streaming
    resolved_allowed_root = allowed_root.resolve()

    def assert_safe_spec(spec: CommandSpec) -> None:
        program = spec.argv[0] if spec.argv else ""
        assert program not in RUNTIME_ESCAPE_BINARIES, f"acceptance matrix tried to require {program}: {spec.display()}"

    def guarded_run(self: CommandRunner, spec: CommandSpec, check: bool = True):
        assert_safe_spec(spec)
        if not self.dry_run:
            assert spec.argv[:1] == ("write-file",), (
                f"acceptance matrix tried to execute a host command: {spec.display()}"
            )
            assert len(spec.argv) >= 2
            assert _is_relative_to(Path(spec.argv[1]).resolve(), resolved_allowed_root)
        return original_run(self, spec, check)

    def guarded_run_streaming(self: CommandRunner, spec: CommandSpec, on_line, check: bool = True):
        assert_safe_spec(spec)
        assert self.dry_run, f"acceptance matrix tried to stream a host command: {spec.display()}"
        return original_run_streaming(self, spec, on_line, check)

    def blocked_call(*_args, **_kwargs):
        raise AssertionError("acceptance matrix tried to escape dry-run/offline mode")

    monkeypatch.setattr(CommandRunner, "run", guarded_run)
    monkeypatch.setattr(CommandRunner, "run_streaming", guarded_run_streaming)
    monkeypatch.setattr(subprocess, "run", blocked_call)
    monkeypatch.setattr(subprocess, "Popen", blocked_call)
    monkeypatch.setattr(os, "system", blocked_call)
    monkeypatch.setattr(os, "popen", blocked_call)
    monkeypatch.setattr(socket, "create_connection", blocked_call)
    monkeypatch.setattr(urllib.request, "urlopen", blocked_call)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _files_outside_project(tmp_path: Path, project_root: Path) -> list[Path]:
    resolved_project = project_root.resolve()
    outside = []
    for path in tmp_path.rglob("*"):
        if path.is_file() and not _is_relative_to(path.resolve(), resolved_project):
            outside.append(path.relative_to(tmp_path))
    return sorted(outside)


def test_cli_acceptance_matrix_runs_source_workflows_offline(
    capsys,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    monkeypatch.delenv("DISTROFORGE_LLAMA_MODEL", raising=False)
    monkeypatch.delenv("DISTROFORGE_OLLAMA_MODEL", raising=False)

    project_root = tmp_path / "acceptance-project"
    _block_runtime_escapes(monkeypatch, project_root)
    out = _run_cli(capsys, ["new", "Acceptance", str(project_root), "--from-scratch"])
    assert "Created Acceptance" in out
    project = Project.load(project_root)
    assert project.root == project_root
    assert project.source_mode == "bootstrap"

    out = _run_cli(capsys, ["plan", str(project_root)])
    assert "Validate project" in out
    assert "Rebuild ISO" in out

    out = _run_cli(capsys, ["validate", str(project_root)])
    assert "Validation OK" in out

    readiness = json.loads(_run_cli(capsys, ["readiness", str(project_root), "--json"]))
    assert readiness["status"] in {"ready", "review"}
    assert readiness["dry_run"]["commands"] == []

    dry_run = json.loads(
        _run_cli(
            capsys,
            ["dry-run-report", str(project_root), "--json", "--no-command-simulation"],
        )
    )
    assert dry_run["commands"] == []
    assert dry_run["error"] is None

    gate = json.loads(
        _run_cli(capsys, ["release-gate", str(project_root), "--json"], expected_code=2)
    )
    assert gate["status"] == "blocked"
    assert any(item["code"] == "iso" for item in gate["items"])

    drill = json.loads(_run_cli(capsys, ["publish-drill", str(project_root), "--json"]))
    assert drill["execute_signing"] is False
    assert drill["pipeline"]["status"] == "blocked"
    assert (project.output_dir / "publish" / "PUBLISH-DRILL.json").exists()

    pipeline = json.loads(_run_cli(capsys, ["release-pipeline", str(project_root), "--json"]))
    assert pipeline["status"] == "blocked"
    assert {"publish-bundle", "sign-release-final", "verify-release"} <= {
        stage["name"] for stage in pipeline["stages"]
    }

    policy = json.loads(_run_cli(capsys, ["packaging-policy", str(ROOT), "--json"]))
    assert policy["blocked"] is False
    assert policy["missing_package_data"] == []
    assert "vulndb.json" in policy["autopkgtest_policy"]["required_checks"]

    hermetic = _run_cli(
        capsys,
        ["hermetic-build-plan", str(ROOT), "--backend", "sbuild", "--suite", "unstable"],
    )
    assert "Backend: sbuild" in hermetic
    assert "Suite: unstable" in hermetic
    assert "sbuild --arch amd64 --dist unstable --no-run-lintian" in hermetic

    doctor = json.loads(
        _run_cli(capsys, ["forgeadvisor", "doctor-ai", "--backend", "offline", "--json"])
    )
    assert doctor["backend"] == "offline"
    assert any("no model, network, or cloud service" in finding["detail"] for finding in doctor["findings"])

    review = json.loads(
        _run_cli(
            capsys,
            [
                "forgeadvisor",
                "review-build",
                str(project_root),
                "--backend",
                "offline",
                "--json",
                "--no-sudo",
            ],
        )
    )
    assert review["backend"] == "offline"
    assert review["title"] == "build review for Acceptance"

    proposals = json.loads(
        _run_cli(
            capsys,
            [
                "forgeadvisor",
                "propose-fixes",
                str(project_root),
                "--backend",
                "offline",
                "--json",
                "--no-sudo",
            ],
        )
    )
    assert proposals["backend"] == "offline"
    assert proposals["status"] == "preview only - nothing is applied"

    assert _files_outside_project(tmp_path, project_root) == []


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from distroforge.ui.qt import QApplication

    return QApplication.instance() or QApplication([])


def _button_by_label(window, label: str):
    from distroforge.ui.qt import QPushButton

    matches = [button for button in window.findChildren(QPushButton) if button.text() == label]
    assert matches, f"Missing GUI button: {label}"
    return matches[0]


def test_gui_acceptance_surfaces_open_offscreen_and_route_release_actions(
    qt_app,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from distroforge.ui.main_window import MainWindow

    monkeypatch.setattr("distroforge.ui.main_window.QMessageBox.critical", lambda *_args, **_kwargs: None)
    window = MainWindow()
    assert not window.isVisible()

    for surface in ("start", "build", "artifacts", "maintainer"):
        window._open_surface(surface)
        assert window._pages.currentIndex() == window._surfaces[surface]

    for label in (
        "Plan",
        "Dry-run",
        "Release Gate",
        "Packaging Policy",
        "Hermetic Build",
        "Publish Drill",
        "Release Pipeline",
        "ForgeAdvisor",
        "FA: propose fixes",
        "FA: AI doctor",
    ):
        _button_by_label(window, label)

    for label in (
        "Release Gate",
        "Packaging Policy",
        "Hermetic Build",
        "Publish Drill",
        "Release Pipeline",
        "ForgeAdvisor",
        "FA: propose fixes",
    ):
        _button_by_label(window, label).click()

    assert "Create or open a project first." in window.logs.toPlainText()
