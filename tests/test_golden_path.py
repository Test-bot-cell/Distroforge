"""The golden path: the one chain this project runs for real, and its preconditions.

Two subjects, both of which had nothing holding them.

The workflow. Until this file, no test in the tree read a workflow at all -- grep for
``.github`` under ``tests/`` came back empty -- so every property that makes
``golden-path.yml`` a golden path rather than a file was unenforced. Deleting its
``schedule`` trigger, flipping ``--execute`` to ``--dry-run``, or moving ``boot-proof``
from ``--backend qemu`` to ``--backend auto`` would each leave a workflow that still
parses, still runs and still reports success while proving nothing, and the suite would
not have noticed any of the three. ``auto`` is the sharpest of them: it falls back to
reading the ISO's structure without booting it (core/boot_proof.py:180), so the one job
whose purpose is to watch a kernel come up would come back green having never started
QEMU.

The privilege probe. ``_validate_host_privilege`` refused any host with no tty and no
askpass helper, which is every automated host there is, and the message said sudo
"cannot authenticate" -- false wherever a NOPASSWD rule authenticates it without
asking. Nothing covered that branch in either direction: the suite was 1043 tests green
both before and after the fix.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandRunner, CommandSpec
from distroforge.core.preflight import _validate_host_privilege

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github/workflows/golden-path.yml"
CI_WORKFLOW = REPO_ROOT / ".github/workflows/ci.yml"
DEFINITION = REPO_ROOT / ".github/golden-path/reference-derivative.yaml"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(document: dict) -> dict:
    """The ``on:`` block, whatever YAML decided ``on`` means.

    YAML 1.1 resolves the bare word ``on`` to the boolean ``True``, so ``document["on"]``
    is a KeyError against the very file that clearly has one. Measured: safe_load of this
    workflow yields the key ``True``.
    """
    return document.get("on", document.get(True))  # type: ignore[arg-type]


def _scripts(document: dict) -> str:
    return "\n".join(
        step["run"]
        for job in document["jobs"].values()
        for step in job["steps"]
        if "run" in step
    )


def test_golden_path_runs_on_a_schedule_and_never_on_push() -> None:
    triggers = _triggers(_load(WORKFLOW))
    assert "schedule" in triggers, "a golden path nobody runs is a file"
    assert any(entry.get("cron") for entry in triggers["schedule"])
    # workflow_dispatch is not decoration: GitHub honours it only "if the workflow file
    # exists on the default branch", and without it the only way to exercise the path is
    # to wait for Sunday.
    assert "workflow_dispatch" in triggers
    # The rule this workflow lives under. docs/debian-canonical-compliance.md forbids
    # producing package build artifacts without explicit authorization and CONTRIBUTING.md
    # says never build to verify a change; a push trigger here would quietly repeal both.
    assert "push" not in triggers
    assert "pull_request" not in triggers


def test_golden_path_cannot_be_cancelled_by_an_ordinary_push() -> None:
    golden = _load(WORKFLOW)
    ci = _load(CI_WORKFLOW)
    # ci.yml groups by ${{ github.workflow }}-${{ github.ref }} and cancels in progress.
    # A scheduled run happens on refs/heads/main, the same ref a push to main uses, so a
    # shared group would let a push kill an hour-long build -- and a cancelled run reports
    # as "cancelled", not "failed", so the week would look quiet rather than broken.
    assert golden["concurrency"]["group"] != ci["concurrency"]["group"]
    assert golden["concurrency"]["cancel-in-progress"] is False
    assert golden["permissions"] == {"contents": "read"}
    for name, job in golden["jobs"].items():
        assert job.get("timeout-minutes"), f"{name} may not run unbounded"


def test_golden_path_executes_rather_than_plans() -> None:
    scripts = _scripts(_load(WORKFLOW))
    assert "iso-build" in scripts and "--execute" in scripts
    assert "debian-package" in scripts
    # The whole distinction between this workflow and ci.yml. Every command here has a
    # planning mode that exits 0 having built nothing, and each is one flag away.
    assert "--dry-run" not in scripts


def test_golden_path_boot_proof_boots_and_does_not_fall_back() -> None:
    scripts = _scripts(_load(WORKFLOW))
    assert "boot-proof" in scripts
    # --backend auto degrades to iso-scan when QEMU is missing or refuses
    # (core/boot_proof.py:180): structural evidence about a file, from the one step whose
    # subject is a running kernel. It has to be named, so it has to fail when absent.
    assert "--backend qemu" in scripts
    assert "--backend auto" not in scripts
    # On a BIOS host a green proof only confirms the half docs/build-pipeline.md:361 says
    # already worked, and prebuild_vm.firmware defaults to bios (core/prebuild_vm.py:24),
    # so the firmware has to be stated or the hard half goes untested.
    assert "--firmware uefi" in scripts
    assert '.proof_level == "runtime"' in scripts, "ready alone does not mean it booted"


def test_the_reference_derivative_exists_and_cannot_hang() -> None:
    scripts = _scripts(_load(WORKFLOW))
    relative = DEFINITION.relative_to(REPO_ROOT).as_posix()
    assert relative in scripts, "the workflow must build the definition this tree ships"
    assert DEFINITION.is_file()
    definition = _load(DEFINITION)
    assert definition["source_mode"] == "bootstrap", "the point is to build, not remaster"
    # QaMatrixService builds its QemuInvocation with no timeout_seconds (core/qa.py:52),
    # so CommandRunner.run gets no timeout (core/command.py:118) and a guest that never
    # reaches a login prompt runs until the job's six-hour ceiling. Both shipped examples
    # set it, which is why this definition is not one of them.
    assert "qa" not in definition


def test_the_shipped_examples_are_still_the_reason_this_definition_exists() -> None:
    # The negative control for the test above: if a future cleanup removed qa.scenarios
    # from the examples, the assertion that this definition avoids them would still pass
    # while its stated reason had quietly evaporated.
    for name in ("minimal-bootstrap.yaml", "developer-workstation.yaml"):
        example = _load(REPO_ROOT / "examples" / name)
        assert example.get("qa", {}).get("scenarios"), (
            f"examples/{name} no longer sets qa.scenarios; "
            "the comments in .github/golden-path/reference-derivative.yaml are now stale"
        )


def test_the_fields_the_workflow_asserts_on_are_the_fields_the_reports_carry(
    tmp_path: Path,
) -> None:
    """jq reads names, and Python is free to rename them.

    A renamed field makes ``jq -e`` return null and exit non-zero, so the weekly run
    fails rather than passing wrongly -- but it fails on a Sunday, in a job nobody is
    watching, about a defect that was committed on a Tuesday. These are the field paths
    golden-path.yml asserts on, checked against reports the code produces now.
    """
    from distroforge.core.boot_proof import run_boot_proof
    from distroforge.core.iso_build import run_iso_build
    from distroforge.core.packaging import build_debian_package
    from distroforge.core.project import Project

    project = Project.create("golden", tmp_path / "proj", "26.04")
    iso_report = run_iso_build(project, definition=DEFINITION).to_dict()
    for field in ("status", "execute", "output_exists", "output_size", "output_sha256"):
        assert field in iso_report, f"golden-path.yml reads .{field} of ISO-BUILD.json"

    proof = run_boot_proof(project, backend="qemu", execute=False).to_dict()
    for field in ("status", "proof_level", "selected_backend", "firmware"):
        assert field in proof, f"golden-path.yml reads .{field} of boot-proof.json"

    package = build_debian_package(REPO_ROOT).to_dict()
    for field in ("status", "execute", "build", "checks", "artifacts"):
        assert field in package, f"golden-path.yml reads .{field} of the package report"
    assert "status" in package["build"]
    assert {"name", "status", "reason"} <= set(package["checks"][0])
    # .artifacts[] | select(.kind == "deb") -- the workflow used to say .name, which no
    # artifact has.
    from distroforge.core.packaging import PackageBuildArtifact

    assert "kind" in PackageBuildArtifact.__dataclass_fields__


def test_the_workflow_accepts_the_lintian_verdict_this_package_actually_earns() -> None:
    # lintian_status returns "review required" for any tag at all, including the one
    # pedantic tag this package carries on purpose (core/packaging.py:1218), and the
    # project's rule is that review does not fail. A workflow demanding "passed" would
    # therefore fail a healthy artifact every Sunday -- the same over-gating the suite
    # caught three times when these exit statuses were first wired up.
    scripts = _scripts(_load(WORKFLOW))
    assert '.status == "passed" or .status == "review required"' in scripts
    # autopkgtest gets no such latitude: its other executed verdicts are testbed-broken,
    # test-failed and failed, and none is acceptable where the tool is installed.
    assert 'select(.name == "autopkgtest") | .status == "passed"' in scripts


def _issues(monkeypatch: pytest.MonkeyPatch, *, isatty: bool, sudo_rc: int) -> list:
    monkeypatch.delenv("DISTROFORGE_PRIVILEGE", raising=False)
    monkeypatch.delenv("SUDO_ASKPASS", raising=False)
    monkeypatch.setattr("distroforge.core.preflight.sudo_askpass_program", lambda: None)
    monkeypatch.setattr(
        "distroforge.core.preflight.sys.stdin", type("S", (), {"isatty": lambda self: isatty})()
    )

    class Runner(CommandRunner):
        def __init__(self) -> None:
            super().__init__(dry_run=False)

        @staticmethod
        def has_binary(name: str) -> bool:
            return name == "sudo"

        def run(self, spec: CommandSpec, check: bool = True):  # type: ignore[override]
            assert spec.argv == ("sudo", "-n", "true"), spec.argv
            self.history.append(spec)
            from distroforge.core.command import CommandResult

            return CommandResult(spec=spec, returncode=sudo_rc, stdout="", stderr="")

    return _validate_host_privilege(BuildOptions(), Runner(), execute=True)


def test_a_host_where_sudo_needs_no_password_is_not_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every CI runner, every provisioning script, every cron job: no terminal, no
    # graphical askpass, and a NOPASSWD rule that authenticates without asking. This was
    # an error, and the error text told the reader to install a graphical askpass helper
    # on a machine with no display.
    assert _issues(monkeypatch, isatty=False, sudo_rc=0) == []


def test_a_host_where_sudo_would_prompt_is_still_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The negative control, and the maintainer's own workstation: `sudo -n true` exits 1
    # with "interactive authentication is required" there, so the refusal has to survive.
    issues = _issues(monkeypatch, isatty=False, sudo_rc=1)
    assert [issue.code for issue in issues] == ["sudo-askpass"]


def test_the_probe_is_not_asked_of_a_dry_run_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    # A dry-run runner answers 0 to everything it is handed (core/command.py:108), so
    # asking it whether sudo needs a password would fabricate a yes -- exactly the silent
    # success this check exists to prevent.
    monkeypatch.delenv("DISTROFORGE_PRIVILEGE", raising=False)
    monkeypatch.delenv("SUDO_ASKPASS", raising=False)
    monkeypatch.setattr("distroforge.core.preflight.sudo_askpass_program", lambda: None)
    monkeypatch.setattr(
        "distroforge.core.preflight.sys.stdin", type("S", (), {"isatty": lambda self: False})()
    )
    runner = CommandRunner(dry_run=True)
    issues = _validate_host_privilege(BuildOptions(), runner, execute=True)
    assert [issue.code for issue in issues] == ["sudo-askpass"]
    assert runner.history == [], "the probe must not be handed to a runner that fakes success"


def test_sudo_dash_n_is_the_question_this_host_answers_no_to() -> None:
    """The probe against the real sudo, not a fake.

    Measured on the maintainer's workstation: `sudo -n true` exits non-zero with
    "interactive authentication is required". It never prompts, which is what makes it
    safe to call from a preflight check, and this asserts that rather than trusting it.
    """
    if not CommandRunner.has_binary("sudo"):
        pytest.skip("no sudo on this host")
    completed = subprocess.run(
        ["sudo", "-n", "true"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode in {0, 1}, completed.stderr
    if completed.returncode == 0:
        # A host with a NOPASSWD rule, which is the case the fix exists for.
        assert completed.stdout == ""
    else:
        assert "password" in completed.stderr.lower() or "authentication" in completed.stderr.lower()


def test_the_workflow_is_the_only_one_that_builds() -> None:
    # ci.yml runs on every push. If it ever grew a real build, the rule that a build is
    # explicit would be repealed by a file rather than by a decision.
    ci_scripts = _scripts(_load(CI_WORKFLOW))
    assert "dpkg-buildpackage" not in ci_scripts
    assert "--execute" not in ci_scripts
    workflows = sorted(p.name for p in (REPO_ROOT / ".github/workflows").glob("*.yml"))
    assert workflows == ["ci.yml", "golden-path.yml"], (
        "a new workflow file needs a decision about whether it may build, "
        f"and this test is where that decision is recorded: {workflows}"
    )
