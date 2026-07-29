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

And the gap those two left. Every check here parses the workflow with ``yaml.safe_load``
and asks what it says, which is a strictly weaker question than whether GitHub will run
it: the first push of ``golden-path.yml`` produced a run with no jobs, no log and "This
run likely failed because of a workflow file issue", because a job-level ``env:`` named
the ``runner`` context. Fifteen sabotages of that same file were each caught by a test,
and all fifteen stepped over a file Actions would not load at all. Valid YAML is not a
valid workflow, so the shape of what may name a context is now checked too.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandRunner, CommandSpec
from distroforge.core.packaging import debian_changelog_suite
from distroforge.core.preflight import _validate_host_privilege
from distroforge.core.releases import get_release, load_releases

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github/workflows/golden-path.yml"
CI_WORKFLOW = REPO_ROOT / ".github/workflows/ci.yml"
DEFINITION = REPO_ROOT / ".github/golden-path/reference-derivative.yaml"
MAINTAINER_KEY = REPO_ROOT / ".github/golden-path/maintainer-signing-key.asc"
MAINTAINER_KEY_SHA256 = (
    "a1b6ee870e2708571bc43cf42d12a0c315c58dd1dad7760a27f660db3162e0ab"
)
MAINTAINER_FINGERPRINT = "93D942241BECDD422606C36C4C0D75219B5506CF"

# Quoted from GitHub's context-availability table, the row for jobs.<job_id>.env:
# "github, needs, strategy, matrix, vars, secrets, inputs". The row one level down,
# jobs.<job_id>.steps.<step_id>.env, adds "job, runner, env, steps" -- the four that
# describe a step already running. Naming one of those above a step does not degrade to
# an empty string at run time; Actions refuses the file, and refuses it whole.
JOB_LEVEL_CONTEXTS = frozenset({"github", "needs", "strategy", "matrix", "vars", "secrets", "inputs"})
FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
FULL_FINGERPRINT = re.compile(r"[0-9A-F]{40}|[0-9A-F]{64}")


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


def _uses_values(node: object) -> list[object]:
    """Every GitHub Actions ``uses`` value nested below ``node``."""
    if isinstance(node, dict):
        found = [value for key, value in node.items() if key == "uses"]
        return found + [
            reference
            for value in node.values()
            for reference in _uses_values(value)
        ]
    if isinstance(node, list):
        return [reference for item in node for reference in _uses_values(item)]
    return []


def _mutable_action_reference(reference: object) -> bool:
    """Whether a remote action or reusable workflow can move without a source change."""
    if not isinstance(reference, str):
        return True
    if reference.startswith(("./", "docker://")):
        return False
    _repository, separator, revision = reference.rpartition("@")
    return not separator or FULL_COMMIT_SHA.fullmatch(revision) is None


def test_every_remote_action_is_pinned_to_a_full_commit_sha() -> None:
    offenders = {
        path.name: [
            reference
            for reference in _uses_values(_load(path))
            if _mutable_action_reference(reference)
        ]
        for path in sorted(
            path
            for path in (REPO_ROOT / ".github/workflows").iterdir()
            if path.suffix in {".yml", ".yaml"}
        )
    }
    offenders = {path: references for path, references in offenders.items() if references}

    assert offenders == {}, (
        "remote actions and reusable workflows must use an immutable 40-character "
        f"commit SHA, never a movable tag, branch, or abbreviated SHA: {offenders}"
    )


def test_the_action_reference_guard_rejects_movable_and_abbreviated_refs() -> None:
    assert _mutable_action_reference("actions/checkout@v4")
    assert _mutable_action_reference("actions/checkout@main")
    assert _mutable_action_reference("actions/checkout@11d5960")
    assert _mutable_action_reference({"actions/checkout": "v4"})
    assert not _mutable_action_reference(
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
    )
    assert not _mutable_action_reference("./.github/actions/local")


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


def _contexts_named(node: object) -> set[str]:
    """Every context a ``${{ ... }}`` expression anywhere under ``node`` refers to."""
    if isinstance(node, dict):
        return set().union(*(_contexts_named(value) for value in node.values()), set())
    if isinstance(node, list):
        return set().union(*(_contexts_named(item) for item in node), set())
    if not isinstance(node, str):
        return set()
    named: set[str] = set()
    for expression in re.findall(r"\$\{\{(.*?)\}\}", node, flags=re.DOTALL):
        # Quoted literals hold dots of their own: hashFiles('setup.cfg') would otherwise
        # read as a context named "setup", and a check that fails on ci.yml instead of on
        # the mistake it exists for is worse than no check.
        named.update(re.findall(r"([A-Za-z_][A-Za-z0-9_-]*)\s*\.", re.sub(r"'[^']*'", "", expression)))
    return named


def test_the_context_extractor_sees_the_expression_that_broke_the_first_push() -> None:
    # Without this, the guard below could pass by finding nothing at all.
    assert _contexts_named({"env": {"DERIVATIVE_ROOT": "${{ runner.temp }}/x"}}) == {"runner"}
    assert _contexts_named("${{ github.workflow }}-${{ github.ref }}") == {"github"}
    assert _contexts_named("${{ matrix.python-version }}") == {"matrix"}
    assert _contexts_named("${{ hashFiles('setup.cfg') }}") == set()
    assert _contexts_named({"runs-on": "ubuntu-latest", "timeout-minutes": 90}) == set()


def test_no_job_level_key_names_a_context_that_only_exists_inside_a_step() -> None:
    """Ask of every workflow the question yaml.safe_load cannot ask.

    Scope is deliberately the job mapping minus its steps: those are the rows quoted
    above, measured against a real refusal, rather than a transcription of the whole
    table. A step may name anything the table allows it.
    """
    for workflow in sorted((REPO_ROOT / ".github/workflows").glob("*.yml")):
        for name, job in _load(workflow)["jobs"].items():
            named = _contexts_named({key: value for key, value in job.items() if key != "steps"})
            assert named <= JOB_LEVEL_CONTEXTS, (
                f"{workflow.name}: job {name} names {sorted(named - JOB_LEVEL_CONTEXTS)} "
                "outside its steps, which makes the whole file unloadable"
            )


def test_the_derivative_root_is_defined_before_it_is_used() -> None:
    scripts = [step.get("run", "") for step in _load(WORKFLOW)["jobs"]["reference-derivative"]["steps"]]
    defines = [i for i, s in enumerate(scripts) if "DERIVATIVE_ROOT=" in s and "GITHUB_ENV" in s]
    uses = [i for i, s in enumerate(scripts) if "$DERIVATIVE_ROOT" in s]
    assert defines, "no step writes DERIVATIVE_ROOT to GITHUB_ENV; a job-level env: cannot"
    assert uses, "the build no longer reads it"
    # GITHUB_ENV reaches the steps after the one that writes it, never the one writing it
    # nor any above. Reordered the other way, the build would run against an empty path.
    assert defines[0] < uses[0]


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
    bootstrap = definition.get("bootstrap", {})
    assert bootstrap.get("archive_keyring") == (
        "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
    )
    assert re.fullmatch(
        r"[0-9a-f]{64}",
        str(bootstrap.get("archive_keyring_sha256", "")),
    )
    fingerprints = bootstrap.get("archive_signer_fingerprints", [])
    assert fingerprints and len(fingerprints) == len(set(fingerprints))
    assert all(FULL_FINGERPRINT.fullmatch(str(value)) for value in fingerprints)
    # QaMatrixService builds its QemuInvocation with no timeout_seconds (core/qa.py:52),
    # so CommandRunner.run gets no timeout (core/command.py:118) and a guest that never
    # reaches a login prompt runs until the job's six-hour ceiling. Both shipped examples
    # set it, which is why this definition is not one of them.
    assert "qa" not in definition


def test_golden_path_verifies_the_builder_with_the_pinned_public_key(
    tmp_path: Path,
) -> None:
    scripts = _scripts(_load(WORKFLOW))
    workflow = _load(WORKFLOW)
    job_env = workflow["jobs"]["reference-derivative"]["env"]

    assert job_env.get("PYTHONDONTWRITEBYTECODE") == "1"
    assert "pip install --no-compile -e ." in scripts
    assert "find distroforge" in scripts and "__pycache__" in scripts
    assert f"{MAINTAINER_KEY_SHA256}  $KEY" in scripts
    assert f'test "$FINGERPRINT" = "{MAINTAINER_FINGERPRINT}"' in scripts
    assert "git verify-commit HEAD" in scripts
    assert 'echo "GNUPGHOME=$GIT_GNUPGHOME" >> "$GITHUB_ENV"' in scripts

    key_bytes = MAINTAINER_KEY.read_bytes()
    assert hashlib.sha256(key_bytes).hexdigest() == MAINTAINER_KEY_SHA256
    assert b"BEGIN PGP PUBLIC KEY BLOCK" in key_bytes
    assert b"PRIVATE KEY" not in key_bytes

    gnupg_home = tmp_path / "gnupg"
    gnupg_home.mkdir(mode=0o700)
    result = subprocess.run(
        (
            "gpg",
            "--batch",
            "--homedir",
            str(gnupg_home),
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
            str(MAINTAINER_KEY),
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    fingerprints = [
        fields[9]
        for line in result.stdout.splitlines()
        if (fields := line.split(":"))[0] == "fpr"
    ]
    assert fingerprints[0] == MAINTAINER_FINGERPRINT


def test_reference_derivative_declares_disjoint_external_source_policies() -> None:
    bootstrap = _load(DEFINITION)["bootstrap"]
    policies = bootstrap.get("source_policies", [])

    assert len(policies) == 3
    assert len({policy["policy_id"] for policy in policies}) == len(policies)
    assert all(policy["base_uri"].startswith("https://") for policy in policies)
    suites = [suite for policy in policies for suite in policy["suites"]]
    assert len(suites) == len(set(suites))
    assert set(suites) == {
        "resolute",
        "resolute-updates",
        "resolute-backports",
        "resolute-security",
    }
    expected_signers = set(bootstrap["archive_signer_fingerprints"])
    expected_keyring = bootstrap["archive_keyring_sha256"]
    for policy in policies:
        assert set(policy["signer_fingerprints"]) == expected_signers
        assert policy["keyring_sha256"] == [expected_keyring]
        assert policy["max_release_age_seconds"] > 0


def test_golden_path_asserts_the_offline_package_and_run_closure() -> None:
    scripts = _scripts(_load(WORKFLOW))

    assert "release-gate" in scripts
    assert "--definition .github/golden-path/reference-derivative.yaml" in scripts
    for code in (
        "package-inputs",
        "provenance",
        "source-trust",
        "iso",
        "sha256",
        "boot-proof",
    ):
        assert f'"{code}"' in scripts
    publish_line = next(
        line
        for line in scripts.splitlines()
        if "python -m distroforge publish-bundle" in line
    )
    assert "|| true" not in publish_line


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
    # Answer the "is sudo installed" question here instead of letting the host answer it.
    # core/preflight.py:164 returns a "privilege" issue before ever reaching the askpass
    # branch when the binary is missing, and ci.yml's distro-dependencies container has no
    # sudo in it -- so this test passed on the maintainer's workstation and failed in CI on
    # a fact about the image rather than about the code. dry_run stays real, since that is
    # the whole subject.
    monkeypatch.setattr(runner, "has_binary", lambda name: name == "sudo")
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


def test_every_verdict_is_printed_before_it_is_asserted() -> None:
    """A step must say what it found before it refuses it.

    Both assertion steps in the first real run of this workflow hid the thing that
    explained the failure. The package leg ended with a ``jq -r`` printing every
    check's status and reason -- last, so under ``sh -e`` it only ran on the happy
    path, and the run that stopped at ``.status == "built" or "review required"``
    never printed the ``autopkgtest: test-failed`` behind it. Reading the verdict
    meant downloading the artifact. The ISO leg was worse: its report did not exist,
    so the log accused a missing file.

    The rule, checked here rather than remembered: in any script that both prints with
    ``jq -r`` and asserts with ``jq -e``, the printing comes before the first assertion
    that can abort the step. A ``jq -e`` guarding an ``||`` cannot abort -- that is the
    idiom the ISO leg uses to print a failure before asserting there was none -- so it
    does not count, and the check would be wrong rather than strict if it did.
    """
    for name, job in _load(WORKFLOW)["jobs"].items():
        for step in job["steps"]:
            # Join backslash continuations so one command is one line, which is what
            # decides whether an "||" belongs to the jq -e in front of it.
            script = step.get("run", "").replace("\\\n", " ")
            if "jq -r" not in script or "jq -e" not in script:
                continue
            lines = script.splitlines()
            reports = [i for i, line in enumerate(lines) if "jq -r" in line]
            aborts = [i for i, line in enumerate(lines) if "jq -e" in line and "||" not in line]
            assert aborts, f"{name}: step {step.get('name')!r} asserts nothing that can fail"
            assert reports[0] < aborts[0], (
                f"{name}: step {step.get('name')!r} asserts before it reports, so a "
                "failing run prints the assertion and not the reason for it"
            )


# Images whose whole meaning is "whatever is current". Each one names a different suite
# depending on the day it is pulled, which is the opposite of what a package built for a
# named suite needs.
_FLOATING_IMAGES = ("ubuntu:devel", "ubuntu:rolling", "ubuntu:latest")


def _containers() -> list[tuple[str, str, str]]:
    """Every (workflow, job, image) that builds inside a container image."""
    found: list[tuple[str, str, str]] = []
    for path in (WORKFLOW, CI_WORKFLOW):
        for name, job in _load(path)["jobs"].items():
            container = job.get("container")
            image = container if isinstance(container, str) else (container or {}).get("image", "")
            if image:
                found.append((path.name, name, image))
    return found


def test_no_job_builds_against_whatever_happens_to_be_current() -> None:
    """The suite a job builds in has to be named, not inherited from a moving tag.

    Measured in the golden path's first real run, not inferred: the leg that built,
    linted and autopkgtested the package ran ``container: ubuntu:devel`` and its log
    reads ``archive.ubuntu.com/ubuntu stonking InRelease``. ``devel`` is whatever is in
    development, so once 26.04 released that image became 26.10 and the job silently
    started answering a question about the *next* distribution -- while two comments,
    here and in ci.yml, said it was the suite debian/changelog targets.

    Nothing could have caught that, because the label and the changelog were never
    compared. This is that comparison.
    """
    containers = _containers()
    assert containers, (
        "both workflows lost their containers, and with them the only job that tests "
        "against the distribution's own Python rather than setup-python's"
    )
    for workflow, job, image in containers:
        assert image not in _FLOATING_IMAGES, (
            f"{workflow}: job {job!r} builds in {image}, which names no suite -- it names "
            "whatever Ubuntu is developing on the day the run happens"
        )


def test_every_container_is_the_suite_debian_changelog_targets() -> None:
    """And the named suite is the one this source is packaged for.

    ``debian_changelog_suite`` is asked rather than the top stanza read, for the reason
    that function documents: between releases the top stanza is UNRELEASED and names no
    target. It is the same answer ``lintian_vendor_for_suite`` is fed, so a package can
    no longer be built on one suite and graded against another's profile.
    """
    suite = debian_changelog_suite(REPO_ROOT)
    assert suite, "debian/changelog names no target suite, so no image can be checked against it"
    versions = {release.codename: version for version, release in load_releases().items()}
    assert suite in versions, (
        f"debian/changelog targets {suite!r}, which distroforge/data/releases.toml does "
        "not know -- the registry, the changelog and the CI image are one fact in three "
        "files and this is where they are held together"
    )
    accepted = {f"ubuntu:{versions[suite]}", f"ubuntu:{suite}"}
    for workflow, job, image in _containers():
        assert image in accepted, (
            f"{workflow}: job {job!r} builds in {image} while debian/changelog targets "
            f"{suite}; one of {sorted(accepted)} names that suite"
        )


def _runners() -> list[tuple[str, str, object]]:
    """Every (workflow, job, runs-on) across both workflows."""
    return [
        (path.name, name, job.get("runs-on"))
        for path in (WORKFLOW, CI_WORKFLOW)
        for name, job in _load(path)["jobs"].items()
    ]


def test_no_job_runs_on_a_floating_runner_label() -> None:
    """The sibling of the container gate, for the host rather than the image.

    ``ubuntu-latest`` is whatever GitHub currently promotes, which is an older LTS, and
    five jobs across the two workflows took it. This project's development cycle is
    resolute, so those jobs were exercising another release's mmdebstrap, apt, dpkg and
    python3 against a resolute codebase -- and the first real golden-path run did exactly
    that: a 2024 archive and ``mmdebstrap 1.4.3-6`` asked to assemble a 2026 suite.

    The container gate above could not catch it. Two of the five jobs have no container at
    all, and for the other two the host label and the image were never compared with each
    other. This is the missing comparison, and it is deliberately about the *label*:
    checking the suite at run time is the job of the step that reads /etc/os-release, and
    a reviewer reading the YAML has to be able to see it too.
    """
    runners = _runners()
    assert runners, "both workflows lost their jobs"
    for workflow, job, label in runners:
        assert isinstance(label, str), (
            f"{workflow}: job {job!r} has runs-on={label!r}; a matrix or list of labels "
            "here would slip past this gate, so state one label"
        )
        assert label not in {"ubuntu-latest", "ubuntu-rolling", "ubuntu-devel"}, (
            f"{workflow}: job {job!r} runs on {label!r}, which names no release -- it "
            "names whatever GitHub promotes on the day the run happens"
        )


def test_every_runner_is_the_release_debian_changelog_targets() -> None:
    """And the named label is the release this source is packaged for: resolute.

    Held to the changelog rather than to a literal, exactly as the container gate is, so
    the runner label, the container image, distroforge/data/releases.toml and
    debian/changelog stay one fact instead of four copies of it.
    """
    suite = debian_changelog_suite(REPO_ROOT)
    versions = {release.codename: version for version, release in load_releases().items()}
    assert suite in versions, f"debian/changelog targets {suite!r}, unknown to releases.toml"
    expected = f"ubuntu-{versions[suite]}"
    for workflow, job, label in _runners():
        assert label == expected, (
            f"{workflow}: job {job!r} runs on {label!r} while debian/changelog targets "
            f"{suite}; {expected} names that release"
        )


def test_the_runner_is_the_suite_the_derivative_bootstraps() -> None:
    """The ISO leg's runner image must be the release it asks mmdebstrap for.

    The first run bootstrapped resolute with a toolchain inherited from a floating
    ``ubuntu-latest``: its log reads a 2024 archive and ``mmdebstrap 1.4.3-6``, asked to
    assemble a suite from 2026. It exited 0 with a rootfs that had ``env`` and no
    ``apt-get``, and the build died five phases later inside the chroot. Resolute (26.04)
    is this project's development cycle; every runner label is pinned to it.

    Two labels, one floating and one fixed, never compared -- the same defect as the
    container above. Both halves are checked: the label here, so a reviewer sees it, and
    ``/etc/os-release`` against the registry at run time, because a preview label can be
    withdrawn and ``-latest`` migrates on GitHub's schedule.
    """
    job = _load(WORKFLOW)["jobs"]["reference-derivative"]
    release = job.get("env", {}).get("DERIVATIVE_RELEASE", "")
    assert release, (
        "the job declares no DERIVATIVE_RELEASE, so the release it builds is a literal "
        "somewhere in its steps and nothing can compare it with runs-on"
    )
    get_release(release)  # raises if the registry has never heard of it
    assert job["runs-on"] == f"ubuntu-{release}", (
        f"the derivative bootstraps {release} on {job['runs-on']!r}, so its mmdebstrap, "
        "apt and dpkg are another release's"
    )
    creations = [step for step in job["steps"] if "distroforge new" in step.get("run", "")]
    assert creations, "no step creates the project any more"
    for step in creations:
        assert "$DERIVATIVE_RELEASE" in step["run"], (
            "the release is a literal in this step and a literal in runs-on, which is two "
            "copies of one fact: pass $DERIVATIVE_RELEASE"
        )
    scripts = _scripts(_load(WORKFLOW))
    assert "releases.toml" in scripts and "VERSION_CODENAME" in scripts, (
        "nothing compares the image the job is running on with the release it builds, so "
        "a migrated label would be found again by a broken build rather than by a step"
    )
    assert "debian_changelog_suite" in scripts, (
        "nothing compares the container with debian/changelog either"
    )
