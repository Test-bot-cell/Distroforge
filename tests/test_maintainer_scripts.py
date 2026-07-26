"""The packaging shell scripts, checked the way nothing checked them before.

DistroForge shipped a 707-byte ``python3 -c`` payload in ``debian/distroforge.postinst``
from 0.3.4-4 to 0.3.5-2. It raised ``SyntaxError`` on its fifth line, every time, and
three layers hid it: ``>/dev/null 2>&1`` on the invocation, ``if ! runuser ...; then
return 0`` around it, and ``|| true`` at the call site. The changelog announced a
feature that had never once executed.
"""

from __future__ import annotations

import functools
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "tools/check-maintainer-scripts.py"
# The payload the shipped package carried, verbatim from debian/distroforge.postinst
# at 0.3.5-2, down to the literal backslashes the single quotes handed to Python.
SHIPPED_POSTINST_PAYLOAD = (
    "import ast, subprocess; \\\n"
    'desktop_entry="distroforge.desktop"; \\\n'
    "try: \\\n"
    "    raw=subprocess.check_output([1], text=True); \\\n"
    "except Exception: \\\n"
    "    raise SystemExit(0)"
)


@functools.cache
def _gate():
    # A hyphenated filename is not an importable module name, so load it by path. The
    # module has to land in sys.modules before it executes: dataclasses resolves the
    # postponed annotations of a frozen dataclass through sys.modules[cls.__module__].
    name = "check_maintainer_scripts"
    spec = importlib.util.spec_from_file_location(name, GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_the_gate_exists_and_is_executable() -> None:
    assert GATE.is_file()
    assert GATE.stat().st_mode & 0o111


def test_packaging_scripts_are_discovered_without_a_brace_glob() -> None:
    """``debian/*.{postinst,prerm,postrm}`` is shell syntax and matches nothing here.

    Path.glob reads the braces literally, so a gate written that way scans zero files
    and reports success. This asserts the discovery actually returns something.
    """
    gate = _gate()

    scripts = gate.packaging_scripts(ROOT)
    braced = sorted((ROOT / "debian").glob("*.{postinst,prerm,postrm}"))

    assert braced == []
    assert len(scripts) >= gate.MINIMUM_SCRIPTS
    assert (ROOT / "debian/tests/smoke") in scripts


def test_every_embedded_payload_compiles() -> None:
    gate = _gate()

    report = gate.check(ROOT)

    assert report.problems == [], report.render_text()
    # Anti-vacuity, both floors: a clean report over nothing learned nothing.
    assert len(report.scripts) >= gate.MINIMUM_SCRIPTS
    assert len(report.payloads) >= gate.MINIMUM_PAYLOADS


def test_the_gate_reads_heredocs_so_it_does_not_cancel_itself() -> None:
    """A ``-c``-only extractor stops working the moment the payload is fixed properly.

    The correct spelling of a multi-line payload in a shell script is a heredoc, so
    a gate that only understands ``-c`` retires itself on the day its own finding is
    repaired -- and reports green over an empty corpus from then on.
    """
    gate = _gate()

    payloads = gate.check(ROOT).payloads
    forms = {payload.form for payload in payloads}

    assert any(form.startswith("heredoc") for form in forms)


def test_the_gate_rejects_the_payload_the_package_actually_shipped(tmp_path: Path) -> None:
    gate = _gate()
    script = tmp_path / "debian/distroforge.postinst"
    script.parent.mkdir(parents=True)
    script.write_text(f"#!/bin/sh\nset -eu\npython3 -c '{SHIPPED_POSTINST_PAYLOAD}'\n", encoding="utf-8")

    report = gate.check(tmp_path)

    assert len(report.payloads) == 1
    assert any("invalid syntax" in problem for problem in report.problems)
    assert not report.ok


def test_the_gate_rejects_a_maintainer_script_that_reaches_into_a_user_session(tmp_path: Path) -> None:
    """Decision of this work package, made executable.

    dpkg runs maintainer scripts as root with no way to ask the user anything and no
    record of what they changed, so ``org.gnome.shell favorite-apps`` -- the user's
    own dock, under the user's own /home -- is not theirs to write. Which is also why
    the package needs no postrm: it now creates no state outside its file manifest,
    and a root postrm must not delete the per-user config the GUI wrote.
    """
    gate = _gate()
    script = tmp_path / "debian/distroforge.postinst"
    script.parent.mkdir(parents=True)
    script.write_text(
        "#!/bin/sh\nset -eu\nrunuser -u someone -- /usr/bin/gsettings set org.gnome.shell x y\n",
        encoding="utf-8",
    )

    problems = gate.check(tmp_path).problems

    assert any("absolute path" in problem for problem in problems)
    assert any("user session" in problem for problem in problems)


def test_no_maintainer_script_mutates_a_user_session() -> None:
    gate = _gate()

    offenders = [
        str(script)
        for script in gate.packaging_scripts(ROOT)
        if script.parts[:2] != ("debian", "tests")
        for token in gate._SESSION_REACH
        if token in (ROOT / script).read_text(encoding="utf-8")
    ]

    assert offenders == []


def test_the_gate_runs_clean_as_a_command() -> None:
    result = subprocess.run(
        (sys.executable, str(GATE), str(ROOT)),
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Problems: none" in result.stdout


@pytest.mark.parametrize(
    ("script", "expected"),
    (
        ("#!/bin/sh\npython3 -c 'import os\\nprint(os)'\n", "-c '...'"),
        ('#!/bin/sh\npython3 -c "import os"\n', '-c "..."'),
        ("#!/bin/sh\npython3 - <<'PY'\nimport os\nPY\n", "heredoc <<PY"),
        ("#!/bin/sh\npython3 - <<PY\nimport os\nPY\n", "heredoc <<PY"),
    ),
)
def test_both_payload_spellings_are_extracted(tmp_path: Path, script: str, expected: str) -> None:
    gate = _gate()
    path = tmp_path / "debian/tests/smoke"
    path.parent.mkdir(parents=True)
    path.write_text(script, encoding="utf-8")

    payloads = gate.check(tmp_path).payloads

    assert [payload.form for payload in payloads] == [expected]


def test_a_double_quoted_payload_is_unescaped_like_the_shell_would(tmp_path: Path) -> None:
    """Single and double quotes do not deliver the same bytes to the interpreter.

    Inside single quotes the shell hands every byte through untouched. Inside double
    quotes it removes the backslash-newline itself and collapses ``\\\\``, ``\\"``,
    ``\\$`` and ``\\```; a gate that compiled the raw text would be checking a payload
    the interpreter never receives.
    """
    gate = _gate()
    continued = tmp_path / "debian/distroforge.postinst"
    continued.parent.mkdir(parents=True)
    continued.write_text('#!/bin/sh\npython3 -c "import os; \\\nprint(os)"\n', encoding="utf-8")

    assert gate.check(tmp_path).payloads[0].source == "import os; print(os)"

    escaped = tmp_path / "debian/tests/smoke"
    escaped.parent.mkdir(parents=True)
    escaped.write_text('#!/bin/sh\npython3 -c "print(\\"a\\\\nb\\")"\n', encoding="utf-8")
    payloads = {payload.script.name: payload.source for payload in gate.check(tmp_path).payloads}

    assert payloads["smoke"] == 'print("a\\nb")'
