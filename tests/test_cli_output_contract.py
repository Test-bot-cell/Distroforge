"""One output contract for every command that advertises `--json`.

`--json` exists so another program can read the answer. That only works if the shape of
what lands on stdout is the same for every command, and it was not: the flag was accepted
and ignored by one command, an English sentence was concatenated onto the JSON of another,
two ended without a trailing newline and one ended with two. Each of those is invisible to
a human reading the terminal and fatal to `jq`, a checksum over an archived report, or a
golden-file comparison.

The contract asserted here, in both modes:

- stdout ends with exactly one newline;
- with `--json`, what precedes it parses as JSON, and nothing else is on stdout.

Advisories for humans go to stderr. That is what `livefs-iso-build` does with its
"pass --write" hint, which used to be appended to the document.

The commands are enumerated from the parser, not from a hand-written list, so a new
`--json` command joins these tests by existing. One is not exercised and says why; the
test that names it fails if that set changes, which is the only way an exclusion stays a
decision instead of becoming a habit.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json

import pytest

from distroforge import cli

# hermetic-release-bundle refuses to run until the release artifacts it bundles exist on
# disk, which means a real dpkg-buildpackage. Building is not something a test does.
NOT_EXERCISED = {
    "hermetic-release-bundle": "needs a built .deb on disk, so it cannot run without a build",
}

# Commands whose positional arguments are not a project root. Formatted against the
# context built by the `workspace` fixture. Where a command wants a file of a kind this
# test cannot produce, it gets a stand-in of the wrong format on purpose: the command then
# reports the problem, and reporting it is the output path under test.
EXTRA_ARGS: dict[str, tuple[str, ...]] = {
    "buildinfo-report": ("{profile}",),
    "capture": ("{tmp}",),
    "capture-diff": ("{profile}",),
    "evidence-verify": ("{drill}",),
    "live-build-plan": ("{profile}", "--output-dir", "{unique}"),
    "livefs-iso-build": ("{profile}", "--work-dir", "{unique}", "--dest", "{unique}.iso"),
    "livefs-iso-plan": ("{profile}", "--work-dir", "{unique}", "--dest", "{unique}.iso"),
    "new": ("newborn", "{unique}"),
    "publish-drill-diff": ("{drill}", "{drill}"),
    "qemu-smoke-plan": ("--iso", "{iso}"),
    "release-readiness": ("--iso", "{iso}", "--output-dir", "{unique}"),
    "upgrade-media": ("--to", "26.10"),
    "wizard": ("guided", "{unique}"),
}


def _json_commands() -> dict[str, argparse.ArgumentParser]:
    parser = cli.build_parser()
    subparsers = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    return {
        name: sub
        for name, sub in subparsers.choices.items()
        if "--json" in {option for action in sub._actions for option in action.option_strings}
    }


def _run(argv: list[str]) -> tuple[str, str]:
    """Run one command in-process and return (stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        with contextlib.suppress(SystemExit):
            cli.main(argv)
    return out.getvalue(), err.getvalue()


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    root = tmp_path_factory.mktemp("contract")
    project = root / "project"
    _run(["new", "contract", str(project)])

    iso = root / "stand-in.iso"
    iso.write_bytes(b"\0" * 64)

    # A real capture profile and a real publish drill, so the commands that take one are
    # exercised against the shape they expect rather than against a refusal.
    profile = root / "captured.yaml"
    _run(["capture", str(root), "--output", str(profile)])
    drill = root / "drill.json"
    drill_out, _ = _run(["publish-drill", str(project), "--json"])
    drill.write_text(drill_out, encoding="utf-8")

    return {
        "root": str(project),
        "tmp": str(root),
        "iso": str(iso),
        "profile": str(profile),
        "drill": str(drill),
        "scratch": str(root / "scratch"),
    }


def _argv(command: str, sub: argparse.ArgumentParser, ctx: dict[str, str], mode: str) -> list[str]:
    unique = f"{ctx['scratch']}-{command}-{mode}"
    if command in EXTRA_ARGS:
        extra = [
            item.format(**ctx, unique=unique) for item in EXTRA_ARGS[command]
        ]
    else:
        positionals = [
            action
            for action in sub._actions
            if not action.option_strings and action.dest != "help"
        ]
        extra = []
        for action in positionals:
            if action.dest == "root":
                extra.append(ctx["root"])
            elif action.nargs not in ("*", "?"):
                pytest.fail(
                    f"{command} takes the positional {action.dest!r}, which this test does "
                    "not know how to supply: add it to EXTRA_ARGS or to NOT_EXERCISED"
                )
    return [command, *extra, *(["--json"] if mode == "json" else [])]


def test_the_tables_account_for_every_json_command():
    commands = set(_json_commands())
    unknown = (set(EXTRA_ARGS) | set(NOT_EXERCISED)) - commands
    assert not unknown, f"tables name commands that no longer accept --json: {sorted(unknown)}"
    assert set(NOT_EXERCISED) == {"hermetic-release-bundle"}, (
        "the set of commands this contract does not cover has changed; every entry needs a "
        "reason that is not 'it was failing'"
    )


def test_the_contract_covers_the_whole_surface():
    # A floor, so the tables cannot quietly stop exercising commands. 49 accept --json and
    # exactly one is excluded.
    assert len(_json_commands()) - len(NOT_EXERCISED) >= 48


@pytest.mark.parametrize("command", sorted(set(_json_commands()) - set(NOT_EXERCISED)))
def test_json_output_is_one_json_document_and_one_trailing_newline(command, workspace):
    sub = _json_commands()[command]
    stdout, _stderr = _run(_argv(command, sub, workspace, "json"))

    assert stdout, f"{command} --json wrote nothing to stdout"
    assert stdout.endswith("\n"), f"{command} --json does not end with a newline"
    assert not stdout.endswith("\n\n"), f"{command} --json ends with a blank line"

    body = stdout[:-1]
    try:
        json.loads(body)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"{command} --json did not print JSON ({exc}); tail was {body[-70:]!r}"
        ) from exc


@pytest.mark.parametrize("command", sorted(set(_json_commands()) - set(NOT_EXERCISED)))
def test_text_output_ends_with_exactly_one_newline(command, workspace):
    sub = _json_commands()[command]
    stdout, _stderr = _run(_argv(command, sub, workspace, "text"))

    assert stdout, f"{command} wrote nothing to stdout"
    assert stdout.endswith("\n"), f"{command} does not end with a newline"
    assert not stdout.endswith("\n\n"), f"{command} ends with a blank line"


def test_the_pass_write_advisory_is_on_stderr_not_in_the_document(workspace):
    # The concrete case that motivated the rule: this sentence used to be concatenated
    # onto the JSON, so `livefs-iso-build --json | jq` failed on a run that exited 0.
    argv = _argv("livefs-iso-build", _json_commands()["livefs-iso-build"], workspace, "json")
    stdout, stderr = _run(argv)

    assert "Pass --write" in stderr
    assert "Pass --write" not in stdout
    json.loads(stdout)
