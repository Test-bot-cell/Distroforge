# Contributing to DistroForge

## Verifying your work

```
make check
```

That is the whole contract: `ruff check .`, `mypy distroforge/`, `pytest -q`,
`shellcheck` over the Debian packaging scripts, and `compile()` over the `python3`
payloads embedded in them. It needs no network and installs nothing. Run it before
every commit; CI runs the same five.

Prefer `make check` over calling `pytest` yourself, and not only for the coverage:
the Makefile exports `PYTHONDONTWRITEBYTECODE=1`. Python invalidates a `.pyc` on the
source's whole-second mtime and byte size, so editing a line to the *same length*
inside one second — which is exactly what happens while checking that a test can
fail — leaves a stale cache in place and the run answers about code you no longer
have. `make clean-pyc` clears it if you have already been bitten.

`pre-commit install` wires the fast subset into your commits. The hook file is
deliberately all `repo: local` with `language: system` or `language: pygrep`, so
it never clones a repository and never provisions a virtualenv — a single
`repo: https://` entry or one `language: python` hook would break that.

## Never build to verify a change

`make check` does not build a `.deb` or an ISO, and neither should you in order to
prove a change works. Package and ISO builds are explicit, deliberate acts: they
take minutes, they need privilege, and they write outside the tree. Every check in
this project is designed to be meaningful without one — dry-run plans are compared
against golden argv, and the few checks that drive a real external tool (`gpg`,
`sha256sum`) stay offline, rootless and sub-second.

If you believe a defect can only be shown by a real build, say so instead of
building: that is a gap in the test design, and naming it is more useful than a
one-off manual run.

## The four non-negotiable pillars

Each is a contract document, not a guideline, and each is backed by tests that
fail when the code drifts from it:

| Pillar | Contract |
|---|---|
| Debian/Canonical compliance | [docs/debian-canonical-compliance.md](docs/debian-canonical-compliance.md) |
| Cognitive ergonomics | [docs/ux-cognitive-ergonomics.md](docs/ux-cognitive-ergonomics.md) |
| CLI / GUI / docs parity | [docs/gui-parity.md](docs/gui-parity.md) |
| Velocity and responsiveness | [docs/velocity-responsiveness.md](docs/velocity-responsiveness.md) |

Some of those documents are phrase-locked by `tests/test_pillar_contracts.py` and
`tests/test_policy_compliance.py`: the comparison ignores case and line wrapping,
but rewording a locked sentence fails the suite. That is intentional. If a pillar
needs to change, change the test in the same commit and say why.

## Parity is a three-part deliverable

A feature is not finished until it exists in the CLI, in the GUI, and in the
relevant `.md`. `tests/test_platform_contracts.py` compares the argparse surface
against the GUI contract, so a flag added to only one side fails.

## Typing is a ratchet

`mypy` checks every module except an explicit debt list in `pyproject.toml`, which
only ever shrinks — `tests/test_typing_ratchet.py` enforces that, and refuses
entries naming modules that no longer exist. Adding a module to that list to make
a red check go green is how the `distroforge-typer explain` crash survived
unnoticed; fix the type error instead.

## `--json` is a contract, not a formatting preference

A command that accepts `--json` writes **one** JSON document to stdout and ends it with
**exactly one** newline. Same trailing-newline rule without `--json`. Messages for a human
— hints, "pass `--write`", warnings — go to stderr, never into the document.

Two conventions for the newline live in the tree and both are fine: a renderer returns the
document without a trailing newline and `print()` adds it (53 of 59 `render_json`), or the
renderer keeps it and the caller passes `end=""` (the rest). What is not fine is mixing
them at one call site, which is how `explain` came to print a blank line, `capture` and
`livefs-iso-plan` came to print none, `new --json` came to print prose, and
`livefs-iso-build --json` came to append an English sentence after the closing brace. Every
one of those exits 0 and looks right in a terminal.

`tests/test_cli_output_contract.py` enumerates the `--json` commands from the parser, so a
new command is covered the moment it exists. If it cannot be driven without a build, add it
to `NOT_EXERCISED` **with the reason** — the test asserts the exact contents of that set, so
an exclusion has to be argued once rather than accumulating.

## The Qt import shim, and why it is shaped the way it is

`distroforge/ui/qt.py` is the only module that imports Qt directly. It types the tree
against **PyQt6** — the binding `python3-distroforge` depends on — inside
`if TYPE_CHECKING`, and keeps the runtime preference for PySide6 with a PyQt6 fallback
in the `else`. Do not flatten that back into a plain `try`/`except` import.

`mypy` treats the two arrangements very differently. With a plain `try`/`except`, the
branch that redefines names the other branch already resolved is 35 errors — so the
tree was clean on a PyQt6 machine, red on a PySide6 one, and the CI Typecheck step had
to be pinned to one binding to stay green. Pinning it hid the worse half: with PySide6
unresolvable, `ignore_missing_imports` made `QMainWindow` an `Any`, an `Any` base class
makes every attribute access legal, and `MainWindow` was not being type-checked at all.

Two consequences worth knowing before you touch the UI:

- Widgets are attached to the window from the outside by `build_window_widgets()` and
  the page builders, so `MainWindow` **declares** the ones it reads or has to expose to
  satisfy a protocol. Read an undeclared one and `mypy` says so; that is the signal to
  add the declaration, with the widget's own class and not `QWidget`.
- A `Protocol` attribute is invariant. `sudo_check: QWidget` in a window protocol does
  not mean "any widget will do" — it means only a plain `QWidget` matches, and it will
  reject a window that declares the `QCheckBox` it actually holds. Annotate protocol
  members with the real class too.

`tests/test_qt_shim.py` covers what neither tool can see: that the typing branch and the
runtime branches still export the same names, and that no declaration on `MainWindow`
points at a widget no builder assigns any more. Type-checking against PyQt6 only is a
deliberate trade — a call PyQt6 accepts and PySide6 rejects is not a type error here, and
the eight-way runtime matrix is what covers it.

## Tests must be able to fail

A new test has to fail against the code it is meant to guard. Check it: apply the
test without the fix and watch it go red. Three kinds of test that look like
coverage and are not:

- one that skips when its tool is missing, so it never runs where it matters;
- one whose assertion holds before the fix as well as after;
- one that greps the source instead of calling the code.

All three were found in this suite. Prefer a counting or handshake assertion over
a wall-clock one: timing assertions are flaky across hardware and prove less.
