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

## Tests must be able to fail

A new test has to fail against the code it is meant to guard. Check it: apply the
test without the fix and watch it go red. Three kinds of test that look like
coverage and are not:

- one that skips when its tool is missing, so it never runs where it matters;
- one whose assertion holds before the fix as well as after;
- one that greps the source instead of calling the code.

All three were found in this suite. Prefer a counting or handshake assertion over
a wall-clock one: timing assertions are flaky across hardware and prove less.
