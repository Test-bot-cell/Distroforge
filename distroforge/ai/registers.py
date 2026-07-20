"""Adaptive advisory registers — one brain, many voices.

A *register* is the advisory voice ForgeAdvisor speaks in. It is a thin
projection over the single canonical level vocabulary (``core.workflows``):
exactly one register per workflow level, keyed by ``LEVEL_KEYS`` so it can never
drift into a parallel taxonomy. The register changes *how* the agent speaks and
*how much* it expands — never *what* it does to the build. Selection is silent
(derived from the active workflow level) but always overridable; this module
owns only that voice metadata, no side effects and no engine access.
"""

from __future__ import annotations

from dataclasses import dataclass

from distroforge.core.workflows import LEVEL_KEYS, WORKFLOW_LEVELS


@dataclass(frozen=True)
class AdvisorRegister:
    """The advisory voice for one canonical workflow level."""

    level: str
    voice: str
    audience: str
    expand_jargon: bool
    lens_note: str


# One register per canonical level. Built against WORKFLOW_LEVELS below so the
# set of registers stays identical to LEVEL_KEYS; a missing level raises at
# import time rather than silently shipping a half-populated taxonomy.
_VOICES: dict[str, AdvisorRegister] = {
    "beginner": AdvisorRegister(
        level="beginner",
        voice="Beginner",
        audience="a first-time remix maker",
        expand_jargon=True,
        lens_note=(
            "Beginner view: jargon is expanded in plain language below; "
            "you do not need the command line."
        ),
    ),
    "power-user": AdvisorRegister(
        level="power-user",
        voice="Power user",
        audience="a power user managing repositories and rollback",
        expand_jargon=False,
        lens_note=(
            "Power-user view: weigh repositories, rollback snapshots and "
            "provenance for these findings."
        ),
    ),
    "maintainer": AdvisorRegister(
        level="maintainer",
        voice="Maintainer",
        audience="a release maintainer",
        expand_jargon=False,
        lens_note=(
            "Maintainer view: connect these findings to release readiness, "
            "policy and trademark clearance."
        ),
    ),
    "developer": AdvisorRegister(
        level="developer",
        voice="Senior Debian/Canonical",
        audience="a senior Debian/Canonical maintainer",
        expand_jargon=False,
        lens_note=(
            "Debian/Canonical lens: weigh these findings against Debian "
            "Policy, lintian and Standards-Version."
        ),
    ),
}


def _build_registers() -> dict[str, AdvisorRegister]:
    registers: dict[str, AdvisorRegister] = {}
    for level in WORKFLOW_LEVELS:
        try:
            registers[level.key] = _VOICES[level.key]
        except KeyError as exc:  # pragma: no cover - guards against a new level shipping voiceless.
            raise ValueError(f"Workflow level {level.key!r} has no advisory register voice.") from exc
    return registers


REGISTERS: dict[str, AdvisorRegister] = _build_registers()
DEFAULT_REGISTER_LEVEL: str = LEVEL_KEYS[0]


def register_keys() -> tuple[str, ...]:
    """The register vocabulary, identical to the canonical level keys."""
    return tuple(REGISTERS)


def get_register(level: str) -> AdvisorRegister:
    """Resolve a register by level, rejecting anything outside the vocabulary."""
    try:
        return REGISTERS[level]
    except KeyError as exc:
        known = ", ".join(REGISTERS)
        raise ValueError(f"Unknown advisory register {level!r}. Known: {known}") from exc


def select_register(level: str | None) -> AdvisorRegister:
    """Ring 0 silent selection: pick the voice for ``level``, degrade to beginner.

    A valid level is honoured (an explicit override); ``None`` or anything
    unknown degrades to the beginner register so the advisor never raises while
    choosing how to speak.
    """
    if level and level in REGISTERS:
        return REGISTERS[level]
    return REGISTERS[DEFAULT_REGISTER_LEVEL]
