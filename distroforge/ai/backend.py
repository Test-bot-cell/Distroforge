from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class AdvisorContext:
    """Read-only grounding handed to a backend so it can narrate.

    A backend may turn this into prose but must not invent facts beyond it. The
    findings and ``corpus_citation`` are already computed deterministically by
    ForgeAdvisor; the backend only rephrases them.
    """

    title: str
    verdict: str
    findings: tuple[str, ...] = ()
    corpus_citation: str = ""
    register: str = ""


@dataclass(frozen=True)
class BackendStatus:
    name: str
    available: bool
    detail: str


class AdvisorBackend(Protocol):
    """Pluggable local-first narration backend.

    Every backend stays advisory: it produces text only and never touches the
    build, recipe, or host. ``narrate`` returns ``None`` to signal "I cannot
    help right now", which lets ForgeAdvisor degrade to the offline backend.
    """

    name: str

    def available(self) -> bool: ...

    def status(self) -> BackendStatus: ...

    def narrate(self, context: AdvisorContext) -> str | None: ...


def _prompt(context: AdvisorContext) -> str:
    findings = "; ".join(context.findings) if context.findings else "none"
    return (
        "Summarize this DistroForge build advisory in two plain sentences. "
        "Do not invent details beyond the facts given.\n"
        f"Audience: {context.register or 'a general user'}\n"
        f"Title: {context.title}\n"
        f"Verdict: {context.verdict}\n"
        f"Findings: {findings}\n"
        f"Build history: {context.corpus_citation or 'none recorded'}\n"
    )


class OfflineBackend:
    """Always-available, dependency-free backend.

    It calls no model, network, or cloud service; it renders the already-computed
    advisory context into a short, deterministic line so the offline path is never
    empty and the fallback is always exercised.
    """

    name = "offline"

    def available(self) -> bool:
        return True

    def status(self) -> BackendStatus:
        return BackendStatus(
            self.name,
            True,
            "Deterministic local heuristics; no model, network, or cloud service required.",
        )

    def narrate(self, context: AdvisorContext) -> str | None:
        if context.findings:
            head = f"{len(context.findings)} finding(s) reported; first: {context.findings[0]}."
        else:
            head = "No findings need advisory escalation."
        return f"Verdict {context.verdict}. {head}"


class _ShellBackend:
    """Thin shim that shells out to an optional local model CLI.

    It ships no weights and imports no ML library. Any missing binary, missing
    model, non-zero exit, or timeout returns ``None`` so ForgeAdvisor degrades to
    the offline backend instead of failing.
    """

    name = ""
    binary = ""
    timeout = 20.0

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def _command(self, prompt: str) -> list[str] | None:
        raise NotImplementedError

    def status(self) -> BackendStatus:
        if self.available():
            return BackendStatus(
                self.name,
                True,
                f"{self.binary} found; narration shells out and degrades to offline on any error.",
            )
        return BackendStatus(
            self.name,
            False,
            f"{self.binary} is not installed; this backend degrades to offline.",
        )

    def narrate(self, context: AdvisorContext) -> str | None:
        if not self.available():
            return None
        command = self._command(_prompt(context))
        if command is None:
            return None
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=self.timeout, check=True
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return result.stdout.strip() or None


class LlamaBackend(_ShellBackend):
    name = "llama"
    binary = "llama-cli"

    def _command(self, prompt: str) -> list[str] | None:
        model = os.environ.get("DISTROFORGE_LLAMA_MODEL", "").strip()
        if not model:
            return None
        return [self.binary, "-m", model, "-p", prompt, "-n", "200", "--no-display-prompt"]


class OllamaBackend(_ShellBackend):
    name = "ollama"
    binary = "ollama"

    def _command(self, prompt: str) -> list[str] | None:
        model = os.environ.get("DISTROFORGE_OLLAMA_MODEL", "llama3").strip() or "llama3"
        return [self.binary, "run", model, prompt]


_BACKENDS: tuple[type, ...] = (OfflineBackend, LlamaBackend, OllamaBackend)


def available_backends() -> list[AdvisorBackend]:
    return [backend() for backend in _BACKENDS]


def backend_names() -> list[str]:
    return [backend.name for backend in _BACKENDS]


def select_backend(name: str | None) -> AdvisorBackend:
    for backend in _BACKENDS:
        if backend.name == name:
            return backend()
    return OfflineBackend()
