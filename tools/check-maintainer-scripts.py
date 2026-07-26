#!/usr/bin/env python3
"""Compile the Python payloads embedded in the packaging shell scripts.

A ``python3 -c '...'`` payload inside a maintainer script is syntax-checked by
nothing at all: dpkg runs the script, the interpreter dies, and the surrounding
``2>/dev/null`` plus ``|| true`` swallow the traceback. DistroForge shipped such a
payload from 0.3.4-4 to 0.3.5-2 -- 707 bytes that never once executed. This gate
extracts every embedded payload and hands it to :func:`compile`, so a broken
payload breaks the test suite instead of shipping as silent dead code.

Three design choices, each one a defect this gate hit while it was written:

* Discovery never uses a brace glob. ``debian/*.{postinst,prerm,postrm}`` is
  shell syntax; :meth:`pathlib.Path.glob` reads the braces literally and matches
  nothing, so the gate would report success after reading zero files.
* The report carries an anti-vacuity floor. Scanning no script, or finding no
  payload, is a failure -- not the green light it would otherwise look like.
* Both payload spellings are extracted. ``-c`` inline payloads *and* heredocs: a
  gate that only understands ``-c`` cancels itself the moment the payload it
  guards is rewritten as the heredoc that ``-c`` should have been.

Two extra rules keep the decisions of this work package from silently regressing:
maintainer scripts may not spell commands with an absolute path (the lintian tag
``command-with-path-in-maintainer-script``), and they may not reach into a user
session -- ``gsettings``, ``dconf``, ``runuser``, ``/home`` -- because a script
running as root cannot ask the user for consent and dpkg cannot undo the write.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# dpkg calls exactly these; ``config`` belongs to debconf and is a shell script too.
MAINTAINER_SCRIPT_NAMES = ("preinst", "postinst", "prerm", "postrm", "config")
# Anti-vacuity floors. A tree that packages anything has at least one shell script
# carrying at least one Python payload; below these numbers the gate learned nothing.
MINIMUM_SCRIPTS = 1
MINIMUM_PAYLOADS = 1
_SHELL_SHEBANGS = ("#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env sh", "#!/usr/bin/env bash")
_PYTHON_COMMAND = re.compile(r"\bpython(?:3(?:\.\d+)?)?\b")
_INLINE_PAYLOAD = re.compile(r"\bpython(?:3(?:\.\d+)?)?\s+(?:-\w+\s+)*-c\s+(['\"])")
_HEREDOC_START = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_ABSOLUTE_COMMAND = re.compile(r"(?<![\w./-])/(?:usr/)?s?bin/([A-Za-z0-9._-]+)")
_SESSION_REACH = ("gsettings", "dconf", "runuser", "/home/", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")


@dataclass(frozen=True)
class Payload:
    """One Python source fragment lifted out of a shell script."""

    script: Path
    line: int
    form: str
    source: str


@dataclass
class Report:
    scripts: list[Path] = field(default_factory=list)
    payloads: list[Payload] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def render_text(self) -> str:
        lines = [
            "Maintainer script payload gate",
            "==============================",
            f"Scripts scanned: {len(self.scripts)}",
        ]
        lines.extend(f"  {path}" for path in self.scripts)
        lines.append(f"Python payloads compiled: {len(self.payloads)}")
        lines.extend(f"  {item.script}:{item.line} ({item.form}, {len(item.source)} bytes)" for item in self.payloads)
        if self.problems:
            lines.append("Problems:")
            lines.extend(f"  {problem}" for problem in self.problems)
        else:
            lines.append("Problems: none")
        return "\n".join(lines) + "\n"


def packaging_scripts(root: Path) -> list[Path]:
    """Every shell script in ``debian/`` that dpkg or autopkgtest executes.

    Names are enumerated one by one on purpose: the brace form that reads so
    naturally in a shell prompt matches nothing through :mod:`pathlib`.
    """
    debian = root / "debian"
    found: list[Path] = []
    for name in MAINTAINER_SCRIPT_NAMES:
        found.append(debian / name)
        found.extend(sorted(debian.glob(f"*.{name}")))
    tests = debian / "tests"
    if tests.is_dir():
        found.extend(sorted(path for path in tests.iterdir() if path.is_file() and path.name != "control"))
    return [path for path in dict.fromkeys(found) if path.is_file() and _is_shell_script(path)]


def _is_shell_script(path: Path) -> bool:
    if path.name in MAINTAINER_SCRIPT_NAMES or path.suffix.lstrip(".") in MAINTAINER_SCRIPT_NAMES:
        return True
    first = path.read_text(encoding="utf-8", errors="replace").split("\n", 1)[0].strip()
    return first.startswith(_SHELL_SHEBANGS)


def extract_payloads(script: Path, text: str) -> list[Payload]:
    return [*_inline_payloads(script, text), *_heredoc_payloads(script, text)]


def _inline_payloads(script: Path, text: str) -> list[Payload]:
    """Lift ``python3 -c <quoted>`` payloads, honouring the shell's quoting rules.

    Inside single quotes the shell hands every byte through untouched, so a
    backslash-newline stays in the payload and Python sees one logical line --
    which is precisely how ``try: ... ; except:`` became a SyntaxError. Inside
    double quotes the shell eats the backslash-newline first, so the payload must
    be unescaped the same way before it is compiled.
    """
    payloads: list[Payload] = []
    for match in _INLINE_PAYLOAD.finditer(text):
        quote = match.group(1)
        start = match.end()
        end = _closing_quote(text, start, quote)
        if end is None:
            continue
        body = text[start:end]
        source = body if quote == "'" else _unescape_double_quoted(body)
        payloads.append(Payload(script, text.count("\n", 0, match.start()) + 1, f"-c {quote}...{quote}", source))
    return payloads


def _closing_quote(text: str, start: int, quote: str) -> int | None:
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\" and quote == '"':
            index += 2
            continue
        if char == quote:
            return index
        index += 1
    return None


def _unescape_double_quoted(body: str) -> str:
    body = body.replace("\\\n", "")
    for escaped, plain in (("\\\\", "\\"), ('\\"', '"'), ("\\$", "$"), ("\\`", "`")):
        body = body.replace(escaped, plain)
    return body


def _heredoc_payloads(script: Path, text: str) -> list[Payload]:
    """Lift ``python3 - <<'PY' ... PY`` payloads, the form ``-c`` should have been."""
    payloads: list[Payload] = []
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _HEREDOC_START.search(line)
        if not match or not _PYTHON_COMMAND.search(line.split("<<", 1)[0]):
            index += 1
            continue
        delimiter = match.group(2)
        body: list[str] = []
        index += 1
        while index < len(lines) and lines[index].strip() != delimiter:
            body.append(lines[index])
            index += 1
        payloads.append(Payload(script, index - len(body), f"heredoc <<{delimiter}", "\n".join(body) + "\n"))
        index += 1
    return payloads


def check(root: Path) -> Report:
    report = Report()
    for script in packaging_scripts(root):
        relative = script.relative_to(root)
        report.scripts.append(relative)
        text = script.read_text(encoding="utf-8")
        report.problems.extend(_style_problems(relative, text))
        for payload in extract_payloads(relative, text):
            report.payloads.append(payload)
            try:
                compile(payload.source, f"{payload.script}:{payload.line}", "exec")
            except SyntaxError as exc:
                where = f"{payload.script}:{payload.line} ({payload.form})"
                report.problems.append(f"{where}: payload line {exc.lineno}: {exc.msg}: {(exc.text or '').strip()!r}")
    if len(report.scripts) < MINIMUM_SCRIPTS:
        report.problems.append(f"scanned {len(report.scripts)} scripts, expected at least {MINIMUM_SCRIPTS}")
    if len(report.payloads) < MINIMUM_PAYLOADS:
        report.problems.append(f"found {len(report.payloads)} payloads, expected at least {MINIMUM_PAYLOADS}")
    return report


def _style_problems(relative: Path, text: str) -> list[str]:
    """Rules that only bind dpkg-run scripts, not the autopkgtest ones."""
    if relative.parts[:2] == ("debian", "tests"):
        return []
    problems: list[str] = []
    for number, line in enumerate(text.split("\n"), start=1):
        if number == 1 and line.startswith("#!"):
            continue
        bare = line.split("#", 1)[0]
        for match in _ABSOLUTE_COMMAND.finditer(bare):
            problems.append(f"{relative}:{number}: command spelled with an absolute path: {match.group(0)}")
        for token in _SESSION_REACH:
            if token in bare:
                problems.append(f"{relative}:{number}: maintainer scripts must not reach into a user session: {token}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compile Python payloads embedded in packaging shell scripts")
    parser.add_argument("root", nargs="?", default=".", help="project root holding debian/ (default: .)")
    args = parser.parse_args(argv)
    report = check(Path(args.root).resolve())
    print(report.render_text(), end="")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
