"""Real signer verification for a pinned GPG fingerprint.

`gpg --verify` answers a narrower question than the one the options ask: it
accepts any valid signature from any key in the caller's keyring. The pinned
fingerprint used to be emitted as a `gpg-fingerprint-assert` /
`gpg-fingerprint-check` marker, and CommandRunner short-circuits virtual commands
to rc=0 in execute mode just as it does in dry-run -- so the value accepted by
`--kernel-gpg-fingerprint`, `--source-iso-gpg-fingerprint` and the GUI's "Signer
fingerprint" field was compared against nothing, anywhere.

Asking gpg for its status channel and reading the VALIDSIG line is what actually
answers the question, so that is what these helpers do.
"""

from __future__ import annotations

from pathlib import Path

_VALIDSIG = "[GNUPG:] VALIDSIG "


def verify_argv(signature: Path, payload: Path, keyring: str | None = None) -> tuple[str, ...]:
    """Argv for a verification whose signer can afterwards be identified."""
    argv = ["gpg"]
    if keyring:
        argv.extend(["--no-default-keyring", "--keyring", str(keyring)])
    argv.extend(["--status-fd", "1", "--verify", str(signature), str(payload)])
    return tuple(argv)


def normalize_fingerprint(value: str) -> str:
    return "".join(value.split()).removeprefix("0x").removeprefix("0X").upper()


def signer_fingerprints(status_output: str) -> tuple[str, ...]:
    """Primary-key fingerprints gpg reported as VALIDSIG."""
    found: list[str] = []
    for line in status_output.splitlines():
        if line.startswith(_VALIDSIG):
            fields = line[len(_VALIDSIG) :].split()
            if fields:
                found.append(fields[0].upper())
    return tuple(found)


def assert_signer(status_output: str, expected: str, description: str) -> None:
    """Raise unless gpg reported a good signature from the pinned signer.

    A pinned value shorter than 40 hex digits is treated as a key id, matched
    against the end of the reported fingerprint, which is how gpg itself resolves
    short and long key ids.
    """
    wanted = normalize_fingerprint(expected)
    if not wanted:
        return
    seen = signer_fingerprints(status_output)
    if not seen:
        raise ValueError(
            f"GPG reported no valid signature for {description}; "
            f"cannot honour the pinned fingerprint {expected}"
        )
    if not any(fingerprint == wanted or fingerprint.endswith(wanted) for fingerprint in seen):
        raise ValueError(
            f"GPG signature for {description} is from {', '.join(seen)}, "
            f"not from the pinned fingerprint {expected}"
        )
