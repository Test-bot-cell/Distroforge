from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

# ``YYYYMMDDTHHMMSSZ``, the form apt's sources.list(5) describes for a snapshot
# identifier. apt does not check it: the same page says that servers may support other
# forms and that "APT does not verify" them, so an unchecked typo becomes a mid-build
# 404 at best -- and, measured, something worse than a 404 in two cases out of three.
_SNAPSHOT_ID = re.compile(r"\A\d{8}T\d{6}Z\Z")

# "Snapshots of the Ubuntu archive are available for any date and time after 1 March
# 2023", says the service itself at https://snapshot.ubuntu.com/. Earlier identifiers
# 404, which is loud but only after the build has reached its first apt fetch.
_SNAPSHOT_FLOOR = datetime(2023, 3, 1, tzinfo=UTC)

# mksquashfs documents -mkfs-time and SOURCE_DATE_EPOCH as taking "an unsigned 32-bit
# int indicating seconds since the epoch", so anything outside that range is not a
# timestamp it can use.
_EPOCH_MAX = 2**32 - 1


@dataclass
class ReproducibleOptions:
    enabled: bool = False
    source_date_epoch: int | None = None
    # An apt snapshot *identifier*, not a URL. See :func:`snapshot_problem`.
    apt_snapshot: str | None = None

    @property
    def effective_source_date_epoch(self) -> int | None:
        """The epoch to pin, or ``None`` when nothing should be pinned.

        A value left in the options while the feature is switched off must not reach a
        command: the switch is what the operator turned off, and a build that pinned
        timestamps anyway would not be the build they asked for.
        """
        return self.source_date_epoch if self.enabled else None

    @property
    def effective_apt_snapshot(self) -> str | None:
        """The snapshot to pin, on the same reasoning as the epoch above."""
        return self.apt_snapshot if self.enabled else None

    def pin_summary(self) -> str:
        """What this phase will pin, for the one line the operator sees."""
        if not self.enabled:
            return "disabled"
        pins = []
        if self.source_date_epoch is not None:
            pins.append(f"SOURCE_DATE_EPOCH={self.source_date_epoch}")
        if self.apt_snapshot:
            pins.append(f"apt snapshot {self.apt_snapshot}")
        return ", ".join(pins) if pins else "enabled, nothing pinned"


def source_date_epoch_argv(epoch: int | None) -> tuple[str, ...]:
    """The argv prefix that makes an image-producing tool deterministic.

    Both tools that write shipped bytes honour ``SOURCE_DATE_EPOCH`` on their own
    documented authority, so nothing here is invented. ``mksquashfs`` 4.7.5 states it
    "is used as the filesystem creation timestamp. Also any file timestamps which are
    after SOURCE_DATE_EPOCH will be clamped to SOURCE_DATE_EPOCH"; ``xorrisofs`` 1.5.6
    states it supplies the default of ``--modification-date=``, of ``--gpt_disk_guid``,
    of ``--set_all_file_dates`` and of the "now" time for nodes with no disk source.

    It travels in the argv rather than in ``CommandSpec.env`` -- which is a real field,
    used by ``core.gnome_favorites`` to hand a command a whole session environment --
    for two reasons, each of which would otherwise fail silently. First, these two
    commands run under the privilege wrapper, and the wrapper discards what it is given:
    sudoers(5) for the sudo-rs on this platform says "the env_reset flag cannot be
    disabled. This causes commands to be executed with a new, minimal environment", and
    pkexec(1) says the program's environment "will be set to a minimal known and safe
    environment". ``env VAR=value prog`` is set by a program running *under* the wrapper,
    so no privilege policy can drop it. Second, a plan is meant to be read and re-run,
    and ``CommandSpec.display()`` and the JSONL build log both render argv and nothing
    else -- a pin carried beside the argv would be missing from the very record that
    claims to say what the build did.

    ``env`` is the first word, never the last: ``mksquashfs`` reads everything after
    ``-e`` as an exclude pattern.
    """
    if epoch is None:
        return ()
    return ("env", f"SOURCE_DATE_EPOCH={epoch}")


def epoch_problem(epoch: int) -> str | None:
    """Why ``epoch`` cannot be used as a timestamp, or ``None`` when it can."""
    if epoch < 0 or epoch > _EPOCH_MAX:
        return (
            f"{epoch} is outside the unsigned 32-bit range mksquashfs documents for a "
            "timestamp, so the repack would refuse it"
        )
    return None


def snapshot_problem(snapshot: str, now: datetime | None = None) -> str | None:
    """Why ``snapshot`` cannot pin the archive, or ``None`` when it can.

    The identifier goes to apt as the ``snapshot=`` source option, which apt resolves
    to whichever snapshot service the repository belongs to -- measured routing an
    Ubuntu source to ``snapshot.ubuntu.com/ubuntu/<id>`` and a Debian one to
    ``snapshot.debian.org/archive/debian/<id>``. That is why this project passes the
    identifier and never builds the URL: the layouts differ per vendor and apt already
    knows both.

    Validating here is not belt-and-braces. Measured against the live service with
    ``APT::Update::Error-Mode=any``, only one of three bad identifiers is loud:

    * malformed (``pouet``) -- apt exits 100 on a 404. Loud, but an hour in.
    * in the future (``20990301T030400Z``) -- HTTP 200, and the indices served are
      byte-for-byte the live archive's. apt exits 0 and the build is simply not
      pinned while still reporting that it is. This is the case nothing else catches.
    * before the service exists -- 404.

    A snapshot older than the target suite is a fourth trap, and it is *not* checked
    here: it also exits 0, on an archive that is merely empty, and no release date is
    available in this project's release table to compare against. It is documented in
    ``docs/build-pipeline.md`` rather than half-guarded.
    """
    if not _SNAPSHOT_ID.match(snapshot):
        return (
            f"{snapshot!r} is not an apt snapshot identifier; sources.list(5) describes "
            "the form YYYYMMDDTHHMMSSZ, such as 20250601T030400Z"
        )
    try:
        stamp = datetime.strptime(snapshot, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        return f"{snapshot!r} is not a real date and time ({exc})"
    if stamp < _SNAPSHOT_FLOOR:
        return (
            f"{snapshot} predates the snapshot service, which covers dates after "
            f"{_SNAPSHOT_FLOOR.date()} by its own statement"
        )
    if stamp > (now or datetime.now(UTC)):
        return (
            f"{snapshot} is in the future, and a future identifier does not fail: the "
            "service answers it with the current archive, so the build would not be "
            "pinned to anything while still reporting that it is"
        )
    return None


class ReproducibleService:
    """Refuses a reproducible build whose inputs are not actually pinned.

    This phase used to write ``etc/distroforge-reproducible.env`` into the target and
    stop there. Nothing in this project, in apt, or in any build tool ever read that
    file, and it shipped inside the image: the feature announced itself to the operator
    and changed nothing about the bytes produced. The pinning now happens where those
    bytes are made -- ``SOURCE_DATE_EPOCH`` on the two commands that write them, and the
    apt ``snapshot=`` option on the sources every package comes from -- so what is left
    for this phase is the one useful thing it can do, which is to refuse before an hour
    of work instead of after it.
    """

    # It takes no runner, no root and no privilege flag any more: it runs no command
    # and writes nothing. Keeping those parameters would advertise a reach this phase
    # no longer has, and the phase-contract gate measures that reach for real.
    def __init__(self, options: ReproducibleOptions) -> None:
        self.options = options

    def apply(self) -> None:
        if not self.options.enabled:
            return
        epoch = self.options.source_date_epoch
        if epoch is None:
            raise ValueError(
                "Reproducible builds are enabled but no SOURCE_DATE_EPOCH is pinned, so "
                "every timestamp would come from the clock and two builds of one tree "
                "would differ. Pass --source-date-epoch (a Unix timestamp, usually the "
                "date of the newest source change) or turn --reproducible off."
            )
        problem = epoch_problem(epoch)
        if problem:
            raise ValueError(f"Refusing to pin SOURCE_DATE_EPOCH: {problem}.")
        snapshot = self.options.apt_snapshot
        if snapshot:
            problem = snapshot_problem(snapshot)
            if problem:
                raise ValueError(f"Refusing to pin the apt snapshot: {problem}.")
