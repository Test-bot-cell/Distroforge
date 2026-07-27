"""Executable teeth for the reproducible-build options, which used to have none.

``--reproducible`` wrote ``etc/distroforge-reproducible.env`` into the target and
stopped there. Nothing in this project, in apt, or in any build tool read that file, and
it shipped inside the image: the option announced itself in the CLI, in the GUI, in the
phase list and in the build log, and changed nothing about the bytes produced. No test
covered it, which is how it stayed that way.

Every pin asserted here was measured against the real tools and the real archive before
being written:

* ``mksquashfs`` 4.7.5 documents ``SOURCE_DATE_EPOCH`` as the filesystem creation
  timestamp and as a clamp on later file timestamps; ``xorrisofs`` 1.5.6 documents it as
  the default of ``--modification-date=``, ``--gpt_disk_guid`` and
  ``--set_all_file_dates``. Neither needed a flag invented for it.
* the pin travels in the argv because the privilege wrapper discards environments:
  sudoers(5) for sudo-rs states ``env_reset`` "cannot be disabled", and pkexec(1) sets a
  "minimal known and safe environment".
* ``apt`` resolves ``snapshot=<id>`` on an ordinary archive URI to the right snapshot
  service per vendor -- measured routing an Ubuntu source to
  ``snapshot.ubuntu.com/ubuntu/<id>`` and a Debian one to
  ``snapshot.debian.org/archive/debian/<id>``, and changing the resolved version of
  ``openssl`` from 3.0.13-0ubuntu3.11 to 3.0.13-0ubuntu3.5 for a June 2025 identifier.
* a snapshot identifier in the future is the case that needs guarding here rather than
  by the service: ``20990301T030400Z`` answers HTTP 200 with indices byte-identical to
  the live archive, ``apt-get update`` exits 0 even under
  ``APT::Update::Error-Mode=any``, and the build is simply not pinned.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import distroforge.core.build_pipeline as build_pipeline
from distroforge.core.apt import AptService, Repository, parse_repository_line, pin_snapshot
from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.build_pipeline import build_services
from distroforge.core.command import CommandRunner, CommandSpec
from distroforge.core.dry_run_report import generate_dry_run_report
from distroforge.core.iso import IsoService
from distroforge.core.mirrors import MirrorOptions, MirrorService
from distroforge.core.ppa import PpaOptions, PpaSpec
from distroforge.core.project import Project
from distroforge.core.release_track import ReleaseTrackOptions, ReleaseTrackService
from distroforge.core.releases import get_release
from distroforge.core.reproducible import (
    ReproducibleOptions,
    ReproducibleService,
    epoch_problem,
    snapshot_problem,
    source_date_epoch_argv,
)
from distroforge.core.squashfs import SquashfsService

EPOCH = 1700000000
# A real identifier in the past, so this file does not expire.
SNAPSHOT = "20250601T030400Z"


def _project(tmp_path, name: str) -> Project:
    project = Project.create(name, tmp_path / name.lower(), "26.04")
    project.source_mode = "bootstrap"
    return project


def _options(*, enabled: bool = True, epoch: int | None = EPOCH, snapshot: str | None = None,
             mirror: str | None = None) -> BuildOptions:
    options = BuildOptions()
    options.reproducible = ReproducibleOptions(
        enabled=enabled, source_date_epoch=epoch, apt_snapshot=snapshot
    )
    options.bootstrap.mirror = mirror
    return options


def _history(tmp_path, name: str, options: BuildOptions) -> list[CommandSpec]:
    runner = CommandRunner(dry_run=True)
    BuildOrchestrator(_project(tmp_path, name), runner, options).run()
    return runner.history


def _spec_for(history: list[CommandSpec], tool: str) -> CommandSpec:
    # Searched anywhere in the argv, never at argv[0]: the privilege wrapper owns the
    # head of the list, and so does the `env` prefix this file is about.
    return next(spec for spec in history if tool in spec.argv)


def _findings(tmp_path, name: str, options: BuildOptions):
    project = _project(tmp_path, name)
    return generate_dry_run_report(project, options, run_orchestrator=False).findings


def _codes(findings) -> set[str]:
    return {finding.code for finding in findings}


# --- the epoch reaches the commands that write shipped bytes -----------------


def test_the_repack_command_carries_the_epoch(tmp_path) -> None:
    spec = _spec_for(_history(tmp_path, "PinRepack", _options()), "mksquashfs")
    assert f"SOURCE_DATE_EPOCH={EPOCH}" in spec.argv


def test_the_iso_command_carries_the_epoch(tmp_path) -> None:
    spec = _spec_for(_history(tmp_path, "PinIso", _options()), "xorriso")
    assert f"SOURCE_DATE_EPOCH={EPOCH}" in spec.argv


def test_nothing_is_pinned_when_the_feature_is_off(tmp_path) -> None:
    # The control that matters: a suite where the pin is always present would pass every
    # assertion above while making the option meaningless.
    history = _history(tmp_path, "PinOff", _options(enabled=False))
    assert not [spec for spec in history if any("SOURCE_DATE_EPOCH" in arg for arg in spec.argv)]


def test_an_epoch_left_behind_a_disabled_switch_does_not_leak(tmp_path) -> None:
    # Unchecking the box in the GUI leaves the value in its field. The build the operator
    # asked for is the unpinned one.
    options = _options(enabled=False, epoch=EPOCH)
    assert options.reproducible.effective_source_date_epoch is None
    history = _history(tmp_path, "PinStale", options)
    assert not [spec for spec in history if any("SOURCE_DATE_EPOCH" in arg for arg in spec.argv)]


def test_the_prefix_sits_after_the_wrapper_and_before_the_tool(tmp_path) -> None:
    # The load-bearing shape. `sudo SOURCE_DATE_EPOCH=... mksquashfs` would be dropped:
    # sudoers(5) for sudo-rs says env_reset cannot be disabled. `sudo env VAR=v tool`
    # survives because a program under the wrapper sets it.
    options = _options()
    options.use_sudo = True
    argv = _spec_for(_history(tmp_path, "PinOrder", options), "mksquashfs").argv
    assert argv[0] in ("sudo", "pkexec")
    env_at = argv.index("env")
    assert env_at < argv.index(f"SOURCE_DATE_EPOCH={EPOCH}") < argv.index("mksquashfs")
    assert env_at > 0


def test_the_prefix_is_before_the_exclude_list(tmp_path) -> None:
    # mksquashfs reads every word after -e as an exclude pattern, so a pin appended at
    # the end would be swallowed in silence and the image would simply not be pinned.
    argv = _spec_for(_history(tmp_path, "PinExclude", _options()), "mksquashfs").argv
    assert argv.index(f"SOURCE_DATE_EPOCH={EPOCH}") < argv.index("-e")


def test_the_printed_plan_shows_the_pin(tmp_path) -> None:
    # core/command.py documents that the plan is read and re-run by operators. A pin the
    # plan omits is a plan that reproduces something else.
    spec = _spec_for(_history(tmp_path, "PinPlan", _options()), "mksquashfs")
    assert f"SOURCE_DATE_EPOCH={EPOCH}" in spec.display()


def test_the_services_that_only_read_are_not_pinned() -> None:
    # unpack() and extract() write working trees, not media; pinning them would claim a
    # determinism about files nobody ships.
    runner = CommandRunner(dry_run=True)
    SquashfsService(runner, use_sudo=False, source_date_epoch=EPOCH).unpack(
        __file__, runner.log_path or __file__  # type: ignore[arg-type]
    )
    IsoService(runner, use_sudo=False, source_date_epoch=EPOCH).extract(
        __file__, __file__  # type: ignore[arg-type]
    )
    assert not [spec for spec in runner.history if "env" in spec.argv]


def test_the_prefix_helper_is_empty_without_an_epoch() -> None:
    assert source_date_epoch_argv(None) == ()
    assert source_date_epoch_argv(EPOCH) == ("env", f"SOURCE_DATE_EPOCH={EPOCH}")


# --- the build refuses a pin it cannot honour --------------------------------


def test_enabling_without_an_epoch_is_refused() -> None:
    with pytest.raises(ValueError) as excinfo:
        ReproducibleService(ReproducibleOptions(enabled=True)).apply()
    assert "SOURCE_DATE_EPOCH" in str(excinfo.value)
    assert "--source-date-epoch" in str(excinfo.value)


def test_the_preview_refuses_it_too(tmp_path) -> None:
    findings = _findings(tmp_path, "PreviewNoEpoch", _options(epoch=None))
    assert "reproducible-epoch-missing" in _codes(findings)
    assert [f for f in findings if f.code == "reproducible-epoch-missing"][0].level == "error"


def test_an_epoch_outside_the_documented_range_is_refused() -> None:
    # mksquashfs documents an unsigned 32-bit value; 2**32 is the first one it cannot use.
    assert epoch_problem(EPOCH) is None
    assert epoch_problem(0) is None
    assert "32-bit" in (epoch_problem(2**32) or "")
    assert "32-bit" in (epoch_problem(-1) or "")
    with pytest.raises(ValueError, match="32-bit"):
        ReproducibleService(ReproducibleOptions(enabled=True, source_date_epoch=2**32)).apply()


def test_the_preview_and_the_build_agree_about_a_bad_epoch(tmp_path) -> None:
    findings = _findings(tmp_path, "PreviewBadEpoch", _options(epoch=2**32))
    assert "reproducible-epoch-invalid" in _codes(findings)


# --- the snapshot identifier is validated where nothing else validates it ----


def test_a_good_identifier_passes() -> None:
    assert snapshot_problem(SNAPSHOT) is None


def test_a_malformed_identifier_is_refused() -> None:
    assert "YYYYMMDDTHHMMSSZ" in (snapshot_problem("pouet") or "")
    assert "YYYYMMDDTHHMMSSZ" in (snapshot_problem("2025-06-01") or "")


def test_an_impossible_date_is_refused() -> None:
    assert snapshot_problem("20251301T030400Z") is not None


def test_an_identifier_older_than_the_service_is_refused() -> None:
    # The service states it covers dates after 1 March 2023; earlier ones 404 mid-build.
    assert "predates" in (snapshot_problem("20220101T000000Z") or "")
    assert snapshot_problem("20230301T000001Z") is None


def test_a_future_identifier_is_refused_because_nothing_else_refuses_it() -> None:
    # Measured: the service answers a future identifier with HTTP 200 and the live
    # archive's own indices, and apt exits 0. Refusing here is the only refusal there is.
    now = datetime(2026, 7, 27, tzinfo=UTC)
    assert "future" in (snapshot_problem("20990301T030400Z", now=now) or "")
    assert snapshot_problem(SNAPSHOT, now=now) is None


def test_the_build_and_the_preview_both_refuse_a_bad_identifier(tmp_path) -> None:
    with pytest.raises(ValueError, match="apt snapshot"):
        ReproducibleService(
            ReproducibleOptions(enabled=True, source_date_epoch=EPOCH, apt_snapshot="pouet")
        ).apply()
    findings = _findings(tmp_path, "PreviewBadSnap", _options(snapshot="pouet"))
    assert "reproducible-snapshot-invalid" in _codes(findings)


# --- the snapshot reaches every source the build will fetch from -------------


def _apt(snapshot: str | None) -> AptService:
    return AptService(
        CommandRunner(dry_run=True),
        __file__,  # type: ignore[arg-type]
        get_release("26.04"),
        use_sudo=False,
        snapshot=snapshot,
    )


def test_every_default_source_carries_the_snapshot() -> None:
    lines = [line for line in _apt(SNAPSHOT).render_sources().splitlines() if line]
    assert lines
    assert all(f"[snapshot={SNAPSHOT}]" in line for line in lines)


def test_no_source_carries_one_when_none_is_pinned() -> None:
    assert "snapshot=" not in _apt(None).render_sources()


def test_an_operator_supplied_source_is_pinned_as_well() -> None:
    repo = Repository(suite="noble", components=("main",), uri="http://archive.invalid/ubuntu")
    rendered = _apt(SNAPSHOT).render_sources([repo])
    assert f"[snapshot={SNAPSHOT}]" in rendered
    assert "http://archive.invalid/ubuntu" in rendered


def test_a_source_the_operator_already_pinned_keeps_its_own_identifier() -> None:
    theirs = "20240401T000000Z"
    repo = Repository(
        suite="noble", components=("main",), uri="http://a.invalid/ubuntu", snapshot=theirs
    )
    assert pin_snapshot([repo], SNAPSHOT)[0].snapshot == theirs


def test_the_option_shares_the_bracket_with_signed_by() -> None:
    repo = Repository(
        suite="noble",
        components=("main", "universe"),
        uri="http://a.invalid/ubuntu",
        signed_by="/usr/share/keyrings/x.gpg",
        snapshot=SNAPSHOT,
    )
    assert repo.source_line() == (
        f"deb [signed-by=/usr/share/keyrings/x.gpg snapshot={SNAPSHOT}] "
        "http://a.invalid/ubuntu noble main universe"
    )


def test_a_rendered_source_parses_back_into_itself() -> None:
    # The asymmetry to guard: a parser that drops the option would silently unpin any
    # source that made a round trip through it, and project.repositories does exactly
    # that on every build.
    repo = Repository(
        suite="noble",
        components=("main",),
        uri="http://a.invalid/ubuntu",
        signed_by="/k.gpg",
        snapshot=SNAPSHOT,
    )
    assert parse_repository_line(repo.source_line()) == repo


def test_the_release_track_writes_pinned_sources_too(tmp_path) -> None:
    # Found by listing every apt-source writer in the tree rather than assuming there
    # were two: --release-track writes its own archive sources into the chroot, and an
    # unpinned one would be the single source still serving whatever is current.
    root = tmp_path / "trackroot"
    service = ReleaseTrackService(
        CommandRunner(dry_run=False),
        root,
        get_release("26.04"),
        ReleaseTrackOptions(mode="rolling"),
        use_sudo=False,
        snapshot=SNAPSHOT,
    )
    service.configure()
    written = (root / "etc/apt/sources.list.d/distroforge-track.list").read_text()
    lines = [line for line in written.splitlines() if line.startswith("deb ")]
    assert lines
    assert all(f"[snapshot={SNAPSHOT}]" in line for line in lines)


def test_the_release_track_line_is_unchanged_without_a_snapshot(tmp_path) -> None:
    root = tmp_path / "trackplain"
    ReleaseTrackService(
        CommandRunner(dry_run=False),
        root,
        get_release("26.04"),
        ReleaseTrackOptions(mode="rolling"),
        use_sudo=False,
    ).configure()
    written = (root / "etc/apt/sources.list.d/distroforge-track.list").read_text()
    assert "snapshot=" not in written
    assert "[" not in written


def test_the_release_track_receives_the_pin_from_the_build(tmp_path) -> None:
    options = _options(snapshot=SNAPSHOT)
    orch = BuildOrchestrator(_project(tmp_path, "TrackSeam"), CommandRunner(dry_run=True), options)
    assert build_services(orch).release_track.snapshot == SNAPSHOT


def test_a_ppa_is_reported_as_unpinnable_rather_than_pinned(tmp_path) -> None:
    # Measured: apt derives the snapshot host by prefixing "snapshot." to the
    # repository's, so a PPA resolves to snapshot.ppa.launchpadcontent.net, which does
    # not exist. Every fetch is Ign, apt exits 0, and the live PPA is used. Writing the
    # option there would be a second placebo of exactly the kind this change removes.
    options = _options(snapshot=SNAPSHOT, mirror="https://pinned.invalid/ubuntu")
    options.ppa = PpaOptions([PpaSpec("graphics-drivers", "ppa", "ABCDEF1234567890")],
                             auto_fetch_fingerprint=False)
    findings = _findings(tmp_path, "PpaUnpinned", options)
    assert "reproducible-ppa-unpinned" in _codes(findings)
    warning = [f for f in findings if f.code == "reproducible-ppa-unpinned"][0]
    assert warning.level == "warning"
    assert "ppa:graphics-drivers/ppa" in warning.message


def test_no_ppa_warning_without_a_ppa(tmp_path) -> None:
    options = _options(snapshot=SNAPSHOT, mirror="https://pinned.invalid/ubuntu")
    assert "reproducible-ppa-unpinned" not in _codes(_findings(tmp_path, "NoPpa", options))


def test_a_refused_identifier_does_not_also_emit_coverage_warnings(tmp_path) -> None:
    # A snapshot the build will refuse has no reach to describe; the warnings would be
    # noise stacked on top of the one line that matters.
    options = _options(snapshot="pouet")
    options.ppa = PpaOptions([PpaSpec("graphics-drivers", "ppa")], auto_fetch_fingerprint=False)
    codes = _codes(_findings(tmp_path, "RefusedQuiet", options))
    assert "reproducible-snapshot-invalid" in codes
    assert "reproducible-base-unpinned" not in codes
    assert "reproducible-ppa-unpinned" not in codes


def test_the_deb822_mirror_layer_renders_the_same_pin(tmp_path) -> None:
    project = _project(tmp_path, "MirrorPin")
    service = MirrorService(
        CommandRunner(dry_run=True), project, MirrorOptions(enabled=True), snapshot=SNAPSHOT
    )
    rendered = service.render_sources()
    assert f"Snapshot: {SNAPSHOT}" in rendered
    # Every stanza, not just the first: the security stanza is a separate entry.
    stanzas = [block for block in rendered.split("\n\n") if block.strip()]
    assert len(stanzas) > 1
    assert all(f"Snapshot: {SNAPSHOT}" in block for block in stanzas)


def test_the_mirror_layer_is_pinned_by_the_build_too(tmp_path, monkeypatch) -> None:
    # The mirror layer replaces core/apt.py's sources rather than adding to them, so a
    # pin wired into only one of the two would leave the build unpinned whenever
    # --mirrors is on -- a flag with nothing to do with reproducibility.
    seen: dict[str, object] = {}
    original = build_pipeline.MirrorService

    class Spy(original):  # type: ignore[misc,valid-type]
        def __init__(self, *args, **kwargs) -> None:
            seen.update(kwargs)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(build_pipeline, "MirrorService", Spy)
    options = _options(snapshot=SNAPSHOT)
    options.mirrors = MirrorOptions(enabled=True)
    _history(tmp_path, "MirrorWired", options)
    assert seen.get("snapshot") == SNAPSHOT


# --- the wiring seam itself --------------------------------------------------


def test_the_shared_services_receive_both_pins(tmp_path) -> None:
    options = _options(snapshot=SNAPSHOT)
    orch = BuildOrchestrator(_project(tmp_path, "Seam"), CommandRunner(dry_run=True), options)
    services = build_services(orch)
    assert services.squashfs.source_date_epoch == EPOCH
    assert services.iso.source_date_epoch == EPOCH
    assert services.apt.snapshot == SNAPSHOT


def test_the_shared_services_receive_nothing_when_the_feature_is_off(tmp_path) -> None:
    options = _options(enabled=False, snapshot=SNAPSHOT)
    orch = BuildOrchestrator(_project(tmp_path, "SeamOff"), CommandRunner(dry_run=True), options)
    services = build_services(orch)
    assert services.squashfs.source_date_epoch is None
    assert services.iso.source_date_epoch is None
    assert services.apt.snapshot is None


# --- the half this does not pin, said out loud -------------------------------


def test_a_snapshot_warns_that_the_base_rootfs_is_not_pinned(tmp_path) -> None:
    # debootstrap and mmdebstrap take a mirror URL, which carries no apt source option,
    # so the base is outside the snapshot's reach. The residual gap is announced rather
    # than hidden -- and not guessed at, since the snapshot URL layout differs per vendor.
    findings = _findings(tmp_path, "BaseUnpinned", _options(snapshot=SNAPSHOT))
    assert "reproducible-base-unpinned" in _codes(findings)
    warning = [f for f in findings if f.code == "reproducible-base-unpinned"][0]
    assert warning.level == "warning"
    assert "--bootstrap-mirror" in warning.remediation


def test_the_warning_goes_away_once_the_base_is_pinned(tmp_path) -> None:
    options = _options(
        snapshot=SNAPSHOT, mirror=f"https://snapshot.ubuntu.com/ubuntu/{SNAPSHOT}"
    )
    assert "reproducible-base-unpinned" not in _codes(_findings(tmp_path, "BasePinned", options))


def test_no_reproducible_finding_appears_when_the_feature_is_off(tmp_path) -> None:
    codes = _codes(_findings(tmp_path, "QuietOff", _options(enabled=False, snapshot="pouet")))
    assert not [code for code in codes if code.startswith("reproducible-")]


# --- what the operator is told the phase will do -----------------------------


def test_the_phase_line_names_what_it_pins() -> None:
    assert ReproducibleOptions().pin_summary() == "disabled"
    assert ReproducibleOptions(enabled=True).pin_summary() == "enabled, nothing pinned"
    summary = ReproducibleOptions(
        enabled=True, source_date_epoch=EPOCH, apt_snapshot=SNAPSHOT
    ).pin_summary()
    assert f"SOURCE_DATE_EPOCH={EPOCH}" in summary
    assert f"apt snapshot {SNAPSHOT}" in summary


def test_nothing_writes_the_hints_file_any_more(tmp_path) -> None:
    # The file this feature used to consist of. It shipped inside the image and no
    # reader for it has ever existed anywhere.
    history = _history(tmp_path, "NoHints", _options(snapshot=SNAPSHOT))
    assert not [
        spec for spec in history if any("distroforge-reproducible.env" in arg for arg in spec.argv)
    ]
