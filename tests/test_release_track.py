from __future__ import annotations

from pathlib import Path

import pytest

from distroforge.core.command import CommandRunner
from distroforge.core.release_track import ReleaseTrackOptions, ReleaseTrackService
from distroforge.core.releases import get_release

RELEASE = "26.04"
CODENAME = "resolute"


def _service(*, mode: str = "devel", devel_suite: str = "devel", **kw) -> ReleaseTrackService:
    return ReleaseTrackService(
        CommandRunner(dry_run=True),
        Path("/tmp/distroforge-track-root"),
        get_release(RELEASE),
        ReleaseTrackOptions(mode=mode, devel_suite=devel_suite, **kw),
    )


@pytest.mark.parametrize("mode", ["devel", "rolling"])
def test_devel_track_resolves_placeholder_to_release_codename(mode: str) -> None:
    # "devel" is a debootstrap script alias, not an apt suite; it must resolve to the
    # real release codename or apt aborts with an invalid APT::Default-Release value.
    assert _service(mode=mode)._track_suite() == CODENAME


@pytest.mark.parametrize("mode", ["devel", "rolling"])
def test_apt_default_release_pins_a_real_suite(mode: str) -> None:
    apt_defaults = _service(mode=mode)._apt_defaults()
    assert f'APT::Default-Release "{CODENAME}";' in apt_defaults
    assert '"devel"' not in apt_defaults


def test_track_sources_never_emit_the_bare_devel_suite() -> None:
    sources = _service(mode="devel", enable_proposed=True, enable_backports=True)._sources()
    suites = [line.split()[2] for line in sources.splitlines() if line.startswith("deb ")]
    assert suites  # sanity: at least one apt source line was produced
    assert all(suite == CODENAME or suite.startswith(f"{CODENAME}-") for suite in suites)
    assert "devel" not in suites


def test_explicit_codename_override_is_honoured() -> None:
    # A maintainer may still pin a specific codename within the same archive.
    assert _service(mode="devel", devel_suite="questing")._track_suite() == "questing"


def test_non_devel_mode_uses_release_codename() -> None:
    # backports-on-stable must still resolve to the codename, never "devel".
    assert _service(mode="stable", enable_backports=True)._track_suite() == CODENAME


def _round_trip_service(root: Path, **kw) -> ReleaseTrackService:
    # A real (non-dry-run, rootless) service so configure() actually writes/removes
    # files on disk -- the round trip the dry-run unit tests above cannot exercise.
    return ReleaseTrackService(
        CommandRunner(dry_run=False),
        root,
        get_release(RELEASE),
        ReleaseTrackOptions(**kw),
        use_sudo=False,
    )


def test_stable_reconfigure_sheds_a_prior_devel_runs_pin(tmp_path) -> None:
    # The reported failure in miniature: a reused rootfs carried a previous devel
    # run's `APT::Default-Release "devel"`. configure() is now a pure function of the
    # current options, so a later stable build removes the stale pin instead of
    # leaving apt to choke on a release that no longer exists in the sources.
    root = tmp_path / "root"
    seeded = {
        "etc/apt/apt.conf.d/90distroforge-release-track": 'APT::Default-Release "devel";\n',
        "etc/apt/sources.list.d/distroforge-track.list": "deb x devel main\n",
        "etc/apt/preferences.d/distroforge-proposed": "Package: *\n",
    }
    for relative, text in seeded.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    _round_trip_service(root, mode="stable").configure()

    for relative in seeded:
        assert not (root / relative).exists(), relative


def test_devel_reconfigure_writes_codename_pin_not_devel(tmp_path) -> None:
    # The full configure() round trip, not just the helper: an enabled devel track
    # pins the real codename, never the bare "devel" placeholder apt rejects.
    root = tmp_path / "root"
    _round_trip_service(root, mode="devel").configure()
    pin = (root / "etc/apt/apt.conf.d/90distroforge-release-track").read_text(encoding="utf-8")
    assert f'"{CODENAME}"' in pin
    assert '"devel"' not in pin
