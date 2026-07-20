from __future__ import annotations

import json
from pathlib import Path

import pytest

from distroforge.commands.artifacts import render_qemu_interaction
from distroforge.core.command import CommandRunner
from distroforge.core.interaction_plan import (
    InteractionPlan,
    InteractionStep,
    available_interaction_plans,
    resolve_interaction_plan,
)
from distroforge.core.project import Project
from distroforge.core.qemu_interaction import QemuInteractionOptions, QemuInteractionService
from distroforge.core.qmp import QmpControl, stop_by_pidfile


def _run(tmp_path, plan_spec="boot-capture", **option_kwargs):
    runner = CommandRunner(dry_run=True)
    iso = tmp_path / "image.iso"
    plan = resolve_interaction_plan(plan_spec, iso)
    options = QemuInteractionOptions(enable_kvm=False, **option_kwargs)
    report = QemuInteractionService(runner, iso, tmp_path / "work", tmp_path / "dist", plan, options).run()
    commands = [spec.argv for spec in runner.history]
    qemu = next(argv for argv in commands if argv and argv[0] == "qemu-system-x86_64")
    return report, commands, qemu


def test_interaction_dry_run_exposes_headless_qmp_steps_and_writes_report(tmp_path) -> None:
    report, commands, qemu = _run(tmp_path)

    assert "-qmp" in qemu
    assert "-daemonize" in qemu
    assert "-pidfile" in qemu
    assert "-cdrom" in qemu
    assert qemu[qemu.index("-display") + 1] == "none"
    assert any(argv[:1] == ("interaction-await-serial",) for argv in commands)
    assert any(argv[:1] == ("qmp-command",) and "screendump" in argv[-1] for argv in commands)
    assert any(argv[:1] == ("qmp-command",) and "query-status" in argv[-1] for argv in commands)
    assert any(argv[:1] == ("qmp-command",) and "quit" in argv[-1] for argv in commands)
    assert any(argv == ("write-file", str(tmp_path / "dist" / "qemu-interaction-report.json")) for argv in commands)
    assert any(argv == ("write-file", str(tmp_path / "dist" / "INTERACTION-INTEGRITY")) for argv in commands)
    assert report.argv == qemu


def test_interaction_qmp_control_dry_run_emits_canonical_shape_without_socket(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)
    socket_path = tmp_path / "missing.qmp"

    QmpControl(runner, timeout_seconds=1).command("query-status", socket_path)

    assert runner.history[-1].argv == (
        "qmp-command",
        str(socket_path),
        '{"execute": "query-status", "arguments": {}}',
    )
    assert not socket_path.exists()


def test_interaction_stop_by_pidfile_is_a_noop_without_pidfile(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)

    stop_by_pidfile(runner, tmp_path / "absent.pid")

    assert not any(spec.argv[:1] == ("kill",) for spec in runner.history)


def test_interaction_plan_round_trips_and_rejects_unknown_action() -> None:
    plan = InteractionPlan(
        name="custom",
        description="demo",
        firmware="uefi",
        network=True,
        steps=(
            InteractionStep("wait", seconds=2.0, description="pause"),
            InteractionStep("sendkey", value="ctrl-alt-f2"),
        ),
    )

    again = InteractionPlan.from_dict(json.loads(plan.render_json()))
    assert again.to_dict() == plan.to_dict()
    with pytest.raises(ValueError):
        InteractionStep("frobnicate")


def test_interaction_resolves_builtins_and_smoke_scenarios(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    names = available_interaction_plans()

    assert "boot-capture" in names
    assert "headless-status" in names
    assert "install-uefi-online" in names

    smoke = resolve_interaction_plan("install-uefi-online", iso)
    assert smoke.firmware == "uefi"
    assert smoke.network is True
    assert [step.action for step in smoke.steps] == ["wait-serial", "screendump", "query-status", "quit"]

    with pytest.raises(ValueError):
        resolve_interaction_plan("does-not-exist", iso)


def test_interaction_loads_a_plan_from_a_json_file(tmp_path) -> None:
    spec = tmp_path / "plan.json"
    spec.write_text(
        json.dumps(
            {
                "name": "file-plan",
                "description": "from disk",
                "firmware": "bios",
                "network": False,
                "steps": [{"action": "query-status"}, {"action": "quit"}],
            }
        ),
        encoding="utf-8",
    )

    plan = resolve_interaction_plan(str(spec), tmp_path / "image.iso")
    assert plan.name == "file-plan"
    assert [step.action for step in plan.steps] == ["query-status", "quit"]


def test_interaction_uefi_prepares_writable_ovmf_vars(tmp_path) -> None:
    _, commands, qemu = _run(tmp_path, plan_spec="install-uefi-online")

    assert any(argv[:1] == ("copy-file",) and argv[2].endswith("OVMF_VARS.fd") for argv in commands)
    assert any("if=pflash" in part and "readonly=on" in part for part in qemu)
    assert any(part.startswith("if=pflash,format=raw,file=") and part.endswith("OVMF_VARS.fd") for part in qemu)


def test_interaction_bios_plan_uses_no_firmware_or_kvm_flags(tmp_path) -> None:
    _, commands, qemu = _run(tmp_path)

    assert not any("pflash" in part for part in qemu)
    assert "-bios" not in qemu
    assert "-enable-kvm" not in qemu
    assert not any(argv[:1] == ("copy-file",) for argv in commands)


def test_interaction_sendkey_maps_to_qmp_send_key(tmp_path) -> None:
    plan = InteractionPlan(
        name="keys",
        description="demo",
        steps=(InteractionStep("sendkey", value="ctrl-alt-delete"), InteractionStep("quit")),
    )
    runner = CommandRunner(dry_run=True)
    iso = tmp_path / "image.iso"

    QemuInteractionService(
        runner, iso, tmp_path / "work", tmp_path / "dist", plan, QemuInteractionOptions(enable_kvm=False)
    ).run()

    commands = [spec.argv for spec in runner.history]
    sendkey = next(argv for argv in commands if argv[:1] == ("qmp-command",) and "send-key" in argv[-1])
    assert '"qcode"' in sendkey[-1]
    assert '"ctrl"' in sendkey[-1] and '"alt"' in sendkey[-1] and '"delete"' in sendkey[-1]


def test_interaction_dry_run_writes_no_host_files(tmp_path) -> None:
    _run(tmp_path, plan_spec="install-uefi-online")

    assert not (tmp_path / "dist" / "qemu-interaction-report.json").exists()
    assert not (tmp_path / "dist" / "INTERACTION-INTEGRITY").exists()
    assert not (tmp_path / "dist" / "interaction-serial.log").exists()
    assert not (tmp_path / "work" / "interaction" / "OVMF_VARS.fd").exists()


def test_interaction_report_is_deterministic_and_schema_pinned(tmp_path) -> None:
    first, _, _ = _run(tmp_path)
    second, _, _ = _run(tmp_path)

    payload = first.to_dict()
    assert payload["schema"] == "distroforge.qemu-interaction.v1"
    assert "created_at" not in payload
    assert payload == second.to_dict()


def test_interaction_cli_lists_plans_and_plans_a_smoke_scenario(tmp_path) -> None:
    listing = render_qemu_interaction(None, None, None, "", list_plans=True)
    assert "boot-capture" in listing
    assert "install-uefi-online" in listing

    Project.create("demo", tmp_path, "26.04")
    text = render_qemu_interaction(tmp_path, None, None, "install-uefi-online")
    assert "QEMU interaction: install-uefi-online" in text
    assert "wait-serial" in text


def test_interaction_gui_and_registry_expose_the_surface() -> None:
    page = Path("distroforge/ui/virtualization_page.py").read_text(encoding="utf-8")
    widgets = Path("distroforge/ui/window_widgets.py").read_text(encoding="utf-8")
    actions = Path("distroforge/ui/service_actions.py").read_text(encoding="utf-8")
    registry = Path("distroforge/core/command_registry.py").read_text(encoding="utf-8")

    assert "interaction_plan_combo" in widgets
    assert "interaction_plan_combo" in page
    assert '"Run interaction"' in page
    assert "_run_interaction" in page
    assert "def run_interaction_action" in actions
    assert 'CommandGuiMapping("qemu-interaction"' in registry
