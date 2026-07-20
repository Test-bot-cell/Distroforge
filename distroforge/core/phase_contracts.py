from __future__ import annotations

from dataclasses import dataclass

from .build_phases import PIPELINE_PHASES, BuildPhase

# The ordered stages that run over the BuildServices boundary in core/build_pipeline.py.
# ``build_services`` constructs the shared services and emits no user-facing phase, so no
# contract is mapped to it; it is listed for completeness.
PIPELINE_STAGES: tuple[str, ...] = (
    "run_preflight",
    "build_services",
    "acquire_source",
    "configure_repositories",
    "customize_target",
    "assemble_iso",
)


@dataclass(frozen=True)
class PhaseContract:
    """Declarative metadata for one build phase over the BuildServices boundary.

    ``privileged`` means the phase mutates protected rootfs/ISO state (the squashfs root
    or ISO tree) or otherwise requires the privilege helper when active. ``rollback``
    names the snapshot points the phase creates, or ``None`` when it creates none.
    """

    phase: BuildPhase
    title: str
    stage: str
    inputs: tuple[str, ...]
    artifacts: tuple[str, ...]
    privileged: bool
    rollback: str | None = None


_TITLES: dict[BuildPhase, str] = {spec.phase: spec.title for spec in PIPELINE_PHASES}

# (phase, stage, inputs, artifacts, privileged, rollback) in canonical pipeline order.
# Titles are derived from PIPELINE_PHASES so the catalog cannot drift from the taxonomy.
_CONTRACT_DATA: tuple[
    tuple[BuildPhase, str, tuple[str, ...], tuple[str, ...], bool, str | None], ...
] = (
    (BuildPhase.VALIDATE, "run_preflight",
     ("project definition", "host build tools"), ("validation findings",), False, None),
    (BuildPhase.CONSISTENCY, "run_preflight",
     ("project definition", "build options"), ("consistency findings",), False, None),
    (BuildPhase.POLICY, "run_preflight",
     ("build options", "policy mode"), ("policy report", "trademark clearance"), False, None),
    (BuildPhase.COMPATIBILITY, "run_preflight",
     ("release", "source mode"), ("compatibility report",), False, None),
    (BuildPhase.IMPORT_SCRIPTS, "run_preflight",
     ("legacy scripts",), ("imported chroot hooks",), False, None),
    (BuildPhase.DIFF_PREVIEW, "run_preflight",
     ("build options",), ("diff preview report",), False, None),
    (BuildPhase.PREPARE, "run_preflight",
     ("project paths",), ("workdir", "output dir"), False, None),
    (BuildPhase.BOOTSTRAP_ROOTFS, "acquire_source",
     ("release", "bootstrap options"), ("squashfs root", "ISO tree"), True, None),
    (BuildPhase.EXTRACT_ISO, "acquire_source",
     ("source ISO",), ("ISO tree",), True, None),
    (BuildPhase.UNPACK_FILESYSTEM, "acquire_source",
     ("filesystem.squashfs",), ("squashfs root",), True, None),
    (BuildPhase.CONFIGURE_APT, "configure_repositories",
     ("repositories", "mirror options"), ("apt sources",), True, None),
    (BuildPhase.APT_CACHE, "configure_repositories",
     ("apt cache options",), ("apt proxy/cache config",), True, None),
    (BuildPhase.PPA, "configure_repositories",
     ("PPA specs",), ("PPA sources", "signing keyrings"), True, None),
    (BuildPhase.RELEASE_TRACK, "configure_repositories",
     ("release track options",), ("apt track", "pinning"), True, None),
    (BuildPhase.SYSTEM_SYNC, "customize_target",
     ("system sync options",), ("synced packages",), True, None),
    (BuildPhase.AUTODRIVERS, "customize_target",
     ("driver options",), ("installed drivers",), True, None),
    (BuildPhase.APPLY_PACKAGES, "customize_target",
     ("package plan",), ("installed/removed packages",), True, None),
    (BuildPhase.DESKTOP_SOURCE, "customize_target",
     ("desktop source options",), ("built desktop .deb", "installed desktop"), True, None),
    (BuildPhase.INSTALL_SNAPS, "customize_target",
     ("snap specs",), ("preseeded snaps",), True, None),
    (BuildPhase.SIZE_ANALYSIS, "customize_target",
     ("installed packages",), ("size report",), True, None),
    (BuildPhase.VULN_SCAN, "customize_target",
     ("planned packages", "advisory database"), ("CVE findings",), False, None),
    (BuildPhase.CUSTOMIZE_SYSTEM, "customize_target",
     ("customization options",), ("desktop/display/locale config",), True, None),
    (BuildPhase.BRANDING, "customize_target",
     ("branding options",), ("logo/GRUB/Plymouth/identity assets",), True, None),
    (BuildPhase.USERS, "customize_target",
     ("user specs",), ("users and groups",), True, None),
    (BuildPhase.SYSTEMD, "customize_target",
     ("systemd options",), ("enabled/disabled/masked units",), True, None),
    (BuildPhase.NETWORK, "customize_target",
     ("network options",), ("netplan/DNS/proxy config",), True, None),
    (BuildPhase.KIOSK, "customize_target",
     ("kiosk options",), ("kiosk session",), True, None),
    (BuildPhase.OEM, "customize_target",
     ("OEM options",), ("first-boot/OEM reset flow",), True, None),
    (BuildPhase.KERNEL_MODULE, "customize_target",
     ("kernel module options",), ("compiled module", "refreshed boot assets"), True,
     "before-kernel, after-kernel"),
    (BuildPhase.SECURE_BOOT, "customize_target",
     ("secure boot options",), ("module signing", "MOK enrollment plan"), True, None),
    (BuildPhase.REPRODUCIBLE, "customize_target",
     ("reproducible options",), ("SOURCE_DATE_EPOCH", "apt snapshot metadata"), True, None),
    (BuildPhase.SNAPSHOT, "customize_target",
     ("snapshot options", "target rootfs"), ("rollback archives",), True,
     "after-apt, after-customize, after-sanitize"),
    (BuildPhase.RUN_HOOKS, "customize_target",
     ("hook scripts",), ("hook side effects",), True, None),
    (BuildPhase.SANITIZE_TARGET, "customize_target",
     ("sanitize options",), ("cleaned caches/logs/identity",), True, None),
    (BuildPhase.HEALTH, "assemble_iso",
     ("project", "build options"), ("health score",), False, None),
    (BuildPhase.AUTOINSTALL, "assemble_iso",
     ("autoinstall options",), ("autoinstall.yaml",), True, None),
    (BuildPhase.SEEDS, "assemble_iso",
     ("seed options",), ("seed", "requested manifests"), True, None),
    (BuildPhase.UPDATE_METADATA, "assemble_iso",
     ("squashfs root", "ISO tree"), ("Casper manifest", "filesystem.size"), True, None),
    (BuildPhase.REPACK_FILESYSTEM, "assemble_iso",
     ("squashfs root", "compression"), ("filesystem.squashfs",), True, None),
    (BuildPhase.UPDATE_CHECKSUMS, "assemble_iso",
     ("ISO tree",), ("md5sum.txt",), True, None),
    (BuildPhase.REBUILD_ISO, "assemble_iso",
     ("ISO tree",), ("output ISO",), True, None),
    (BuildPhase.PREBUILD_VM, "assemble_iso",
     ("output ISO", "prebuild VM options"), ("VM lab logs",), False, None),
    (BuildPhase.RELEASE_ARTIFACTS, "assemble_iso",
     ("output ISO",), ("SHA256SUMS", "BUILDINFO", "signature"), False, None),
    (BuildPhase.BOOTCHECK, "assemble_iso",
     ("output ISO",), ("boot smoke result",), False, None),
    (BuildPhase.QEMU_SCREENSHOT, "assemble_iso",
     ("output ISO",), ("boot screenshot",), False, None),
    (BuildPhase.PROVENANCE, "assemble_iso",
     ("project", "planned packages"), ("SBOM", "provenance document"), False, None),
    (BuildPhase.HTML_REPORT, "assemble_iso",
     ("build report", "output ISO"), ("HTML report",), False, None),
    (BuildPhase.QA_MATRIX, "assemble_iso",
     ("output ISO", "QA scenarios"), ("QA matrix results",), False, None),
    (BuildPhase.PREVIEW, "assemble_iso",
     ("output ISO",), ("QEMU preview session",), False, None),
)


PHASE_CONTRACTS: tuple[PhaseContract, ...] = tuple(
    PhaseContract(
        phase=phase,
        title=_TITLES[phase],
        stage=stage,
        inputs=inputs,
        artifacts=artifacts,
        privileged=privileged,
        rollback=rollback,
    )
    for phase, stage, inputs, artifacts, privileged, rollback in _CONTRACT_DATA
)


def contract_for(phase: BuildPhase) -> PhaseContract:
    for contract in PHASE_CONTRACTS:
        if contract.phase == phase:
            return contract
    raise KeyError(f"No phase contract for {phase}")


def contracts_for_stage(stage: str) -> tuple[PhaseContract, ...]:
    if stage not in PIPELINE_STAGES:
        known = ", ".join(PIPELINE_STAGES)
        raise KeyError(f"Unknown pipeline stage: {stage}. Known stages: {known}")
    return tuple(contract for contract in PHASE_CONTRACTS if contract.stage == stage)


def privileged_phases() -> tuple[BuildPhase, ...]:
    return tuple(contract.phase for contract in PHASE_CONTRACTS if contract.privileged)


def rollback_phases() -> tuple[BuildPhase, ...]:
    return tuple(contract.phase for contract in PHASE_CONTRACTS if contract.rollback)


def render_phase_contracts(stage: str | None = None) -> str:
    if stage is not None and stage not in PIPELINE_STAGES:
        known = ", ".join(PIPELINE_STAGES)
        raise KeyError(f"Unknown pipeline stage: {stage}. Known stages: {known}")
    lines = ["DistroForge build phase contracts"]
    lines.append(
        "Stages over the BuildServices boundary: "
        "run_preflight -> acquire_source -> configure_repositories -> "
        "customize_target -> assemble_iso"
    )
    for current in PIPELINE_STAGES:
        if stage is not None and current != stage:
            continue
        contracts = contracts_for_stage(current) if current != "build_services" else ()
        if not contracts:
            continue
        lines.append("")
        lines.append(f"[{current}]")
        for contract in contracts:
            lines.append(f"{contract.phase.value:18} {contract.title}")
            lines.append(f"  privileged: {'yes' if contract.privileged else 'no'}")
            if contract.rollback:
                lines.append(f"  rollback:   {contract.rollback}")
            lines.append(f"  inputs:     {', '.join(contract.inputs)}")
            lines.append(f"  artifacts:  {', '.join(contract.artifacts)}")
    return "\n".join(lines)
