from __future__ import annotations

from dataclasses import dataclass, field

from .branding_compliance import BrandingComplianceService
from .consistency import ConsistencyService
from .project import Project


@dataclass
class PolicyOptions:
    strict: bool = False
    branding_mode: str = "internal"
    forbid_unverified_ppa: bool = True
    require_qa_for_proposed: bool = True
    require_signed_secureboot_modules: bool = True
    forbid_root_autologin: bool = True


@dataclass(frozen=True)
class PolicyFinding:
    code: str
    message: str
    severity: str = "warning"
    category: str = "safety"
    explanation: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, object]:
        return self.__dict__


PolicyViolation = PolicyFinding


class PolicyService:
    def check(self, project: Project, options: object, policy: PolicyOptions) -> list[PolicyFinding]:
        violations: list[PolicyFinding] = []
        for issue in ConsistencyService().check(project, options):
            if issue.level == "error":
                violations.append(
                    PolicyFinding(
                        issue.code,
                        issue.message,
                        severity="error",
                        category="consistency",
                        explanation="The current option mix can produce an unsafe or incoherent ISO.",
                        remediation="Change the conflicting options or run in advisory mode only.",
                    )
                )
        ppas = getattr(getattr(options, "ppa", None), "ppas", [])
        if policy.forbid_unverified_ppa:
            for ppa in ppas:
                if not ppa.fingerprint and not getattr(options.ppa, "auto_fetch_fingerprint", False):
                    violations.append(
                        PolicyFinding(
                            "unverified-ppa",
                            f"PPA ppa:{ppa.owner}/{ppa.name} has no fingerprint or auto-verification",
                            severity="error",
                            category="auth",
                            explanation="Third-party apt sources must be pinned to a trusted signing key.",
                            remediation="Add @FINGERPRINT to the PPA or keep auto key verification enabled.",
                        )
                    )
        release_track = getattr(options, "release_track", None)
        qa = getattr(options, "qa", None)
        if (
            policy.require_qa_for_proposed
            and release_track
            and release_track.enable_proposed
            and qa
            and not qa.scenarios
        ):
            violations.append(
                PolicyFinding(
                    "proposed-without-qa",
                    "Proposed pocket requires at least one QA scenario in strict mode",
                    severity="error",
                    category="debian-policy",
                    explanation="The proposed pocket can introduce unverified regressions.",
                    remediation="Add at least one QA scenario such as live-bios or live-uefi.",
                )
            )
        secure_boot = getattr(options, "secure_boot", None)
        kernel_module = getattr(options, "kernel_module", None)
        if (
            policy.require_signed_secureboot_modules
            and secure_boot
            and kernel_module
            and secure_boot.enabled
            and kernel_module.enabled
            and not secure_boot.sign_modules
        ):
            violations.append(
                PolicyFinding(
                    "secureboot-unsigned-module",
                    "Secure Boot with a custom kernel module requires module signing",
                    severity="error",
                    category="secure-boot",
                    explanation="Unsigned kernel modules will fail Secure Boot expectations.",
                    remediation="Enable module signing or disable the custom kernel module phase.",
                )
            )
        if policy.forbid_root_autologin and project.customization.autologin_user == "root":
            violations.append(
                PolicyFinding(
                    "root-autologin",
                    "Root autologin is forbidden",
                    severity="error",
                    category="safety",
                    explanation="Root autologin is unsafe for redistributable live images.",
                    remediation="Use a normal user or disable autologin.",
                )
            )
        branding = getattr(options, "branding", None)
        if branding:
            branding_mode = "redistributable" if policy.strict else policy.branding_mode
            report = BrandingComplianceService().audit(project, branding, branding_mode)
            for finding in report.findings:
                violations.append(
                    PolicyFinding(
                        finding.code,
                        finding.message,
                        severity=finding.severity,
                        category="canonical-guidelines",
                        explanation="Redistributable remixes must not present Canonical marks as product identity.",
                        remediation=finding.remediation,
                    )
                )
        return violations

    def summary(self, violations: list[PolicyFinding]) -> str:
        if not violations:
            return "policy-ok"
        return "; ".join(f"{violation.code}: {violation.message}" for violation in violations)


@dataclass
class CompatibilityReport:
    release: str
    codename: str
    supported: bool
    messages: list[str] = field(default_factory=list)


class CompatibilityService:
    def check(self, project: Project, options: object) -> CompatibilityReport:
        messages: list[str] = []
        release = project.release
        if not release.supported:
            messages.append("Release is marked planned/experimental in DistroForge data")
        for ppa in getattr(getattr(options, "ppa", None), "ppas", []):
            messages.append(
                f"PPA ppa:{ppa.owner}/{ppa.name} will be checked against Launchpad for {release.codename}"
            )
        if project.source_mode == "bootstrap" and release.installer != "subiquity":
            messages.append("From-scratch mode expects a Subiquity/casper live environment")
        return CompatibilityReport(
            release=release.version,
            codename=release.codename,
            supported=release.supported,
            messages=messages,
        )
