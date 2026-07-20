from __future__ import annotations

from distroforge.ui.path_actions import picker
from distroforge.ui.qt import QVBoxLayout, QWidget
from distroforge.ui.recommendation_actions import build_recommendation_actions
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import responsive_form as _responsive_form
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section


def build_quality_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    assurance_form = _responsive_form()
    assurance_form.addRow(window.secure_boot_check)
    assurance_form.addRow(
        "MOK key",
        _responsive_row(
            window.secure_boot_mok_key_edit,
            picker(
                window,
                window.secure_boot_mok_key_edit,
                title="Select MOK private key",
                file_filter="Keys (*.key *.pem *.priv);;All files (*)",
            ),
            breakpoint=680,
        ),
    )
    assurance_form.addRow(
        "MOK cert",
        _responsive_row(
            window.secure_boot_mok_cert_edit,
            picker(
                window,
                window.secure_boot_mok_cert_edit,
                title="Select MOK certificate (DER)",
                file_filter="Certificates (*.der *.crt *.cer *.pem);;All files (*)",
            ),
            breakpoint=680,
        ),
    )
    assurance_form.addRow(window.secure_boot_sign_modules_check)
    assurance_form.addRow("QA scenarios", window.qa_edit)
    assurance_form.addRow(window.bootcheck_check)
    assurance_form.addRow(window.policy_strict_check)
    assurance_form.addRow("Branding mode", window.brand_compliance_mode_combo)
    assurance_form.addRow(window.size_report_check)
    assurance_form.addRow("Size top", window.size_top_edit)
    assurance_form.addRow(window.vuln_scan_check)
    assurance_form.addRow("CVE policy", window.vuln_policy_combo)
    assurance_form.addRow("CVE database", window.vuln_db_edit)
    assurance_form.addRow("SBOM format", window.sbom_format_combo)
    actions = _responsive_row(
        _button("Plan checks", window._show_plan, "plan"),
        _button("UX Audit", window._run_ux_audit, "audit"),
        _button("Readiness", window._run_readiness, "audit"),
        _button("Branding Audit", window._run_branding_compliance, "audit"),
        _button("Debrand Scan", window._run_debrand_scan, "audit"),
        breakpoint=1040,
    )
    layout.addWidget(_section("Quality Lab", assurance_form, actions))
    layout.addWidget(_section("Readiness", build_recommendation_actions(window), window.readiness_view), 1)
    layout.addWidget(_section("Branding Compliance", window.compliance_view), 1)
    layout.addWidget(_section("UX Audit", window.ux_audit_view), 1)
    return page
