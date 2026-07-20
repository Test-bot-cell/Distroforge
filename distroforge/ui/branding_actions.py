from __future__ import annotations

from distroforge.core.brand_identity import write_identity, write_identity_preview


def run_brand_preview_action(window) -> None:
    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    identity = write_identity_preview(window.project, window._build_options().branding)
    window.compliance_view.setPlainText(identity.render_preview())
    window._log(f"Brand preview written to {window.project.output_dir / 'branding-preview'}")
    window._open_surface("identity")


def export_brand_identity_action(window) -> None:
    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    identity = write_identity(window.project, window._build_options().branding)
    window.compliance_view.setPlainText(identity.render_manifest())
    window._log(f"Brand identity exported to {window.project.output_dir / 'BRANDING-MANIFEST.json'}")
    window._open_surface("identity")
