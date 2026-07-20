from __future__ import annotations

from distroforge.ui.path_actions import image_url_picker, picker, unsplash_picker
from distroforge.ui.qt import QVBoxLayout, QWidget
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import responsive_form as _responsive_form
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section


def build_customization_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    form = _responsive_form()
    form.addRow("Desktop", window.desktop_combo)
    form.addRow("Display manager", window.display_manager_combo)
    form.addRow("Autologin user", window.autologin_edit)
    wallpaper_row = _responsive_row(
        window.wallpaper_edit,
        _button("Select", window._browse_wallpaper),
        image_url_picker(
            window,
            window.wallpaper_edit,
            title="Import wallpaper from URL",
            prompt="Wallpaper image URL:",
        ),
        unsplash_picker(
            window,
            window.wallpaper_edit,
            title="Import wallpaper from Unsplash",
            prompt="Wallpaper image URL (from Unsplash):",
        ),
        breakpoint=680,
    )
    form.addRow("Wallpaper", wallpaper_row)
    form.addRow("Hostname", window.hostname_edit)
    form.addRow("Language / locale", window.locale_combo)
    form.addRow("Timezone", window.timezone_combo)
    form.addRow("Keyboard layout", window.keyboard_combo)
    layout.addWidget(_section("Personalization", form))
    brand_form = _responsive_form()
    brand_form.addRow("Brand name", window.brand_name_edit)
    brand_form.addRow("Pretty name", window.brand_pretty_name_edit)
    brand_form.addRow("Product name", window.brand_product_name_edit)
    brand_form.addRow("Vendor", window.brand_vendor_edit)
    brand_form.addRow("Palette preset", window.brand_palette_combo)
    brand_form.addRow("Palette #hex", window.brand_palette_colors_edit)
    brand_form.addRow("Plymouth main color", window.brand_plymouth_main_color_edit)
    brand_form.addRow(
        "Logo",
        _responsive_row(
            window.brand_logo_edit,
            picker(
                window,
                window.brand_logo_edit,
                title="Select logo image",
                file_filter="Images (*.png *.jpg *.jpeg *.svg *.webp);;All files (*)",
            ),
            image_url_picker(
                window,
                window.brand_logo_edit,
                title="Import logo from URL",
                prompt="Logo image URL:",
            ),
            unsplash_picker(
                window,
                window.brand_logo_edit,
                title="Import logo from Unsplash",
                prompt="Logo image URL (from Unsplash):",
            ),
            breakpoint=680,
        ),
    )
    brand_form.addRow(
        "Login background",
        _responsive_row(
            window.brand_login_background_edit,
            picker(
                window,
                window.brand_login_background_edit,
                title="Select login background image",
                file_filter="Images (*.png *.jpg *.jpeg *.svg *.webp);;All files (*)",
            ),
            image_url_picker(
                window,
                window.brand_login_background_edit,
                title="Import login background from URL",
                prompt="Login background image URL:",
            ),
            unsplash_picker(
                window,
                window.brand_login_background_edit,
                title="Import login background from Unsplash",
                prompt="Login background image URL (from Unsplash):",
            ),
            breakpoint=680,
        ),
    )
    brand_actions = _responsive_row(
        _button("Preview", window._run_brand_preview, "audit"),
        _button("Export Identity", window._export_brand_identity, "save"),
        breakpoint=720,
    )
    layout.addWidget(_section("Brand Basics", brand_form, brand_actions))
    layout.addWidget(_section("Brand Preview", window.compliance_view), 1)
    return page
