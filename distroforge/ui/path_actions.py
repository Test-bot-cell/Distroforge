from __future__ import annotations

import hashlib
import re
import shutil
import tarfile
import webbrowser
import zipfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from distroforge.ui.qt import QFileDialog, QInputDialog, QMessageBox
from distroforge.ui.widgets import button

_SUPPORTED_IMAGE_EXTENSIONS = {
    ".avif",
    ".gif",
    ".jpeg",
    ".jpg",
    ".png",
    ".svg",
    ".webp",
}

_IMAGE_MIME_TO_EXT = {
    "image/avif": ".avif",
    "image/gif": ".gif",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/png": ".png",
    "image/svg+xml": ".svg",
    "image/webp": ".webp",
}

_UNSPLASH_SEARCH_URL = "https://unsplash.com/s/photos/wallpaper"
_PLYMOUTH_SPINNER_GALLERY_URL = "https://www.gnome-look.org/s/Gnome/find/?f=tags&lic=gplv2-later&page=1&search=plymouth"
_GRUB_THEME_GALLERY_URL = "https://www.gnome-look.org/s/Gnome/find/?f=tags&lic=gplv2-later&page=1&search=grub"
_DOWNLOAD_USER_AGENT = "DistroForge/0.3.5 (image browser)"
_CACHE_MAX_BYTES = 35 * 1024 * 1024  # Keep downloads bounded in the UI helper.
_THEME_ARCHIVE_CACHE_MAX_BYTES = 250 * 1024 * 1024

_GRUB_THEME_ASSET_DIR = Path("assets") / "themes" / "grub"
_GRUB_THEME_CACHE_DIR = Path(".cache") / "distroforge" / "themes" / "grub"
_GRUB_THEME_ASSETS_EXTS = {
    ".jpeg",
    ".jpg",
    ".pf2",
    ".png",
    ".svg",
    ".tga",
    ".tiff",
    ".webp",
}

_THEME_ARCHIVE_EXTS = {
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tar.xz",
}

_THEME_ARCHIVE_MIME_TO_EXT = {
    "application/zip": ".zip",
    "application/x-zip-compressed": ".zip",
    "application/x-tar": ".tar",
    "application/gzip": ".gz",
    "application/x-gzip": ".gz",
    "application/x-bzip2": ".bz2",
    "application/x-xz": ".xz",
}


def _project_cache_dir(window) -> Path:
    project = getattr(window, "project", None)
    if project is not None:
        candidate = Path(project.workdir) / "assets" / "backgrounds"
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except OSError:
            # Fall back to a stable per-user cache if project is readonly or not set up.
            pass
    cache_root = Path.home() / ".cache" / "distroforge" / "backgrounds"
    cache_root.mkdir(parents=True, exist_ok=True)
    return cache_root


def _project_grub_theme_dir(window) -> Path:
    project = getattr(window, "project", None)
    if project is not None:
        candidate = Path(project.workdir) / _GRUB_THEME_ASSET_DIR
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except OSError:
            pass
    cache_root = Path.home() / _GRUB_THEME_CACHE_DIR
    cache_root.mkdir(parents=True, exist_ok=True)
    return cache_root


def _slugify_grub_theme(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", value.lower().strip())
    slug = "-".join(part for part in slug.split("-") if part) or "grub-theme"
    return slug[:64]


def _read_grub_theme_metadata(theme_root: Path) -> tuple[str | None, str | None]:
    theme_txt = theme_root / "theme.txt"
    title = None
    version = None

    for raw_line in theme_txt.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip().strip('"')
        if key in {"title-text", "title", "name"} and title is None and value:
            title = value
        elif key == "version" and value and version is None:
            version = value

    return title, version


def _validate_grub_theme_root(theme_root: Path) -> tuple[str | None, str | None]:
    theme_txt = theme_root / "theme.txt"
    if not theme_txt.is_file():
        raise ValueError("Could not find theme.txt in the GRUB theme archive.")

    title, version = _read_grub_theme_metadata(theme_root)
    has_asset = any(
        asset.suffix.lower() in _GRUB_THEME_ASSETS_EXTS for asset in theme_root.rglob("*") if asset.is_file()
    )
    if not has_asset:
        raise ValueError("GRUB theme appears incomplete (no standard image/asset files were found).")

    return title, version


def _apply_to_project_grub_theme(
    window,
    theme_root: Path,
    url: str,
    *,
    title: str | None,
) -> Path:
    project_dir = _project_grub_theme_dir(window)
    source_name = _slugify_grub_theme(title or theme_root.name)
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:8]
    destination = project_dir / f"{source_name}-{digest}"

    if destination.exists():
        if destination.is_file() or destination.is_fifo():
            destination.unlink(missing_ok=True)
        elif destination.is_dir():
            shutil.rmtree(destination)
    shutil.copytree(theme_root, destination)
    return destination


def _extension_from_url(url: str, content_type: str) -> str:
    path_suffix = Path(urlparse(url).path).suffix.lower()
    if path_suffix in _SUPPORTED_IMAGE_EXTENSIONS:
        return path_suffix

    media_type = content_type.split(";", 1)[0].strip().lower()
    return _IMAGE_MIME_TO_EXT.get(media_type, "")


def _theme_archive_extension_from_url(url: str, content_type: str) -> str:
    path = Path(urlparse(url).path).as_posix().lower()
    for ext in sorted(_THEME_ARCHIVE_EXTS, key=len, reverse=True):
        if path.endswith(ext):
            return ext

    media_type = content_type.split(";", 1)[0].strip().lower()
    mapped_ext = _THEME_ARCHIVE_MIME_TO_EXT.get(media_type, "")
    if mapped_ext == ".gz":
        return ".tar.gz"
    if mapped_ext == ".bz2":
        return ".tar.bz2"
    if mapped_ext == ".xz":
        return ".tar.xz"
    if mapped_ext in {".tar", ".zip"}:
        return mapped_ext
    return ""


def _safe_log(window, text: str) -> None:
    logger = getattr(window, "_log", None)
    if callable(logger):
        logger(text)


def _safe_extract_zip(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive, "r") as archive_handle:
        for member in archive_handle.infolist():
            member_name = member.filename
            if _is_unsafe_archive_path(member_name):
                raise ValueError("Unsafe archive entry path.")
            archive_handle.extract(member, path=destination)


def _safe_extract_tar(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:*") as archive_handle:
        for member in archive_handle.getmembers():
            if _is_unsafe_archive_path(member.name):
                raise ValueError("Unsafe archive entry path.")
        archive_handle.extractall(path=destination)


def _is_unsafe_archive_path(path: str) -> bool:
    normalized = path.replace("\\", "/").strip()
    if not normalized:
        return False
    if normalized.startswith("/") or normalized.startswith("\\") or ".." in Path(normalized).parts:
        return True
    return False


def _locate_grub_theme_root(extracted_root: Path) -> Path:
    matches = list(extracted_root.rglob("theme.txt"))
    if not matches:
        raise ValueError("Could not find theme.txt in the GRUB theme archive.")

    matches = [candidate.parent for candidate in matches if candidate.is_file()]
    return sorted(matches, key=lambda path: len(path.relative_to(extracted_root).parts))[0]


def _download_image_to_cache(url: str, cache_dir: Path) -> Path:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Image URLs must use http(s).")

    cache_dir.mkdir(parents=True, exist_ok=True)

    request = Request(url, headers={"User-Agent": _DOWNLOAD_USER_AGENT})
    response = urlopen(request, timeout=20)
    try:
        content_type = response.headers.get("Content-Type", "")
        extension = _extension_from_url(url, content_type)
        if not extension or extension not in _SUPPORTED_IMAGE_EXTENSIONS:
            raise ValueError(
                "Could not detect an image URL (or the server replied with a non-image type). "
                "Use a direct image link ending in png/jpg/jpeg/svg/webp."
            )

        stem = (
            re.sub(
                r"[^A-Za-z0-9_-]+", "-", f"{parsed.netloc}-{parsed.path}".strip("-")
            )
            or "image"
        )
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
        destination = cache_dir / f"{stem[:28]}-{digest}{extension}"

        total_size = 0
        with destination.open("wb") as target:
            while True:
                chunk = response.read(1024 * 256)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > _CACHE_MAX_BYTES:
                    raise ValueError("Downloaded image is unexpectedly large (>35MB).")
                target.write(chunk)

        if total_size == 0:
            raise ValueError("Downloaded image is empty.")
        return destination
    finally:
        response.close()


def _download_file_to_cache(url: str, cache_dir: Path, max_bytes: int, detect_extension) -> Path:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URLs must use http(s).")

    cache_dir.mkdir(parents=True, exist_ok=True)

    request = Request(url, headers={"User-Agent": _DOWNLOAD_USER_AGENT})
    response = urlopen(request, timeout=20)
    try:
        content_type = response.headers.get("Content-Type", "")
        extension = detect_extension(url, content_type)
        if not extension:
            raise ValueError("Could not detect a compatible URL.")

        stem = (
            re.sub(
                r"[^A-Za-z0-9_-]+", "-", f"{parsed.netloc}-{parsed.path}".strip("-")
            )
            or "asset"
        )
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
        destination = cache_dir / f"{stem[:28]}-{digest}{extension}"

        total_size = 0
        with destination.open("wb") as target:
            while True:
                chunk = response.read(1024 * 256)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > max_bytes:
                    raise ValueError("Downloaded asset is unexpectedly large.")
                target.write(chunk)

        if total_size == 0:
            raise ValueError("Downloaded asset is empty.")
        return destination
    finally:
        response.close()


def _extract_archive_to_cache(url: str, archive_path: Path, cache_dir: Path) -> Path:
    destination = cache_dir / Path(f"theme-{hashlib.sha256(url.encode()).hexdigest()[:10]}")
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)

    if zipfile.is_zipfile(archive_path):
        _safe_extract_zip(archive_path, destination)
    elif tarfile.is_tarfile(archive_path):
        _safe_extract_tar(archive_path, destination)
    else:
        raise ValueError("Uploaded asset is not a supported archive.")

    return _locate_grub_theme_root(destination)


def _download_grub_theme_to_cache(url: str, cache_dir: Path) -> Path:
    archive_path = _download_file_to_cache(
        url,
        cache_dir=cache_dir,
        max_bytes=_THEME_ARCHIVE_CACHE_MAX_BYTES,
        detect_extension=_theme_archive_extension_from_url,
    )
    return _extract_archive_to_cache(url, archive_path, cache_dir)


def browse_image_from_url(
    window,
    line_edit,
    *,
    title: str,
    prompt: str,
) -> None:
    """Ask for an image URL, download it to local cache, and fill the target path field."""
    raw_url, ok = QInputDialog.getText(window, title, prompt)
    if not ok:
        return
    url = raw_url.strip()
    if not url:
        return

    try:
        cache_dir = _project_cache_dir(window)
        downloaded = _download_image_to_cache(url, cache_dir)
        line_edit.setText(str(downloaded))
        _safe_log(window, f"Imported background image: {downloaded.name}")
    except Exception as exc:  # pragma: no cover - user-facing path
        QMessageBox.warning(window, "DistroForge", f"Failed to import image URL.\n{exc}")


def browse_unsplash_image(
    window,
    line_edit,
    *,
    title: str,
    prompt: str,
    open_url: str = _UNSPLASH_SEARCH_URL,
) -> None:
    """Open Unsplash and then import an image URL into a local file path field."""
    webbrowser.open(open_url)
    browse_image_from_url(window, line_edit, title=title, prompt=prompt)


def image_url_picker(
    window,
    line_edit,
    *,
    title: str,
    prompt: str,
    icon: str = "open",
):
    return button(
        "From URL",
        lambda: browse_image_from_url(window, line_edit, title=title, prompt=prompt),
        icon,
    )


def unsplash_picker(
    window,
    line_edit,
    *,
    title: str,
    prompt: str,
    open_url: str = _UNSPLASH_SEARCH_URL,
    icon: str = "image",
):
    return button(
        "Unsplash",
        lambda: browse_unsplash_image(
            window,
            line_edit,
            title=title,
            prompt=prompt,
            open_url=open_url,
        ),
        icon,
    )


def browse_grub_theme_from_url(
    window,
    line_edit,
    *,
    title: str,
    prompt: str,
) -> None:
    """Ask for a GRUB theme archive URL and import it into the project if possible."""
    raw_url, ok = QInputDialog.getText(window, title, prompt)
    if not ok:
        return
    url = raw_url.strip()
    if not url:
        return

    try:
        cache_dir = _project_cache_dir(window)
        extracted_root = _download_grub_theme_to_cache(url, cache_dir)
        title_text, theme_version = _validate_grub_theme_root(extracted_root)
        if getattr(window, "project", None) is not None:
            project_grub = _apply_to_project_grub_theme(
                window,
                extracted_root,
                url,
                title=title_text,
            )
        else:
            project_grub = extracted_root
        line_edit.setText(str(project_grub))
        _safe_log(
            window,
            f"Imported GRUB theme: {project_grub.name} "
            + (f"({title_text}) " if title_text else "")
            + f"from {url}",
        )
        if theme_version:
            _safe_log(window, f"Detected GRUB theme version: {theme_version}")
    except Exception as exc:  # pragma: no cover - user-facing path
        QMessageBox.warning(window, "DistroForge", f"Failed to import GRUB theme URL.\n{exc}")


def grub_theme_url_picker(
    window,
    line_edit,
    *,
    title: str,
    prompt: str,
    icon: str = "open",
):
    return button(
        "From URL",
        lambda: browse_grub_theme_from_url(window, line_edit, title=title, prompt=prompt),
        icon,
    )


def clear_field_button(line_edit, text: str = "None", icon: str = ""):
    """Return a quick way to reset a text field."""

    return button(
        text,
        lambda: line_edit.setText(""),
        icon,
    )


def browse_spinner_gallery(_window):
    """Open a curated source of Plymouth themes/spinners."""

    return button(
        "Spinner gallery",
        lambda: webbrowser.open(_PLYMOUTH_SPINNER_GALLERY_URL),
        "open",
    )


def browse_grub_theme_gallery(_window):
    """Open a curated source of GRUB themes."""

    return button(
        "GRUB theme gallery",
        lambda: webbrowser.open(_GRUB_THEME_GALLERY_URL),
        "open",
    )


def browse_into(
    window,
    line_edit,
    *,
    title: str,
    mode: str = "open",
    file_filter: str = "",
) -> None:
    """Fill a path field from the native file manager.

    A GUI affordance over an existing capability -- typing a path. The CLI takes
    the same path as an argument, so parity is untouched; only the entry method
    changes (recognition over recall). The dialog opens at whatever the field
    already holds; a cancelled dialog leaves the field unchanged.
    """
    start = line_edit.text().strip()
    if mode == "dir":
        chosen = QFileDialog.getExistingDirectory(window, title, start)
    elif mode == "save":
        chosen, _ = QFileDialog.getSaveFileName(window, title, start, filter=file_filter)
    else:
        chosen, _ = QFileDialog.getOpenFileName(window, title, start, filter=file_filter)
    if chosen:
        line_edit.setText(chosen)


def picker(
    window,
    line_edit,
    *,
    title: str,
    mode: str = "open",
    file_filter: str = "",
    icon: str | None = None,
):
    """A 'Select' button wired to browse_into for one path field.

    One canonical helper, not a dozen bespoke handlers: every path field gets the
    same labelled affordance and the same behaviour.
    """
    if icon is None:
        icon = "save" if mode == "save" else "open"
    return button(
        "Select",
        lambda: browse_into(window, line_edit, title=title, mode=mode, file_filter=file_filter),
        icon,
    )
