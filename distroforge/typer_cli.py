from __future__ import annotations

from pathlib import Path

try:
    import typer
except ImportError:  # pragma: no cover - gives a clean launcher error.
    typer = None  # type: ignore[assignment]


def _require_typer():
    if typer is None:
        raise SystemExit(
            "Typer is not installed. Install the optional framework extra or use: python -m distroforge"
        )
    return typer


def _legacy(argv: list[str]) -> None:
    from .cli import main

    main(argv)


def run() -> None:
    typer_mod = _require_typer()
    app = typer_mod.Typer(
        name="distroforge",
        help="Modern Typer facade for DistroForge. Unknown/advanced flags remain available in the legacy CLI.",
        no_args_is_help=True,
    )

    @app.command()
    def releases() -> None:
        _legacy(["releases"])

    @app.command("profile-diff")
    def profile_diff(root: Path, profile: str, json_output: bool = typer_mod.Option(False, "--json")) -> None:
        argv = ["profile", "diff", str(root), profile]
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command("source-starters")
    def source_starters(
        release: str | None = None,
        json_output: bool = typer_mod.Option(False, "--json"),
    ) -> None:
        argv = ["source-starters"]
        if release:
            argv.extend(["--release", release])
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command("mirrors-doctor")
    def mirrors_doctor(
        root: Path,
        definition: Path | None = None,
        json_output: bool = typer_mod.Option(False, "--json"),
    ) -> None:
        argv = ["mirrors", "doctor", str(root)]
        if definition:
            argv.extend(["--definition", str(definition)])
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command()
    def new(
        name: str,
        root: Path,
        release: str = "26.04",
        starter: str | None = None,
        source_iso: Path | None = None,
        previous_project: Path | None = None,
    ) -> None:
        argv = ["new", name, str(root), "--release", release]
        if starter:
            argv.extend(["--starter", starter])
        if source_iso:
            argv.extend(["--source-iso", str(source_iso)])
        if previous_project:
            argv.extend(["--previous-project", str(previous_project)])
        _legacy(argv)

    @app.command()
    def doctor(
        install: bool = False,
        include_optional: bool = False,
        no_sudo: bool = False,
        python: bool = False,
        debian_dev: bool = False,
        fix_python: bool = False,
    ) -> None:
        argv = ["doctor"]
        if fix_python:
            argv.append("--fix-python")
        if python:
            argv.append("--python")
        if debian_dev:
            argv.append("--debian-dev")
        if install:
            argv.append("--install")
        if include_optional:
            argv.append("--include-optional")
        if no_sudo:
            argv.append("--no-sudo")
        _legacy(argv)

    @app.command()
    def gui() -> None:
        _legacy(["gui"])

    @app.command()
    def build(
        root: Path,
        source_iso: Path | None = None,
        desktop: str | None = None,
        execute: bool = False,
        no_sudo: bool = False,
        ci: bool = False,
    ) -> None:
        argv = ["build", str(root)]
        if source_iso:
            argv.extend(["--source-iso", str(source_iso)])
        if desktop:
            argv.extend(["--desktop", desktop])
        if execute:
            argv.append("--execute")
        if no_sudo:
            argv.append("--no-sudo")
        if ci:
            argv.append("--ci")
        _legacy(argv)

    @app.command()
    def explain(root: Path) -> None:
        from .commands.explain import render_explain

        typer_mod.echo(render_explain(root))

    @app.command()
    def plugins(root: Path) -> None:
        from .commands.plugins import render_plugins

        typer_mod.echo(render_plugins(root))

    @app.command("export-recipe")
    def export_recipe(root: Path, target: Path) -> None:
        from .commands.recipes import export_project_recipe

        export_project_recipe(root, target)
        typer_mod.echo(f"Wrote {target}")

    @app.command("export-build-preset")
    def export_build_preset(
        root: Path,
        target: Path,
        channel: str | None = None,
        revision: str | None = None,
        notes: str | None = None,
    ) -> None:
        argv = ["export-build-preset", str(root), str(target)]
        if channel:
            argv.extend(["--channel", channel])
        if revision:
            argv.extend(["--revision", revision])
        if notes:
            argv.extend(["--notes", notes])
        _legacy(argv)

    @app.command("ux-audit")
    def ux_audit(
        root: Path,
        definition: Path | None = None,
        json_output: bool = typer_mod.Option(False, "--json"),
    ) -> None:
        argv = ["ux-audit", str(root)]
        if definition:
            argv.extend(["--definition", str(definition)])
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command("branding-audit")
    def branding_audit(
        root: Path,
        definition: Path | None = None,
        mode: str = "internal",
        json_output: bool = typer_mod.Option(False, "--json"),
    ) -> None:
        argv = ["branding", "audit", str(root), "--mode", mode]
        if definition:
            argv.extend(["--definition", str(definition)])
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command("branding-validate")
    def branding_validate(
        root: Path,
        definition: Path | None = None,
        mode: str = "redistributable",
    ) -> None:
        argv = ["branding", "validate", str(root), "--mode", mode]
        if definition:
            argv.extend(["--definition", str(definition)])
        _legacy(argv)

    @app.command("branding-clearance")
    def branding_clearance(
        root: Path,
        definition: Path | None = None,
        mode: str = "redistributable",
        output: Path | None = None,
    ) -> None:
        argv = ["branding", "clearance", str(root), "--mode", mode]
        if definition:
            argv.extend(["--definition", str(definition)])
        if output:
            argv.extend(["--output", str(output)])
        _legacy(argv)

    @app.command("branding-preview")
    def branding_preview(
        root: Path,
        definition: Path | None = None,
        target: str = "all",
        output_dir: Path | None = None,
    ) -> None:
        argv = ["branding", "preview", str(root), "--target", target]
        if definition:
            argv.extend(["--definition", str(definition)])
        if output_dir:
            argv.extend(["--output-dir", str(output_dir)])
        _legacy(argv)

    @app.command("debrand-scan")
    def debrand_scan(
        root: Path,
        definition: Path | None = None,
        json_output: bool = typer_mod.Option(False, "--json"),
    ) -> None:
        argv = ["debrand", "scan", str(root)]
        if definition:
            argv.extend(["--definition", str(definition)])
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command()
    def readiness(
        root: Path,
        definition: Path | None = None,
        json_output: bool = typer_mod.Option(False, "--json"),
    ) -> None:
        argv = ["readiness", str(root)]
        if definition:
            argv.extend(["--definition", str(definition)])
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command("dry-run-report")
    def dry_run_report(
        root: Path,
        definition: Path | None = None,
        json_output: bool = typer_mod.Option(False, "--json"),
        no_command_simulation: bool = False,
    ) -> None:
        argv = ["dry-run-report", str(root)]
        if definition:
            argv.extend(["--definition", str(definition)])
        if json_output:
            argv.append("--json")
        if no_command_simulation:
            argv.append("--no-command-simulation")
        _legacy(argv)

    @app.command("explain-risk")
    def explain_risk(root: Path, definition: Path | None = None) -> None:
        argv = ["explain-risk", str(root)]
        if definition:
            argv.extend(["--definition", str(definition)])
        _legacy(argv)

    @app.command("build-phases")
    def build_phases(stage: str | None = None) -> None:
        argv = ["build-phases"]
        if stage:
            argv.extend(["--stage", stage])
        _legacy(argv)

    @app.command()
    def glossary(term: str | None = typer_mod.Argument(None)) -> None:
        argv = ["glossary"]
        if term:
            argv.append(term)
        _legacy(argv)

    @app.command("guided-recipe")
    def guided_recipe(
        name: str | None = typer_mod.Argument(None),
        json_output: bool = typer_mod.Option(False, "--json"),
    ) -> None:
        argv = ["guided-recipe"]
        if name:
            argv.append(name)
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command("ai-review")
    def ai_review(
        root: Path,
        definition: Path | None = None,
        json_output: bool = typer_mod.Option(False, "--json"),
    ) -> None:
        argv = ["ai-review", str(root)]
        if definition:
            argv.extend(["--definition", str(definition)])
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command("forgeadvisor-explain-log")
    def forgeadvisor_explain_log(
        log: Path,
        json_output: bool = typer_mod.Option(False, "--json"),
    ) -> None:
        argv = ["forgeadvisor", "explain-log", str(log)]
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command("forgeadvisor-review-build")
    def forgeadvisor_review_build(
        root: Path,
        definition: Path | None = None,
        json_output: bool = typer_mod.Option(False, "--json"),
    ) -> None:
        argv = ["forgeadvisor", "review-build", str(root)]
        if definition:
            argv.extend(["--definition", str(definition)])
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command("forgeadvisor-doctor-ai")
    def forgeadvisor_doctor_ai(json_output: bool = typer_mod.Option(False, "--json")) -> None:
        argv = ["forgeadvisor", "doctor-ai"]
        if json_output:
            argv.append("--json")
        _legacy(argv)

    @app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
    def legacy(ctx: typer.Context) -> None:
        _legacy(list(ctx.args))

    app()


if __name__ == "__main__":
    run()
