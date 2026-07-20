# Beginner, Power, Trust Trilogy

This is the UX contract for the three-stage DistroForge entry path.

## Move 1: Beginner-first

Use one guided entry point:

```bash
distroforge wizard MyDesk ./my-desk --profile desktop
distroforge new MyUsb ./my-usb --profile portable
```

Available beginner-first profiles are `portable`, `desktop`, `dev`, and `kiosk`.
Each renders the same human plan used by the GUI Command Center: suggested
desktop environment, mirror policy, partition stance, persistence stance,
security note, apps added/removed, rough duration, expected ISO volume, risks,
and a chunked build plan preview. `--plan-only` previews without writing files.

## Move 2: Power-user composable

Composable profile priority is explicit:

1. project packages
2. `--base`
3. repeated `--layer`
4. repeated `--override`

Later layers win package conflicts. Reinstalling a previously removed package,
or removing a previously installed package, is reported in `conflicts`.

```bash
distroforge profile resolve ./my-desk --base desktop --layer developer --override privacy
distroforge profile resolve ./my-desk --config examples/composable-profile.yaml --json
distroforge profile show developer
distroforge profile diff ./my-desk desktop --against lightweight
```

`--json` emits a machine-readable build contract with resolved packages,
removals, layer order, conflict notes, and replayability metadata.

## Move 3: Trust and Review

Local history is project-owned and replayable:

```bash
distroforge history list ./my-desk
distroforge history replay ./my-desk ENTRY_ID --output replay.yaml
distroforge build ./my-desk --definition replay.yaml
```

History entries are written under `.distroforge/history.jsonl` and store clean
definitions rather than mutating the build pipeline. Replay writes a fresh
definition and prints the next build command.

## Release Checklist

- Run the noob flow with at least one profile: `wizard --profile desktop`.
- Run the power flow with `profile resolve --json`.
- Replay one saved entry with `history replay`.
- Run the existing build dry-run tests.
- Run GUI smoke tests that cover Command Center reachability.
- Keep DE/icon/dock regression tests green before packaging.
