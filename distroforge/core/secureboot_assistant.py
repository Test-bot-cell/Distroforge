from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec


@dataclass
class SecureBootAssistantOptions:
    output_dir: Path
    common_name: str = "DistroForge MOK"


class SecureBootAssistant:
    def __init__(self, runner: CommandRunner, options: SecureBootAssistantOptions) -> None:
        self.runner = runner
        self.options = options

    def plan(self) -> None:
        key = self.options.output_dir / "MOK.key"
        cert = self.options.output_dir / "MOK.crt"
        der = self.options.output_dir / "MOK.der"
        self.runner.run(
            CommandSpec(
                argv=(
                    "openssl",
                    "req",
                    "-new",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-nodes",
                    "-days",
                    "3650",
                    "-subj",
                    f"/CN={self.options.common_name}/",
                ),
                description="Generate Secure Boot MOK keypair",
            )
        )
        self.runner.run(
            CommandSpec(
                argv=("openssl", "x509", "-outform", "DER", "-in", str(cert), "-out", str(der)),
                description="Convert MOK certificate to DER for mokutil import",
            )
        )
        self.runner.run(
            CommandSpec(
                argv=("mokutil", "--import", str(der)),
                description="Plan MOK enrollment",
            )
        )
