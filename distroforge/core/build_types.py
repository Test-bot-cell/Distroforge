from __future__ import annotations

from typing import Protocol


class BuildStepLike(Protocol):
    @property
    def phase(self) -> object: ...

    @property
    def title(self) -> str: ...

    @property
    def detail(self) -> str: ...


class BuildReportLike(Protocol):
    @property
    def steps(self) -> list[BuildStepLike]: ...
