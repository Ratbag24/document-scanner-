"""Detector interface.

A detector inspects one object and returns findings. It must never raise for
malformed input -- hostile files are the normal case here, so parse failures
are reported as findings or errors, not exceptions.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from ..filetype import FileType
from ..result import Finding


@dataclass
class ScanTarget:
    """One object to inspect.

    `name` is the claimed filename (from a URL, Content-Disposition header, or
    archive entry) and is untrusted. `path` is where it sits inside a container,
    used to label findings.
    """

    data: bytes
    name: str | None
    ftype: FileType
    path: str | None = None
    depth: int = 0


class Detector(abc.ABC):
    """Base class for all detectors."""

    name: str = "detector"

    @property
    def available(self) -> bool:
        """False when a required dependency (daemon, ruleset) is missing.

        Unavailable detectors are skipped and reported once at startup rather
        than failing every scan.
        """
        return True

    def unavailable_reason(self) -> str:
        return ""

    @abc.abstractmethod
    def inspect(self, target: ScanTarget) -> list[Finding]:
        """Return findings for `target`. Must not raise."""
        raise NotImplementedError
