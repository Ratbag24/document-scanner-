"""Verdict and result types shared by every detector."""

from __future__ import annotations

import enum
import json
from dataclasses import asdict, dataclass, field
from typing import Any


class Verdict(enum.IntEnum):
    """Ordered severity. Higher always wins when results are merged."""

    CLEAN = 0
    UNKNOWN = 1       # could not be inspected (encrypted archive, unsupported type)
    SUSPICIOUS = 2    # structural oddity, no signature match
    MALICIOUS = 3     # signature or rule match

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    """A single observation about a file.

    `detector` is the producing detector's name, `rule` the specific
    signature/check that fired, and `path` the location inside a container
    (e.g. "archive.zip -> payload.exe") or None for the file itself.
    """

    detector: str
    rule: str
    verdict: Verdict
    detail: str = ""
    path: str | None = None

    def __str__(self) -> str:
        where = f" [{self.path}]" if self.path else ""
        return (f"{self.verdict.label.upper()}: {self.rule}{where} "
                f"({self.detector}) {self.detail}").rstrip()


@dataclass
class ScanResult:
    """Aggregate outcome for one scanned object."""

    name: str
    size: int
    sha256: str
    media_type: str = "application/octet-stream"
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def verdict(self) -> Verdict:
        """Worst finding wins; a file with no findings at all is CLEAN."""
        if not self.findings:
            return Verdict.CLEAN
        return max(f.verdict for f in self.findings)

    @property
    def blocked(self) -> bool:
        return self.verdict >= Verdict.MALICIOUS

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def summary(self) -> str:
        if not self.findings:
            return f"{self.verdict.label} {self.name} ({self.size} bytes, {self.media_type})"
        top = ", ".join(sorted({f.rule for f in self.findings}))
        return f"{self.verdict.label} {self.name} ({self.media_type}): {top}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.label
        d["findings"] = [{**asdict(f), "verdict": f.verdict.label} for f in self.findings]
        return d

    def to_json(self) -> str:
        """One-line JSON, suitable for appending to a log or shipping to a SIEM."""
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)
