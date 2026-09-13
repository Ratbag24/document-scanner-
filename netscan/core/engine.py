"""Scan engine: unpacks an object, runs every detector over every part.

The engine owns the policy decisions detectors deliberately stay out of:
what to unpack, how much work one object may cost, and how findings from the
parts roll up into a single verdict for the whole.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .detectors.base import Detector, ScanTarget
from .detectors.hashes import sha256_of
from .filetype import identify
from .result import Finding, ScanResult, Verdict
from .unpack import UnpackLimits, unpack


@dataclass
class EngineConfig:
    """Engine-wide policy."""

    unpack_containers: bool = True
    unpack_limits: UnpackLimits = field(default_factory=UnpackLimits)
    # Objects above this are hashed and logged but not content-scanned; scanning
    # a 4GB ISO inline would stall the pipeline for every other request.
    max_scan_bytes: int = 100 * 1024 * 1024
    # Treat "could not inspect" as suspicious. Off by default because encrypted
    # archives and unsupported formats are common in normal traffic.
    unknown_is_suspicious: bool = False


class ScanEngine:
    """Runs a fixed set of detectors over an object and its unpacked contents."""

    def __init__(self, detectors: list[Detector], config: EngineConfig | None = None):
        self.detectors = detectors
        self.config = config or EngineConfig()

    @property
    def active_detectors(self) -> list[Detector]:
        return [d for d in self.detectors if d.available]

    def status(self) -> dict[str, str]:
        """Per-detector readiness, for logging at startup and on a health check."""
        return {
            d.name: "ready" if d.available else (d.unavailable_reason() or "unavailable")
            for d in self.detectors
        }

    def scan(self, data: bytes, name: str | None = None) -> ScanResult:
        started = time.monotonic()
        ftype = identify(data, name)
        result = ScanResult(
            name=name or "(unnamed)",
            size=len(data),
            sha256=sha256_of(data),
            media_type=ftype.media_type,
            meta={"file_type": ftype.label},
        )

        if len(data) > self.config.max_scan_bytes:
            result.add(Finding("engine", "too_large_to_scan", Verdict.UNKNOWN,
                               f"{len(data)} bytes exceeds the {self.config.max_scan_bytes} "
                               "byte scan limit; recorded by hash only"))
            return self._finish(result, started)

        # The object itself.
        root = ScanTarget(data=data, name=name, ftype=ftype, path=None, depth=0)
        result.extend(self._run_detectors(root, result))

        # ...then everything inside it.
        if self.config.unpack_containers and ftype.container:
            members, unpack_findings = unpack(data, name or "", ftype, self.config.unpack_limits)
            result.extend(unpack_findings)
            result.meta["contained_objects"] = len(members)
            for member in members:
                target = ScanTarget(data=member.data, name=member.name, ftype=member.ftype,
                                   path=member.path, depth=member.depth)
                result.extend(self._run_detectors(target, result))

        return self._finish(result, started)

    def _finish(self, result: ScanResult, started: float) -> ScanResult:
        """Apply end-of-scan policy. Every return path goes through here so an
        early exit cannot skip it."""
        if self.config.unknown_is_suspicious:
            self._escalate_unknowns(result)
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    def _run_detectors(self, target: ScanTarget, result: ScanResult) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self.detectors:
            if not detector.available:
                continue
            try:
                findings.extend(detector.inspect(target))
            except Exception as exc:
                # Never let one detector's bug suppress the others' findings.
                where = target.path or target.name
                result.errors.append(f"{detector.name} failed on {where}: {exc}")
        return findings

    @staticmethod
    def _escalate_unknowns(result: ScanResult) -> None:
        escalated = [
            Finding(f.detector, f.rule, Verdict.SUSPICIOUS, f.detail, f.path)
            if f.verdict == Verdict.UNKNOWN else f
            for f in result.findings
        ]
        result.findings = escalated
