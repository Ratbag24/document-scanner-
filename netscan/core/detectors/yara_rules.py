"""YARA detector.

YARA is where you express "this specific family/campaign looks like X" once the
structural checks have told you a file is worth a closer look. yara-python is an
optional dependency: with no rules or no module installed the detector reports
itself unavailable and the rest of the pipeline runs unchanged.
"""

from __future__ import annotations

from pathlib import Path

from ..result import Finding, Verdict
from .base import Detector, ScanTarget

try:  # pragma: no cover - import guard
    import yara  # type: ignore
except ImportError:  # pragma: no cover
    yara = None  # type: ignore

# Rule metadata may set `severity = "suspicious"` to downgrade a match.
_SEVERITY = {
    "malicious": Verdict.MALICIOUS,
    "suspicious": Verdict.SUSPICIOUS,
    "info": Verdict.UNKNOWN,
}


class YaraDetector(Detector):
    """Pattern matching with a compiled YARA ruleset."""

    name = "yara"

    def __init__(self, rules_dir: Path | None = None, timeout: int = 20):
        self.rules_dir = rules_dir
        self.timeout = timeout
        self._rules = None
        self._error: str | None = None
        self._rule_count = 0
        self.compile()

    def compile(self) -> None:
        """Compile every .yar/.yara file under rules_dir into one ruleset."""
        self._rules = None
        self._rule_count = 0
        if yara is None:
            self._error = "yara-python is not installed (pip install yara-python)"
            return
        if self.rules_dir is None or not self.rules_dir.is_dir():
            self._error = f"rules directory not found: {self.rules_dir}"
            return
        sources = sorted(
            p for p in self.rules_dir.rglob("*")
            if p.suffix in (".yar", ".yara") and p.is_file()
        )
        if not sources:
            self._error = f"no .yar/.yara files in {self.rules_dir}"
            return
        try:
            self._rules = yara.compile(filepaths={str(p): str(p) for p in sources})
            self._rule_count = len(sources)
            self._error = None
        except Exception as exc:  # a broken rule must not take the scanner down
            self._error = f"rule compilation failed: {exc}"

    @property
    def available(self) -> bool:
        return self._rules is not None

    def unavailable_reason(self) -> str:
        return self._error or ""

    @property
    def rule_files(self) -> int:
        return self._rule_count

    def inspect(self, target: ScanTarget) -> list[Finding]:
        if self._rules is None:
            return []
        try:
            matches = self._rules.match(data=target.data, timeout=self.timeout)
        except Exception as exc:
            return [Finding(self.name, "match_error", Verdict.UNKNOWN, str(exc), target.path)]

        out: list[Finding] = []
        for match in matches:
            meta = getattr(match, "meta", {}) or {}
            verdict = _SEVERITY.get(str(meta.get("severity", "")).lower(), Verdict.MALICIOUS)
            detail = str(meta.get("description", "") or f"matched YARA rule {match.rule}")
            out.append(Finding(self.name, match.rule, verdict, detail, target.path))
        return out
