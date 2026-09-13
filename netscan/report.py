"""Result output: human-readable console lines and machine-readable JSONL.

JSONL is the shipping format because every log collector already parses it, and
one result per line survives truncation -- a half-written line loses one scan
rather than corrupting the file.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

from .core.result import ScanResult, Verdict

_COLORS = {
    Verdict.CLEAN: "\033[32m",
    Verdict.UNKNOWN: "\033[90m",
    Verdict.SUSPICIOUS: "\033[33m",
    Verdict.MALICIOUS: "\033[31m",
}
_RESET = "\033[0m"

_SYMBOLS = {
    Verdict.CLEAN: "ok  ",
    Verdict.UNKNOWN: "?   ",
    Verdict.SUSPICIOUS: "WARN",
    Verdict.MALICIOUS: "BAD ",
}


def _use_color(stream) -> bool:
    return stream.isatty() and os.environ.get("NO_COLOR") is None


class Reporter:
    """Writes results to the console and, optionally, a JSONL file."""

    def __init__(self, log_file: Path | None = None, quiet_clean: bool = False,
                 stream=sys.stdout):
        self.log_file = log_file
        self.quiet_clean = quiet_clean
        self.stream = stream
        self.color = _use_color(stream)
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def report(self, result: ScanResult, source: str | None = None) -> None:
        if self.log_file:
            self._write_log(result, source)
        if self.quiet_clean and result.verdict <= Verdict.UNKNOWN:
            return
        self._write_console(result, source)

    def _write_log(self, result: ScanResult, source: str | None) -> None:
        record = result.to_dict()
        record["timestamp"] = time.time()
        if source:
            record["source"] = source
        import json
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        with self.log_file.open("a") as fh:  # type: ignore[union-attr]
            fh.write(line + "\n")

    def _write_console(self, result: ScanResult, source: str | None) -> None:
        verdict = result.verdict
        symbol = _SYMBOLS[verdict]
        if self.color:
            symbol = f"{_COLORS[verdict]}{symbol}{_RESET}"
        where = f" from {source}" if source else ""
        print(f"[{symbol}] {result.name}{where} "
              f"({_human(result.size)}, {result.meta.get('file_type', result.media_type)})",
              file=self.stream)
        for finding in sorted(result.findings, key=lambda f: -f.verdict):
            if finding.verdict == Verdict.CLEAN:
                continue
            print(f"         {finding}", file=self.stream)
        for error in result.errors:
            print(f"         error: {error}", file=self.stream)
        self.stream.flush()


def quarantine(path: Path, result: ScanResult, quarantine_dir: Path) -> Path:
    """Move a flagged file into quarantine, renamed so it cannot be run.

    The `.quarantined` suffix and 0600 permissions are deliberate: a file sitting
    in a quarantine folder still gets double-clicked by someone eventually.
    """
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in path.name)[:120]
    target = quarantine_dir / f"{stamp}-{result.sha256[:12]}-{safe_name}.quarantined"
    shutil.move(str(path), str(target))
    os.chmod(target, 0o600)
    # Drop the verdict next to the file so the folder is self-describing.
    target.with_suffix(".quarantined.json").write_text(result.to_json() + "\n")
    return target


def _human(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size}B"
