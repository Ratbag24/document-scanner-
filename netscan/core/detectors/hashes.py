"""Hash reputation detector.

Blocklists and allowlists are plain text files, one SHA-256 per line, with
optional `<hash>  <label>` on the same line and `#` comments. That format is
what every threat-intel feed already exports, so a feed can be dropped in with
no conversion step.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from ..result import Finding, Verdict
from .base import Detector, ScanTarget


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load(path: Path) -> dict[str, str]:
    """Parse a hash list into {hash: label}. Missing files yield no entries."""
    entries: dict[str, str] = {}
    if not path.is_file():
        return entries
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        digest = parts[0].lower()
        if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
            continue
        entries[digest] = parts[1].strip() if len(parts) > 1 else ""
    return entries


class HashDetector(Detector):
    """Exact-match lookup against known-bad and known-good digests."""

    name = "hashes"

    def __init__(self, blocklists: list[Path] | None = None, allowlists: list[Path] | None = None):
        self.blocklist_paths = blocklists or []
        self.allowlist_paths = allowlists or []
        self.blocked: dict[str, str] = {}
        self.allowed: dict[str, str] = {}
        self._mtimes: dict[Path, float] = {}
        self.reload()

    def reload(self) -> None:
        """(Re)read every list. Cheap enough to call on a timer or SIGHUP."""
        self.blocked = {}
        self.allowed = {}
        for path in self.blocklist_paths:
            self.blocked.update(_load(path))
        for path in self.allowlist_paths:
            self.allowed.update(_load(path))
        self._mtimes = {
            p: p.stat().st_mtime
            for p in (*self.blocklist_paths, *self.allowlist_paths)
            if p.is_file()
        }

    def reload_if_changed(self) -> bool:
        """Reload when any list file changed on disk. Returns True if reloaded."""
        for path in (*self.blocklist_paths, *self.allowlist_paths):
            mtime = path.stat().st_mtime if path.is_file() else None
            if mtime != self._mtimes.get(path):
                self.reload()
                return True
        return False

    @property
    def available(self) -> bool:
        return bool(self.blocked or self.allowed)

    def unavailable_reason(self) -> str:
        if self.blocked or self.allowed:
            return ""
        configured = self.blocklist_paths + self.allowlist_paths
        if not configured:
            return "no hash lists configured"
        return f"no usable entries in {', '.join(str(p) for p in configured)}"

    def inspect(self, target: ScanTarget) -> list[Finding]:
        digest = sha256_of(target.data)
        if digest in self.blocked:
            label = self.blocked[digest] or "known-bad hash"
            return [Finding(self.name, "known_bad_hash", Verdict.MALICIOUS, label, target.path)]
        if digest in self.allowed:
            # Recorded for the audit trail; CLEAN never raises the verdict.
            return [Finding(self.name, "known_good_hash", Verdict.CLEAN,
                            self.allowed[digest] or "allowlisted", target.path)]
        return []
