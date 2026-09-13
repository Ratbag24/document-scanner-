"""Passive ingestion: scan files Zeek carves out of network traffic.

Zeek reassembles TCP streams and writes any file it sees crossing the wire into
an extraction directory. This watcher picks them up, scans them, and correlates
each one back to the connection that carried it using Zeek's own files.log --
so an alert says "this came from 192.168.1.42 over HTTP", not just "a bad file
appeared".

This path is read-only with respect to the network: it cannot block a download
and cannot break a connection. It sees only unencrypted traffic.
"""

from __future__ import annotations

import contextlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

from ..core.engine import ScanEngine
from ..core.result import Verdict
from ..report import Reporter, quarantine


@dataclass
class FileContext:
    """What Zeek knows about where an extracted file came from."""

    fuid: str
    source: str = ""          # HTTP, FTP_DATA, SMTP, SMB, ...
    mime_type: str = ""
    filename: str = ""        # as declared by the server
    tx_hosts: str = ""        # who sent it
    rx_hosts: str = ""        # who received it

    def describe(self) -> str:
        bits = [b for b in (self.source, f"{self.tx_hosts} -> {self.rx_hosts}"
                            if self.tx_hosts or self.rx_hosts else "") if b]
        return " ".join(bits) or "zeek"


class FilesLogIndex:
    """Tails Zeek's files.log and indexes metadata by file UID.

    Zeek writes the log entry when a file transfer *completes*, which can be
    after the extracted file appears on disk, so lookups retry briefly rather
    than giving up on the first miss.
    """

    def __init__(self, log_path: Path, max_entries: int = 20000):
        self.log_path = log_path
        self.max_entries = max_entries
        self._index: dict[str, FileContext] = {}
        self._offset = 0
        self._fields: list[str] = []
        self._inode: int | None = None

    def refresh(self) -> None:
        """Read whatever has been appended since the last call."""
        if not self.log_path.is_file():
            return
        stat = self.log_path.stat()
        if self._inode is not None and stat.st_ino != self._inode:
            self._offset = 0  # log rotated
            self._fields = []
        self._inode = stat.st_ino
        if stat.st_size < self._offset:
            self._offset = 0  # truncated
        try:
            with self.log_path.open("r", errors="replace") as fh:
                fh.seek(self._offset)
                for line in fh:
                    if not line.endswith("\n"):
                        break  # partial line; re-read it next time
                    self._offset += len(line.encode("utf-8", "replace"))
                    self._ingest(line.rstrip("\n"))
        except OSError:
            return
        self._trim()

    def _ingest(self, line: str) -> None:
        if line.startswith("#"):
            if line.startswith("#fields"):
                self._fields = line.split("\t")[1:]
            return
        if line.startswith("{"):
            self._ingest_json(line)
            return
        if not self._fields:
            return
        values = line.split("\t")
        # strict=False: Zeek pads or truncates rows on rotation boundaries.
        row = dict(zip(self._fields, values, strict=False))
        self._store(row)

    def _ingest_json(self, line: str) -> None:
        try:
            self._store(json.loads(line))
        except (json.JSONDecodeError, TypeError):
            return

    def _store(self, row: dict) -> None:
        fuid = str(row.get("fuid") or row.get("id") or "").strip()
        if not fuid or fuid == "-":
            return
        self._index[fuid] = FileContext(
            fuid=fuid,
            source=_clean(row.get("source")),
            mime_type=_clean(row.get("mime_type")),
            filename=_clean(row.get("filename")),
            tx_hosts=_clean(row.get("tx_hosts")),
            rx_hosts=_clean(row.get("rx_hosts")),
        )

    def _trim(self) -> None:
        if len(self._index) <= self.max_entries:
            return
        # dicts preserve insertion order, so the oldest keys come first.
        excess = len(self._index) - self.max_entries
        for key in list(self._index)[:excess]:
            self._index.pop(key, None)

    def lookup(self, fuid: str) -> FileContext | None:
        return self._index.get(fuid)


def _clean(value) -> str:
    """Normalize a Zeek field: '-' and '(empty)' mean absent; lists get joined."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value)
    text = str(value).strip()
    return "" if text in ("-", "(empty)") else text


def parse_extract_name(name: str) -> tuple[str, str]:
    """Pull (source, fuid) out of a Zeek extracted-file name.

    Zeek's default is `extract-<ts>-<source>-<fuid>`, e.g.
    `extract-1699999999.123456-HTTP-FabcDEF123`. Returns empty strings for names
    that do not follow it.
    """
    if not name.startswith("extract-"):
        return "", ""
    parts = name[len("extract-"):].split("-")
    if len(parts) < 3:
        return "", ""
    return parts[-2], parts[-1]


class ZeekFileWatcher:
    """Polls Zeek's extraction directory and scans each completed file."""

    def __init__(
        self,
        engine: ScanEngine,
        extract_dir: Path,
        reporter: Reporter,
        files_log: Path | None = None,
        quarantine_dir: Path | None = None,
        delete_clean: bool = True,
        poll_interval: float = 1.0,
        settle_seconds: float = 1.5,
        drain_timeout: float = 60.0,
    ):
        self.engine = engine
        self.extract_dir = extract_dir
        self.reporter = reporter
        self.quarantine_dir = quarantine_dir
        self.delete_clean = delete_clean
        self.poll_interval = poll_interval
        self.settle_seconds = settle_seconds
        self.drain_timeout = drain_timeout
        self.index = FilesLogIndex(files_log) if files_log else None
        self._pending: dict[Path, tuple[int, float]] = {}
        self.stats = {"scanned": 0, "malicious": 0, "suspicious": 0, "errors": 0}

    # -- main loop ----------------------------------------------------------

    def run(self, once: bool = False) -> None:
        """Watch until interrupted.

        `once` drains the current backlog and returns. It cannot simply do a
        single pass: a file is only scanned once its size has held steady across
        two polls, so one pass would register everything as pending and scan
        nothing. Instead it polls until nothing is pending, bounded by
        `drain_timeout` so a directory Zeek is actively writing to cannot make a
        one-shot run hang forever.
        """
        self.extract_dir.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.drain_timeout
        while True:
            if self.index:
                self.index.refresh()
            for path in self._ready_files():
                self.process(path)
            if once and (not self._pending or time.monotonic() >= deadline):
                return
            time.sleep(self.poll_interval)

    def _ready_files(self) -> list[Path]:
        """Files whose size has stopped changing -- Zeek writes them progressively.

        Scanning a partially written file would produce a verdict on a truncated
        object, so we require the size to hold steady across two polls.
        """
        ready: list[Path] = []
        now = time.monotonic()
        try:
            entries = [p for p in self.extract_dir.iterdir() if p.is_file()]
        except OSError:
            return ready

        seen: set[Path] = set()
        for path in entries:
            if path.suffix in (".quarantined", ".json"):
                continue
            seen.add(path)
            try:
                size = path.stat().st_size
            except OSError:
                continue
            previous = self._pending.get(path)
            if previous is None or previous[0] != size:
                self._pending[path] = (size, now)
                continue
            if now - previous[1] >= self.settle_seconds:
                ready.append(path)
        # Forget files that vanished between polls.
        for path in list(self._pending):
            if path not in seen:
                self._pending.pop(path, None)
        return ready

    def process(self, path: Path) -> None:
        self._pending.pop(path, None)
        try:
            data = path.read_bytes()
        except OSError as exc:
            self.stats["errors"] += 1
            print(f"[?   ] could not read {path.name}: {exc}")
            return

        source, fuid = parse_extract_name(path.name)
        context = self.index.lookup(fuid) if (self.index and fuid) else None
        # Use the filename the server declared, not Zeek's synthetic one:
        # extension/content mismatch checks are only meaningful against the name
        # the user's machine would actually save the file under. With no
        # files.log entry we pass None rather than "extract-<ts>-HTTP-<fuid>",
        # which carries no real extension and would only invite false positives.
        declared_name = context.filename if context and context.filename else None

        result = self.engine.scan(data, declared_name)
        if declared_name is None:
            result.name = path.name  # keep the on-disk name for the audit trail
        result.meta["zeek_fuid"] = fuid
        result.meta["zeek_source"] = (context.source if context else source) or "unknown"
        if context:
            result.meta["sender"] = context.tx_hosts
            result.meta["recipient"] = context.rx_hosts
            if context.mime_type:
                result.meta["zeek_mime_type"] = context.mime_type

        self.stats["scanned"] += 1
        if result.verdict == Verdict.MALICIOUS:
            self.stats["malicious"] += 1
        elif result.verdict == Verdict.SUSPICIOUS:
            self.stats["suspicious"] += 1

        self.reporter.report(result, source=context.describe() if context else source or None)
        self._dispose(path, result)

    def _dispose(self, path: Path, result) -> None:
        """Quarantine flagged files; delete clean ones so the disk does not fill."""
        if not path.exists():
            return
        if result.verdict >= Verdict.SUSPICIOUS and self.quarantine_dir:
            try:
                quarantine(path, result, self.quarantine_dir)
            except OSError as exc:
                self.stats["errors"] += 1
                print(f"[?   ] quarantine failed for {path.name}: {exc}")
            return
        if self.delete_clean and result.verdict < Verdict.SUSPICIOUS:
            with contextlib.suppress(OSError):
                path.unlink()
