"""Bounded recursive unpacking of containers.

Unpacking attacker-supplied archives is the single most dangerous thing a
scanner does, so every dimension is capped: recursion depth, total uncompressed
output, entry count, per-entry size, and compression ratio. Extraction happens
entirely in memory, which also means archive entry names can never be used for
path traversal -- they are labels only, never filesystem paths.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from dataclasses import dataclass

from .filetype import FileType, identify
from .result import Finding, Verdict


@dataclass
class UnpackLimits:
    """Resource ceilings for one top-level object."""

    max_depth: int = 4
    max_entries: int = 2000
    max_total_bytes: int = 256 * 1024 * 1024
    max_entry_bytes: int = 64 * 1024 * 1024
    # Uncompressed/compressed ratio above which an entry is worth remarking on.
    # Zero-padded binaries, logs and XML legitimately reach several hundred x,
    # so a high ratio alone is a note, not a refusal.
    max_ratio: int = 500
    # An entry is only treated as a decompression bomb when it is BOTH absurdly
    # compressed and absolutely large. Ratio alone is not the danger -- a 250KB
    # zero-padded executable compresses 900x and is perfectly ordinary. What
    # makes a bomb a bomb is the absolute output size, so that is what refuses
    # extraction. Below this, a high ratio is reported and the entry is still
    # scanned, because refusing to look inside it is how real payloads get
    # missed.
    bomb_min_bytes: int = 32 * 1024 * 1024


@dataclass
class Extracted:
    """One object recovered from a container."""

    data: bytes
    name: str
    path: str
    depth: int
    ftype: FileType


class UnpackBudget:
    """Mutable accounting shared across one object's whole unpack tree."""

    def __init__(self, limits: UnpackLimits):
        self.limits = limits
        self.bytes_out = 0
        self.entries = 0
        self.findings: list[Finding] = []

    def note(self, rule: str, verdict: Verdict, detail: str, path: str | None = None) -> None:
        self.findings.append(Finding("unpack", rule, verdict, detail, path))

    def allow(self, size: int) -> bool:
        """Reserve `size` bytes of output budget, or refuse when exhausted."""
        if self.entries >= self.limits.max_entries:
            return False
        if self.bytes_out + size > self.limits.max_total_bytes:
            return False
        self.entries += 1
        self.bytes_out += size
        return True


def _join(parent: str, child: str) -> str:
    child = child.replace("\\", "/").strip("/") or "(unnamed)"
    return f"{parent} -> {child}" if parent else child


def unpack(data: bytes, name: str, ftype: FileType, limits: UnpackLimits | None = None
           ) -> tuple[list[Extracted], list[Finding]]:
    """Recursively extract `data`, returning members and any unpack findings."""
    budget = UnpackBudget(limits or UnpackLimits())
    out: list[Extracted] = []
    _walk(data, name, ftype, name or "(stream)", 0, budget, out)
    return out, budget.findings


def _walk(data: bytes, name: str, ftype: FileType, path: str, depth: int,
          budget: UnpackBudget, out: list[Extracted]) -> None:
    if not ftype.container:
        return
    if depth >= budget.limits.max_depth:
        budget.note("max_depth_reached", Verdict.UNKNOWN,
                    f"stopped unpacking at depth {depth}; deeper contents not inspected", path)
        return

    media = ftype.media_type
    try:
        if media == "application/zip" or media.startswith("application/vnd.openxmlformats") \
                or media in ("application/java-archive", "application/vnd.android.package-archive"):
            members = _from_zip(data, path, budget)
        elif media == "application/x-tar":
            members = _from_tar(data, path, budget)
        elif media in ("application/gzip", "application/x-bzip2", "application/x-xz"):
            members = _from_stream(data, name, media, path, budget)
        else:
            budget.note("unsupported_container", Verdict.UNKNOWN,
                        f"{ftype.label} cannot be opened for inspection; "
                        "contents are not scanned", path)

            return
    except Exception as exc:
        budget.note("container_unreadable", Verdict.UNKNOWN,
                    f"{ftype.label} could not be parsed: {exc}", path)
        return

    for entry_name, entry_data in members:
        entry_path = _join(path, entry_name)
        entry_type = identify(entry_data, entry_name)
        out.append(Extracted(data=entry_data, name=entry_name, path=entry_path,
                             depth=depth + 1, ftype=entry_type))
        _walk(entry_data, entry_name, entry_type, entry_path, depth + 1, budget, out)


def _from_zip(data: bytes, path: str, budget: UnpackBudget) -> list[tuple[str, bytes]]:
    members: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                budget.note("encrypted_archive_entry", Verdict.UNKNOWN,
                            "password-protected entry cannot be scanned -- a common way to "
                            "smuggle malware past scanners",
                            _join(path, info.filename))
                continue
            if not _check_entry(info.filename, info.file_size, info.compress_size, path, budget):
                continue
            if not budget.allow(info.file_size):
                budget.note("unpack_budget_exhausted", Verdict.UNKNOWN,
                            "archive too large or has too many entries; remaining "
                            "contents not scanned", path)
                break
            with zf.open(info) as fh:
                members.append((info.filename, fh.read(budget.limits.max_entry_bytes)))
    return members


def _from_tar(data: bytes, path: str, budget: UnpackBudget) -> list[tuple[str, bytes]]:
    members: list[tuple[str, bytes]] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for info in tf:
            if not info.isfile():
                continue
            if not _check_entry(info.name, info.size, info.size, path, budget):
                continue
            if not budget.allow(info.size):
                budget.note("unpack_budget_exhausted", Verdict.UNKNOWN,
                            "archive too large or has too many entries; remaining "
                            "contents not scanned", path)
                break
            fh = tf.extractfile(info)
            if fh is not None:
                members.append((info.name, fh.read(budget.limits.max_entry_bytes)))
    return members


def _from_stream(data: bytes, name: str, media: str, path: str,
                 budget: UnpackBudget) -> list[tuple[str, bytes]]:
    """Single-stream compressors (gzip/bzip2/xz) wrap exactly one payload."""
    opener = {
        "application/gzip": gzip.decompress,
        "application/x-bzip2": bz2.decompress,
        "application/x-xz": lzma.decompress,
    }[media]
    payload = opener(data)
    if len(payload) > budget.limits.max_entry_bytes:
        budget.note("entry_too_large", Verdict.UNKNOWN,
                    f"decompressed to {len(payload)} bytes, above the per-entry limit", path)
        payload = payload[:budget.limits.max_entry_bytes]
    ratio = len(payload) / max(len(data), 1)
    if ratio > budget.limits.max_ratio:
        # Unlike an archive entry we have already paid the decompression cost, so
        # there is nothing to refuse -- only a verdict to record.
        _note_ratio(ratio, len(payload), len(data), path, budget)
    if not budget.allow(len(payload)):
        return []
    # Strip one compression suffix so the inner name reads naturally.
    inner = name
    for suffix in (".gz", ".bz2", ".xz", ".tgz", ".tbz2", ".txz"):
        if inner.lower().endswith(suffix):
            inner = inner[: -len(suffix)]
            if suffix in (".tgz", ".tbz2", ".txz"):
                inner += ".tar"
            break
    else:
        inner = f"{inner}.decompressed"
    return [(inner, payload)]


def _check_entry(name: str, size: int, compressed: int, path: str,
                 budget: UnpackBudget) -> bool:
    """Inspect an entry's declared shape. Returns False to skip reading it.

    Only two things cause a skip: an entry too large for the per-entry limit,
    and a genuine decompression bomb. A merely very compressible entry is noted
    and still scanned.
    """
    entry_path = _join(path, name)
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or "../" in normalized:
        # Harmless to us (we never write to disk) but it tells us the archive was
        # built to escape an extractor, which is worth reporting on its own.
        budget.note("path_traversal_entry", Verdict.MALICIOUS,
                    f"entry name escapes the extraction directory: {name!r}", entry_path)
    if size > budget.limits.max_entry_bytes:
        budget.note("entry_too_large", Verdict.UNKNOWN,
                    f"entry declares {size} bytes, above the per-entry limit; not scanned",
                    entry_path)
        return False
    if compressed > 0:
        ratio = size / compressed
        if ratio > budget.limits.max_ratio:
            return _note_ratio(ratio, size, compressed, entry_path, budget)
    return True


def _note_ratio(ratio: float, size: int, compressed: int, entry_path: str,
                budget: UnpackBudget) -> bool:
    """Record a high compression ratio. Returns False only for a real bomb."""
    if size >= budget.limits.bomb_min_bytes:
        budget.note("compression_bomb", Verdict.MALICIOUS,
                    f"expands {ratio:.0f}x ({compressed} -> {size} bytes), "
                    "consistent with a decompression bomb", entry_path)
        return False
    budget.note("highly_compressible_entry", Verdict.SUSPICIOUS,
                f"expands {ratio:.0f}x ({compressed} -> {size} bytes); "
                "scanned, but the padding is unusual", entry_path)
    return True
