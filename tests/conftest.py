"""Shared fixtures and sample builders."""

from __future__ import annotations

import io
import zipfile

import pytest

from netscan.core.detectors.structure import StructureDetector
from netscan.core.engine import EngineConfig, ScanEngine

FAKE_PE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 56 + b"PE\x00\x00" + b"\x00" * 200
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 20 + b"IEND\xae\x42\x60\x82"
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64 + b"\xff\xd9"


def make_zip(entries: dict[str, bytes], compress: bool = True) -> bytes:
    buf = io.BytesIO()
    mode = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    with zipfile.ZipFile(buf, "w", mode) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def engine() -> ScanEngine:
    """Engine with only the dependency-free detector, so tests never need clamd."""
    return ScanEngine([StructureDetector()], EngineConfig())
