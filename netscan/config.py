"""Configuration loading and engine construction.

Settings resolve in this order, lowest priority first: built-in defaults, a
TOML config file, then NETSCAN_* environment variables. Environment variables
win so a container can be reconfigured without rebuilding its config file.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .core.detectors.base import Detector
from .core.detectors.clamav import ClamAVDetector
from .core.detectors.hashes import HashDetector
from .core.detectors.structure import StructureDetector
from .core.detectors.yara_rules import YaraDetector
from .core.engine import EngineConfig, ScanEngine
from .core.unpack import UnpackLimits

# The rules/ directory that ships beside the package. Present for a source or
# editable install; absent from a wheel, where NETSCAN_YARA_RULES (or the config
# file) points at wherever the rules were deployed.
_BUNDLED_RULES = Path(__file__).resolve().parent.parent / "rules"


def _default_rules_dir() -> Path | None:
    return _BUNDLED_RULES if _BUNDLED_RULES.is_dir() else None


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass
class Config:
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    clamd_socket: str | None = None
    clamd_enabled: bool = True

    yara_rules_dir: Path | None = field(default_factory=_default_rules_dir)

    blocklists: list[Path] = field(default_factory=list)
    allowlists: list[Path] = field(default_factory=list)

    unpack_containers: bool = True
    max_depth: int = 4
    max_scan_bytes: int = 100 * 1024 * 1024
    unknown_is_suspicious: bool = False

    # Ingestion
    zeek_extract_dir: Path = Path("/var/log/zeek/extract_files")
    quarantine_dir: Path | None = None
    log_file: Path | None = None
    icap_host: str = "0.0.0.0"
    icap_port: int = 1344
    # Verdict at or above which the ICAP path blocks a response.
    block_at: str = "malicious"

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        cfg = cls()
        if path and path.is_file():
            cfg._apply_toml(tomllib.loads(path.read_text()))
        cfg._apply_env()
        return cfg

    def _apply_toml(self, doc: dict) -> None:
        clamav = doc.get("clamav", {})
        self.clamd_host = clamav.get("host", self.clamd_host)
        self.clamd_port = int(clamav.get("port", self.clamd_port))
        self.clamd_socket = clamav.get("socket", self.clamd_socket)
        self.clamd_enabled = bool(clamav.get("enabled", self.clamd_enabled))

        yara_doc = doc.get("yara", {})
        if yara_doc.get("rules_dir"):
            self.yara_rules_dir = Path(yara_doc["rules_dir"])

        hashes = doc.get("hashes", {})
        self.blocklists = [Path(p) for p in hashes.get("blocklists", self.blocklists)]
        self.allowlists = [Path(p) for p in hashes.get("allowlists", self.allowlists)]

        scan = doc.get("scan", {})
        self.unpack_containers = bool(scan.get("unpack_containers", self.unpack_containers))
        self.max_depth = int(scan.get("max_depth", self.max_depth))
        self.max_scan_bytes = int(scan.get("max_scan_bytes", self.max_scan_bytes))
        self.unknown_is_suspicious = bool(
            scan.get("unknown_is_suspicious", self.unknown_is_suspicious))

        ingest = doc.get("ingest", {})
        if ingest.get("zeek_extract_dir"):
            self.zeek_extract_dir = Path(ingest["zeek_extract_dir"])
        if ingest.get("quarantine_dir"):
            self.quarantine_dir = Path(ingest["quarantine_dir"])
        if ingest.get("log_file"):
            self.log_file = Path(ingest["log_file"])

        icap = doc.get("icap", {})
        self.icap_host = icap.get("host", self.icap_host)
        self.icap_port = int(icap.get("port", self.icap_port))
        self.block_at = icap.get("block_at", self.block_at)

    def _apply_env(self) -> None:
        self.clamd_host = os.environ.get("NETSCAN_CLAMD_HOST", self.clamd_host)
        self.clamd_port = _env_int("NETSCAN_CLAMD_PORT", self.clamd_port)
        self.clamd_socket = os.environ.get("NETSCAN_CLAMD_SOCKET", self.clamd_socket)
        self.clamd_enabled = _env_bool("NETSCAN_CLAMD_ENABLED", self.clamd_enabled)
        if os.environ.get("NETSCAN_YARA_RULES"):
            self.yara_rules_dir = Path(os.environ["NETSCAN_YARA_RULES"])
        if os.environ.get("NETSCAN_BLOCKLISTS"):
            self.blocklists = [Path(p) for p in os.environ["NETSCAN_BLOCKLISTS"].split(":") if p]
        if os.environ.get("NETSCAN_ALLOWLISTS"):
            self.allowlists = [Path(p) for p in os.environ["NETSCAN_ALLOWLISTS"].split(":") if p]
        if os.environ.get("NETSCAN_ZEEK_EXTRACT_DIR"):
            self.zeek_extract_dir = Path(os.environ["NETSCAN_ZEEK_EXTRACT_DIR"])
        if os.environ.get("NETSCAN_QUARANTINE_DIR"):
            self.quarantine_dir = Path(os.environ["NETSCAN_QUARANTINE_DIR"])
        if os.environ.get("NETSCAN_LOG_FILE"):
            self.log_file = Path(os.environ["NETSCAN_LOG_FILE"])
        self.icap_host = os.environ.get("NETSCAN_ICAP_HOST", self.icap_host)
        self.icap_port = _env_int("NETSCAN_ICAP_PORT", self.icap_port)
        self.block_at = os.environ.get("NETSCAN_BLOCK_AT", self.block_at)
        self.max_depth = _env_int("NETSCAN_MAX_DEPTH", self.max_depth)
        self.max_scan_bytes = _env_int("NETSCAN_MAX_SCAN_BYTES", self.max_scan_bytes)
        self.unknown_is_suspicious = _env_bool(
            "NETSCAN_UNKNOWN_IS_SUSPICIOUS", self.unknown_is_suspicious)

    # -- construction -------------------------------------------------------

    def detectors(self) -> list[Detector]:
        """Build the detector chain, cheapest and most reliable first."""
        chain: list[Detector] = [StructureDetector()]
        if self.blocklists or self.allowlists:
            chain.append(HashDetector(blocklists=self.blocklists, allowlists=self.allowlists))
        if self.clamd_enabled:
            chain.append(ClamAVDetector(host=self.clamd_host, port=self.clamd_port,
                                        unix_socket=self.clamd_socket))
        if self.yara_rules_dir:
            chain.append(YaraDetector(rules_dir=self.yara_rules_dir))
        return chain

    def engine(self) -> ScanEngine:
        return ScanEngine(
            self.detectors(),
            EngineConfig(
                unpack_containers=self.unpack_containers,
                unpack_limits=UnpackLimits(max_depth=self.max_depth),
                max_scan_bytes=self.max_scan_bytes,
                unknown_is_suspicious=self.unknown_is_suspicious,
            ),
        )
