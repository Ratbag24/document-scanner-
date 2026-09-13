"""ClamAV detector, talking to clamd over its INSTREAM protocol.

We stream bytes to an already-running clamd rather than shelling out to
clamscan: clamscan reloads the ~250MB signature database on every invocation,
which takes seconds, while clamd keeps it resident and answers in milliseconds.
That difference is what makes scanning live traffic feasible at all.
"""

from __future__ import annotations

import socket
import struct

from ..result import Finding, Verdict
from .base import Detector, ScanTarget

# clamd's default StreamMaxLength is 25MB; chunks must be under its read buffer.
_CHUNK = 8192


class ClamAVDetector(Detector):
    """Signature-based scanning via a resident clamd instance."""

    name = "clamav"

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3310,
        unix_socket: str | None = None,
        timeout: float = 30.0,
        max_size: int = 25 * 1024 * 1024,
    ):
        self.host = host
        self.port = port
        self.unix_socket = unix_socket
        self.timeout = timeout
        self.max_size = max_size
        self._version: str | None = None
        self._probe_error: str | None = None

    # -- connection ---------------------------------------------------------

    def _connect(self) -> socket.socket:
        if self.unix_socket:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(self.unix_socket)
        else:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            sock.settimeout(self.timeout)
        return sock

    @property
    def available(self) -> bool:
        return self.version() is not None

    def unavailable_reason(self) -> str:
        return self._probe_error or ""

    def version(self) -> str | None:
        """Cached clamd version string, or None when clamd is unreachable."""
        if self._version is not None:
            return self._version
        try:
            with self._connect() as sock:
                sock.sendall(b"zVERSION\x00")
                self._version = self._read_all(sock).strip("\x00").strip()
                self._probe_error = None
        except OSError as exc:
            self._probe_error = f"cannot reach clamd ({self._endpoint()}): {exc}"
            return None
        return self._version

    def _endpoint(self) -> str:
        return self.unix_socket or f"{self.host}:{self.port}"

    @staticmethod
    def _read_all(sock: socket.socket) -> str:
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if data.endswith(b"\x00"):
                break
        return b"".join(chunks).decode("utf-8", "replace")

    # -- scanning -----------------------------------------------------------

    def inspect(self, target: ScanTarget) -> list[Finding]:
        if len(target.data) > self.max_size:
            return [Finding(self.name, "too_large_to_scan", Verdict.UNKNOWN,
                            f"{len(target.data)} bytes exceeds the {self.max_size} byte "
                            "clamd stream limit", target.path)]
        if not target.data:
            return []
        try:
            response = self._instream(target.data)
        except OSError as exc:
            self._version = None  # force a re-probe next time
            return [Finding(self.name, "scan_unavailable", Verdict.UNKNOWN,
                            f"clamd error: {exc}", target.path)]
        return self._parse(response, target)

    def _instream(self, data: bytes) -> str:
        with self._connect() as sock:
            sock.sendall(b"zINSTREAM\x00")
            for offset in range(0, len(data), _CHUNK):
                chunk = data[offset:offset + _CHUNK]
                sock.sendall(struct.pack("!L", len(chunk)) + chunk)
            sock.sendall(struct.pack("!L", 0))  # zero-length chunk ends the stream
            return self._read_all(sock)

    def _parse(self, response: str, target: ScanTarget) -> list[Finding]:
        line = response.strip().strip("\x00").strip()
        if not line or line.endswith("OK"):
            return []
        if "FOUND" in line:
            # "stream: Eicar-Signature FOUND"
            signature = line.rsplit(":", 1)[-1].replace("FOUND", "").strip()
            return [Finding(self.name, signature or "unnamed_signature", Verdict.MALICIOUS,
                            "matched a ClamAV signature", target.path)]
        if "ERROR" in line:
            detail = line.rsplit(":", 1)[-1].strip()
            # Encrypted archives are reported as errors but mean "cannot inspect".
            verdict = Verdict.UNKNOWN
            return [Finding(self.name, "scan_error", verdict, detail, target.path)]
        return []
