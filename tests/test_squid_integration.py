"""End-to-end test against a real Squid proxy.

The unit tests in test_icap.py drive the ICAP server with a client we wrote,
which proves the parser but not the protocol: it only shows netscan agrees with
our own reading of RFC 3507. This test puts a real Squid in front of a real
origin server and downloads real files through it, which is the only thing that
proves a download actually gets blocked.

Skipped unless NETSCAN_INTEGRATION=1 and squid is installed, because it needs a
proxy binary, three listening ports, and directories Squid's unprivileged user
can write to. Run it with:

    NETSCAN_INTEGRATION=1 pytest tests/test_squid_integration.py -v
"""

from __future__ import annotations

import functools
import http.server
import io
import os
import shutil
import socket
import subprocess
import threading
import time
import zipfile
from pathlib import Path

import pytest

from netscan.core.detectors.structure import StructureDetector
from netscan.core.engine import ScanEngine
from netscan.ingest.icap import make_server
from netscan.report import Reporter

from .conftest import FAKE_PE, PNG

pytestmark = [
    pytest.mark.skipif(os.environ.get("NETSCAN_INTEGRATION") != "1",
                       reason="set NETSCAN_INTEGRATION=1 to run"),
    pytest.mark.skipif(shutil.which("squid") is None, reason="squid is not installed"),
]

SQUID_CONF = """\
http_port {proxy_port}
acl localnet src 127.0.0.1/32
http_access allow localnet
http_access deny all

icap_enable on
icap_preview_enable on
icap_preview_size 4096
icap_persistent_connections on
icap_send_client_ip on
icap_service netscan_resp respmod_precache icap://127.0.0.1:{icap_port}/netscan bypass=off
adaptation_access netscan_resp allow all

access_log stdio:{log_dir}/access.log
cache_log {log_dir}/cache.log
pid_filename {pid_file}
cache deny all
"""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(port: int, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


SAMPLES: dict[str, bytes] = {
    "notes.txt": b"just some ordinary notes\n" * 50,
    "logo.png": PNG,
    "invoice.pdf": FAKE_PE,
    "holiday.png": PNG + FAKE_PE + b"This program cannot be run in DOS mode",
    "documents.zip": _make_zip({"readme.txt": b"see attached\n", "invoice.pdf.exe": FAKE_PE}),
}


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    """Origin server + netscan ICAP + Squid, all on ephemeral ports."""
    root = tmp_path_factory.mktemp("squid-e2e")
    www = root / "www"
    www.mkdir()
    for name, data in SAMPLES.items():
        (www / name).write_bytes(data)

    # Squid drops privileges, so its log directory must be writable by that user.
    # /var/log/squid is created by the package and already is.
    log_dir = Path("/var/log/squid")
    if not os.access(log_dir, os.W_OK):
        pytest.skip(f"{log_dir} is not writable; cannot run squid here")

    origin_port, icap_port, proxy_port = _free_port(), _free_port(), _free_port()

    # `directory` must be passed to __init__ -- setting it as a class attribute
    # is silently overwritten there, and the server then serves the cwd.
    quiet = type("Handler", (http.server.SimpleHTTPRequestHandler,),
                 {"log_message": lambda *a, **k: None})
    handler = functools.partial(quiet, directory=str(www))
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", origin_port), handler)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    engine = ScanEngine([StructureDetector()])
    icap, stats = make_server(engine, Reporter(quiet_clean=True, stream=io.StringIO()),
                              host="127.0.0.1", port=icap_port)
    threading.Thread(target=icap.serve_forever, daemon=True).start()

    conf = root / "squid.conf"
    pid_file = root / "squid.pid"
    conf.write_text(SQUID_CONF.format(proxy_port=proxy_port, icap_port=icap_port,
                                      log_dir=log_dir, pid_file=pid_file))
    squid = subprocess.Popen(["squid", "-N", "-f", str(conf)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    if not (_wait_for(origin_port) and _wait_for(icap_port) and _wait_for(proxy_port)):
        squid.terminate()
        stderr = squid.stderr.read().decode("utf-8", "replace") if squid.stderr else ""
        pytest.skip(f"could not bring up the stack; squid said: {stderr[-400:]}")

    yield {"proxy": proxy_port, "origin": origin_port, "stats": stats}

    squid.terminate()
    try:
        squid.wait(timeout=10)
    except subprocess.TimeoutExpired:
        squid.kill()
    icap.shutdown()
    icap.server_close()
    origin.shutdown()
    origin.server_close()


def fetch(stack, name: str) -> tuple[int, bytes]:
    """GET through Squid with an absolute URI, bypassing every proxy env var.

    urllib and requests both honour `no_proxy`, which in many environments lists
    127.0.0.1 -- they would silently connect straight to the origin and the test
    would pass while testing nothing.
    """
    request = (f"GET http://127.0.0.1:{stack['origin']}/{name} HTTP/1.1\r\n"
               f"Host: 127.0.0.1:{stack['origin']}\r\nConnection: close\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", stack["proxy"]), timeout=30) as sock:
        sock.sendall(request)
        buf = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    head, _, body = buf.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    if b"Transfer-Encoding: chunked" in head:
        body = _dechunk(body)
    return status, body


def _dechunk(raw: bytes) -> bytes:
    out, rest = b"", raw
    while True:
        line, _, rest = rest.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0], 16)
        except ValueError:
            return out
        if size == 0:
            return out
        out += rest[:size]
        rest = rest[size + 2:]


class TestBlocking:
    @pytest.mark.parametrize("name", ["invoice.pdf", "holiday.png", "documents.zip"])
    def test_malicious_downloads_are_blocked(self, stack, name):
        status, body = fetch(stack, name)
        assert status == 403
        assert b"Download blocked" in body

    def test_block_page_names_the_reason(self, stack):
        _, body = fetch(stack, "invoice.pdf")
        assert b"PE/DOS executable" in body
        assert b"SHA-256" in body


class TestPassThrough:
    @pytest.mark.parametrize("name", ["notes.txt", "logo.png"])
    def test_clean_downloads_succeed(self, stack, name):
        status, _ = fetch(stack, name)
        assert status == 200

    @pytest.mark.parametrize("name", ["notes.txt", "logo.png"])
    def test_clean_downloads_arrive_byte_identical(self, stack, name):
        """A scanner that quietly corrupts passing downloads is worse than none."""
        _, body = fetch(stack, name)
        assert body == SAMPLES[name]


class TestScannerState:
    def test_squid_actually_routed_through_netscan(self, stack):
        """Guards against the test silently bypassing the proxy."""
        before = stack["stats"].get("scanned", 0)
        fetch(stack, "notes.txt")
        assert stack["stats"]["scanned"] > before

    def test_repeated_requests_keep_working(self, stack):
        """Squid reuses ICAP connections; the handler must survive that."""
        for _ in range(5):
            assert fetch(stack, "invoice.pdf")[0] == 403
            assert fetch(stack, "logo.png")[0] == 200
