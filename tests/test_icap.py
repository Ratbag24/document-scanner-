"""ICAP tests, including a round trip against a real server on a real socket.

The protocol plumbing (chunked bodies, preview, encapsulated offsets) is where
bugs hide, and they only show up over an actual connection.
"""

import io
import socket
import threading

import pytest

from netscan.core.detectors.structure import StructureDetector
from netscan.core.engine import ScanEngine
from netscan.core.result import Verdict
from netscan.ingest.icap import (
    ICAPError,
    content_type_from_headers,
    filename_from_headers,
    make_server,
    parse_encapsulated,
    verdict_from_name,
)
from netscan.report import Reporter

from .conftest import FAKE_PE, PNG


class TestParsing:
    def test_encapsulated_sorted_by_offset(self):
        assert parse_encapsulated("res-hdr=137, req-hdr=0, res-body=296") == [
            ("req-hdr", 0), ("res-hdr", 137), ("res-body", 296)]

    def test_null_body(self):
        assert parse_encapsulated("null-body=0") == [("null-body", 0)]

    def test_bad_offset_raises_icap_error(self):
        with pytest.raises(ICAPError):
            parse_encapsulated("res-body=abc")

    def test_filename_from_url(self):
        assert filename_from_headers(
            b"GET http://h.test/a/b/setup.exe?v=2 HTTP/1.1", b"") == "setup.exe"

    def test_filename_from_content_disposition_wins(self):
        assert filename_from_headers(
            b"GET http://h.test/download HTTP/1.1",
            b'HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename="in voice.pdf.exe"'
        ) == "in voice.pdf.exe"

    def test_filename_rfc5987_encoded(self):
        assert filename_from_headers(
            b"GET http://h.test/d HTTP/1.1",
            b"Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.exe"
        ) == "résumé.exe"

    def test_filename_path_separators_stripped(self):
        # A server-supplied name must never be usable as a path.
        assert "/" not in filename_from_headers(
            b"GET http://h.test/d HTTP/1.1",
            b'Content-Disposition: attachment; filename="../../etc/passwd"')

    def test_filename_falls_back(self):
        assert filename_from_headers(b"GET http://h.test/ HTTP/1.1", b"") == "(unnamed)"
        assert filename_from_headers(b"GET http://h.test HTTP/1.1", b"") == "(unnamed)"
        assert filename_from_headers(b"garbage", b"") == "(unnamed)"

    def test_filename_percent_decoded(self):
        assert filename_from_headers(
            b"GET /dl/report%20final.pdf HTTP/1.1", b"") == "report final.pdf"

    def test_content_type(self):
        assert content_type_from_headers(
            b"HTTP/1.1 200 OK\r\nContent-Type: image/png; charset=x") == "image/png"

    def test_verdict_from_name(self):
        assert verdict_from_name("Malicious") == Verdict.MALICIOUS
        with pytest.raises(ValueError):
            verdict_from_name("nonsense")


@pytest.fixture
def icap_server(tmp_path):
    """A live ICAP server on an ephemeral port."""
    engine = ScanEngine([StructureDetector()])
    reporter = Reporter(log_file=tmp_path / "scan.jsonl", quiet_clean=True,
                        stream=io.StringIO())
    server, stats = make_server(engine, reporter, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address, stats
    server.shutdown()
    server.server_close()


def icap_respmod(address, body: bytes, filename: str, allow_204: bool = True,
                 disposition: str | None = None) -> bytes:
    """Send one RESPMOD the way Squid does and return the raw ICAP reply."""
    req_hdr = f"GET http://host.test/{filename} HTTP/1.1\r\nHost: host.test\r\n\r\n".encode()
    res_hdr = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
               + (f"Content-Disposition: {disposition}\r\n".encode() if disposition else b"")
               + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
    chunked = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"

    headers = (
        "RESPMOD icap://127.0.0.1/netscan ICAP/1.0\r\n"
        "Host: 127.0.0.1\r\n"
        + ("Allow: 204\r\n" if allow_204 else "")
        + f"Encapsulated: req-hdr=0, res-hdr={len(req_hdr)}, "
          f"res-body={len(req_hdr) + len(res_hdr)}\r\n\r\n"
    ).encode()

    with socket.create_connection(address, timeout=15) as sock:
        sock.sendall(headers + req_hdr + res_hdr + chunked)
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


class TestRoundTrip:
    def test_options(self, icap_server):
        address, _ = icap_server
        with socket.create_connection(address, timeout=15) as sock:
            sock.sendall(b"OPTIONS icap://127.0.0.1/netscan ICAP/1.0\r\n"
                         b"Host: 127.0.0.1\r\n\r\n")
            reply = sock.recv(65536)
        assert reply.startswith(b"ICAP/1.0 200 OK")
        assert b"Methods: RESPMOD" in reply
        assert b"Allow: 204" in reply
        assert b"ISTag:" in reply

    def test_clean_file_passes_with_204(self, icap_server):
        address, stats = icap_server
        reply = icap_respmod(address, PNG, "logo.png")
        assert reply.startswith(b"ICAP/1.0 204 No Content")
        assert stats.get("blocked", 0) == 0
        assert stats["scanned"] == 1

    def test_disguised_executable_is_blocked(self, icap_server):
        address, stats = icap_server
        reply = icap_respmod(address, FAKE_PE, "invoice.pdf")
        assert reply.startswith(b"ICAP/1.0 200 OK")
        assert b"403 Forbidden" in reply
        assert b"Download blocked" in reply
        assert b"X-Netscan-Verdict: malicious" in reply
        assert stats["blocked"] == 1

    def test_block_page_reports_the_reason(self, icap_server):
        address, _ = icap_server
        reply = icap_respmod(address, FAKE_PE, "invoice.pdf")
        assert b"the bytes are a PE/DOS executable" in reply

    def test_block_page_escapes_the_filename(self, icap_server):
        """The filename comes from the server we are defending against.

        Content-Disposition is the realistic vector here: unlike a URL path, it
        can carry a name containing angle brackets that survives intact.
        """
        address, _ = icap_server
        reply = icap_respmod(address, FAKE_PE, "x.pdf",
                             disposition='attachment; filename="<script>alert(1)</script>.pdf"')
        assert b"<script>alert(1)" not in reply
        assert b"&lt;script&gt;" in reply

    def test_no_204_offered_gets_explicit_200(self, icap_server):
        address, _ = icap_server
        reply = icap_respmod(address, PNG, "logo.png", allow_204=False)
        assert reply.startswith(b"ICAP/1.0 200 OK")
        assert b"null-body=0" in reply

    def test_reqmod_passes_through(self, icap_server):
        address, _ = icap_server
        with socket.create_connection(address, timeout=15) as sock:
            sock.sendall(b"REQMOD icap://127.0.0.1/netscan ICAP/1.0\r\n"
                         b"Host: 127.0.0.1\r\nAllow: 204\r\n"
                         b"Encapsulated: null-body=0\r\n\r\n")
            reply = sock.recv(65536)
        assert reply.startswith(b"ICAP/1.0 204")

    def test_malformed_request_gets_400_not_a_crash(self, icap_server):
        address, _ = icap_server
        with socket.create_connection(address, timeout=15) as sock:
            sock.sendall(b"GARBAGE\r\n\r\n")
            reply = sock.recv(65536)
        assert reply.startswith(b"ICAP/1.0 400")

    def test_unsupported_method_gets_405(self, icap_server):
        address, _ = icap_server
        with socket.create_connection(address, timeout=15) as sock:
            sock.sendall(b"DELETE icap://127.0.0.1/x ICAP/1.0\r\nHost: h\r\n\r\n")
            reply = sock.recv(65536)
        assert reply.startswith(b"ICAP/1.0 405")

    def test_server_survives_many_sequential_requests(self, icap_server):
        address, stats = icap_server
        for _ in range(10):
            icap_respmod(address, PNG, "logo.png")
        assert stats["scanned"] == 10

    def test_archive_with_hidden_payload_is_blocked(self, icap_server):
        from .conftest import make_zip
        address, stats = icap_server
        data = make_zip({"readme.txt": b"see attached", "invoice.pdf.exe": FAKE_PE})
        reply = icap_respmod(address, data, "documents.zip")
        assert b"403 Forbidden" in reply
        assert stats["blocked"] == 1
