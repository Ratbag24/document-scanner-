"""Inline ingestion: an ICAP (RFC 3507) service for a proxy such as Squid.

Unlike the passive Zeek path, this one sits in the request path and can actually
stop a download: the proxy hands us each response body before the client sees
it, and we answer either "204 No Content" (pass it through untouched) or a
replacement HTTP response carrying a block page.

Only RESPMOD is implemented -- that is the direction files arrive from.

Two things to understand before deploying this:

1. Buffering. A verdict needs the whole file, so the proxy holds the response
   until we answer. Large downloads stall until complete. `max_body_bytes` caps
   what we will buffer; anything larger is passed through unscanned rather than
   held forever, and that pass-through is logged.
2. TLS. A proxy only sees HTTPS bodies if it terminates TLS with a CA your
   devices trust. See docs/DEPLOYMENT.md -- this is the decision that determines
   how much of your traffic this path can actually inspect.
"""

from __future__ import annotations

import socketserver
import threading
import time
from urllib.parse import unquote, urlsplit

from ..core.engine import ScanEngine
from ..core.result import ScanResult, Verdict
from ..report import Reporter

ISTAG = f'"netscan-{int(time.time())}"'

_BLOCK_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Download blocked</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;
background:#f6f6f4;color:#1b1b1b;display:grid;place-items:center;min-height:100vh}}
main{{max-width:34rem;padding:2rem;background:#fff;border:1px solid #e2e2de;
border-radius:.6rem}}
h1{{margin:0 0 .5rem;font-size:1.3rem;color:#a1260d}}
code{{background:#f2f2ef;padding:.1rem .3rem;border-radius:.2rem;font-size:.9em}}
ul{{padding-left:1.2rem}} li{{margin:.3rem 0}}
footer{{margin-top:1.2rem;padding-top:.8rem;border-top:1px solid #eee;
color:#666;font-size:.82rem}}
</style></head><body><main>
<h1>Download blocked</h1>
<p>This file was stopped before it reached your device because a scan flagged it.</p>
<p><strong>File:</strong> <code>{name}</code><br>
<strong>SHA-256:</strong> <code>{sha256}</code></p>
<p><strong>Reasons:</strong></p>
<ul>{reasons}</ul>
<footer>Blocked by netscan on your network. If you believe this is wrong, the
SHA-256 above identifies the file in the scan log.</footer>
</main></body></html>
"""

_VERDICT_NAMES = {
    "clean": Verdict.CLEAN,
    "unknown": Verdict.UNKNOWN,
    "suspicious": Verdict.SUSPICIOUS,
    "malicious": Verdict.MALICIOUS,
}


class ICAPError(Exception):
    """Malformed ICAP input. Answered with 400 rather than crashing the worker."""


def _read_line(rfile, limit: int = 8192) -> bytes:
    line = rfile.readline(limit)
    if len(line) >= limit and not line.endswith(b"\n"):
        raise ICAPError("header line too long")
    return line


def _parse_headers(rfile, max_headers: int = 100) -> dict[str, str]:
    """Read CRLF-terminated headers into a lowercase-keyed dict."""
    headers: dict[str, str] = {}
    for _ in range(max_headers):
        line = _read_line(rfile)
        if line in (b"\r\n", b"\n", b""):
            return headers
        if b":" not in line:
            continue
        key, _, value = line.partition(b":")
        headers[key.strip().lower().decode("latin-1")] = value.strip().decode("latin-1")
    raise ICAPError("too many headers")


def parse_encapsulated(value: str) -> list[tuple[str, int]]:
    """Parse `Encapsulated: req-hdr=0, res-hdr=137, res-body=296` in offset order."""
    parts: list[tuple[str, int]] = []
    for chunk in value.split(","):
        name, _, offset = chunk.strip().partition("=")
        name = name.strip().lower()
        if not name:
            continue
        try:
            parts.append((name, int(offset.strip() or 0)))
        except ValueError:
            raise ICAPError(f"bad Encapsulated offset in {chunk!r}") from None
    parts.sort(key=lambda p: p[1])
    return parts


def read_chunked(rfile, max_bytes: int) -> tuple[bytes, bool, bool]:
    """Read an HTTP chunked body.

    Returns (data, complete, saw_ieof). `complete` is False when `max_bytes` was
    hit, in which case the remaining bytes are left unread. `saw_ieof` reports
    the ICAP preview terminator `0; ieof`, meaning the preview was the whole body.
    """
    out = bytearray()
    while True:
        line = _read_line(rfile).strip()
        if not line:
            return bytes(out), True, False
        size_token = line.split(b";", 1)[0].strip()
        saw_ieof = b"ieof" in line
        try:
            size = int(size_token, 16)
        except ValueError:
            raise ICAPError(f"bad chunk size {size_token!r}") from None
        if size == 0:
            rfile.readline()  # trailing CRLF after the terminating chunk
            return bytes(out), True, saw_ieof
        if len(out) + size > max_bytes:
            return bytes(out), False, False
        chunk = rfile.read(size)
        if len(chunk) < size:
            return bytes(out) + chunk, False, False
        out += chunk
        rfile.read(2)  # CRLF after each chunk


def filename_from_headers(req_hdr: bytes, res_hdr: bytes) -> str:
    """Best guess at the name the client will save the file under.

    Content-Disposition wins because that is what the browser honours; otherwise
    the last segment of the request URL's path, which is what it falls back to.
    Returns "(unnamed)" when neither yields a name -- a URL with no path, say.
    """
    disposition = _content_disposition_filename(res_hdr)
    if disposition:
        # Never let a server-chosen name contain path separators.
        return disposition.replace("/", "_").replace("\\", "_")

    request_line = req_hdr.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    fields = request_line.split()
    if len(fields) < 2:
        return "(unnamed)"
    path = urlsplit(fields[1]).path
    candidate = unquote(path).rstrip("/").rsplit("/", 1)[-1].strip()
    return candidate or "(unnamed)"


def _content_disposition_filename(res_hdr: bytes) -> str:
    """Extract filename/filename* from a Content-Disposition header, if present."""
    for line in res_hdr.split(b"\r\n"):
        if not line.lower().startswith(b"content-disposition:"):
            continue
        value = line.decode("latin-1", "replace")
        lowered = value.lower()
        # filename*= (RFC 5987, percent-encoded with a charset prefix) is
        # preferred over plain filename= when both are present.
        for token in ("filename*=", "filename="):
            if token not in lowered:
                continue
            raw = value[lowered.index(token) + len(token):].split(";")[0].strip().strip("\"'")
            if token == "filename*=" and "''" in raw:
                raw = raw.split("''", 1)[1]
            if raw:
                return unquote(raw)
    return ""


def content_type_from_headers(res_hdr: bytes) -> str:
    for line in res_hdr.split(b"\r\n"):
        if line.lower().startswith(b"content-type:"):
            return line.partition(b":")[2].strip().split(b";")[0].decode("latin-1", "replace")
    return ""


class ICAPHandler(socketserver.StreamRequestHandler):
    """One ICAP connection. The server keeps it alive across requests."""

    timeout = 120

    # Injected by make_server().
    engine: ScanEngine
    reporter: Reporter
    block_at: Verdict = Verdict.MALICIOUS
    max_body_bytes: int = 64 * 1024 * 1024
    service_path: str = "/netscan"
    stats: dict
    stats_lock: threading.Lock

    def handle(self) -> None:
        while True:
            try:
                if not self._handle_one():
                    return
            except ICAPError as exc:
                self._send_simple(400, f"Bad Request: {exc}")
                return
            except TimeoutError:
                return
            except OSError:
                return

    def _handle_one(self) -> bool:
        line = _read_line(self.rfile)
        if not line:
            return False
        fields = line.decode("latin-1", "replace").split()
        if len(fields) < 3:
            raise ICAPError("malformed request line")
        method = fields[0].upper()
        headers = _parse_headers(self.rfile)

        if method == "OPTIONS":
            self._send_options()
            return True
        if method == "REQMOD":
            # Uploads are not inspected; nothing to do but let them through.
            self._send_no_content(headers)
            return True
        if method != "RESPMOD":
            self._send_simple(405, "Method Not Allowed")
            return False
        self._respmod(headers)
        return True

    # -- RESPMOD ------------------------------------------------------------

    def _respmod(self, headers: dict[str, str]) -> None:
        sections = parse_encapsulated(headers.get("encapsulated", "res-body=0"))
        req_hdr, res_hdr, body = self._read_sections(sections, headers)

        if body is None:  # no body to scan (e.g. a 304)
            self._send_no_content(headers)
            return

        name = filename_from_headers(req_hdr, res_hdr)
        data, complete = body
        if not complete:
            self._bump("passed_through_oversize")
            self.reporter.report(
                self.engine.scan(b"", name), source="icap (oversize, not scanned)")
            self._send_no_content(headers)
            return

        result = self.engine.scan(data, name)
        result.meta["declared_content_type"] = content_type_from_headers(res_hdr)
        result.meta["client"] = self.client_address[0]

        self._bump("scanned")
        self._bump(result.verdict.label)
        self.reporter.report(result, source=f"icap {self.client_address[0]}")

        if result.verdict >= self.block_at:
            self._bump("blocked")
            self._send_block_page(result)
        else:
            self._send_no_content(headers)

    def _read_sections(self, sections: list[tuple[str, int]], headers: dict[str, str]
                       ) -> tuple[bytes, bytes, tuple[bytes, bool] | None]:
        """Read the encapsulated req-hdr/res-hdr blocks and the response body."""
        blocks: dict[str, bytes] = {}
        body_present = False
        for idx, (name, offset) in enumerate(sections):
            if name in ("null-body", "req-body", "res-body"):
                body_present = name == "res-body"
                continue
            # A header block runs until the next section's offset.
            end = sections[idx + 1][1] if idx + 1 < len(sections) else None
            length = (end - offset) if end is not None else 0
            blocks[name] = self.rfile.read(length) if length > 0 else b""

        if not body_present:
            return blocks.get("req-hdr", b""), blocks.get("res-hdr", b""), None

        data, complete, saw_ieof = read_chunked(self.rfile, self.max_body_bytes)
        if "preview" in headers and not saw_ieof and complete:
            # The preview was only the head of the body; ask for the rest.
            self.wfile.write(b"ICAP/1.0 100 Continue\r\n\r\n")
            self.wfile.flush()
            rest, complete, _ = read_chunked(self.rfile, self.max_body_bytes - len(data))
            data += rest
        return blocks.get("req-hdr", b""), blocks.get("res-hdr", b""), (data, complete)

    # -- responses ----------------------------------------------------------

    def _send_options(self) -> None:
        body = (
            f"ICAP/1.0 200 OK\r\n"
            f"Methods: RESPMOD\r\n"
            f"Service: netscan\r\n"
            f"ISTag: {ISTAG}\r\n"
            f"Allow: 204\r\n"
            f"Preview: 4096\r\n"
            f"Max-Connections: 100\r\n"
            f"Options-TTL: 600\r\n"
            f"Encapsulated: null-body=0\r\n\r\n"
        )
        self.wfile.write(body.encode("latin-1"))
        self.wfile.flush()

    def _send_no_content(self, headers: dict[str, str]) -> None:
        """204 when the proxy allows it, otherwise an explicit empty 200."""
        if "204" in headers.get("allow", ""):
            self.wfile.write(f"ICAP/1.0 204 No Content\r\nISTag: {ISTAG}\r\n\r\n".encode("latin-1"))
        else:
            self.wfile.write(
                f"ICAP/1.0 200 OK\r\nISTag: {ISTAG}\r\n"
                f"Encapsulated: null-body=0\r\n\r\n".encode("latin-1"))
        self.wfile.flush()

    def _send_block_page(self, result: ScanResult) -> None:
        reasons = "".join(
            f"<li>{_escape(f.detail or f.rule)}</li>"
            for f in sorted(result.findings, key=lambda f: -f.verdict)
            if f.verdict >= Verdict.SUSPICIOUS
        ) or "<li>flagged by the scanner</li>"
        page = _BLOCK_PAGE.format(
            name=_escape(result.name), sha256=_escape(result.sha256), reasons=reasons
        ).encode("utf-8")

        http_headers = (
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(page)}\r\n"
            "Cache-Control: no-store\r\n"
            "X-Netscan-Verdict: " + result.verdict.label + "\r\n\r\n"
        ).encode("latin-1")
        chunked = f"{len(page):x}\r\n".encode("latin-1") + page + b"\r\n0\r\n\r\n"

        self.wfile.write(
            f"ICAP/1.0 200 OK\r\nISTag: {ISTAG}\r\n"
            f"Encapsulated: res-hdr=0, res-body={len(http_headers)}\r\n\r\n".encode("latin-1")
        )
        self.wfile.write(http_headers)
        self.wfile.write(chunked)
        self.wfile.flush()

    def _send_simple(self, code: int, reason: str) -> None:
        try:
            self.wfile.write(
                f"ICAP/1.0 {code} {reason}\r\nISTag: {ISTAG}\r\n"
                f"Encapsulated: null-body=0\r\n\r\n".encode("latin-1"))
            self.wfile.flush()
        except OSError:
            pass

    def _bump(self, key: str) -> None:
        with self.stats_lock:
            self.stats[key] = self.stats.get(key, 0) + 1

    def log_message(self, *args) -> None:  # silence base-class logging
        pass


class ICAPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_server(engine: ScanEngine, reporter: Reporter, host: str = "0.0.0.0",
                port: int = 1344, block_at: Verdict = Verdict.MALICIOUS,
                max_body_bytes: int = 64 * 1024 * 1024) -> tuple[ICAPServer, dict]:
    """Build a threaded ICAP server. Returns (server, shared stats dict)."""
    stats: dict[str, int] = {}
    lock = threading.Lock()

    handler = type("BoundICAPHandler", (ICAPHandler,), {
        "engine": engine,
        "reporter": reporter,
        "block_at": block_at,
        "max_body_bytes": max_body_bytes,
        "stats": stats,
        "stats_lock": lock,
    })
    return ICAPServer((host, port), handler), stats


def verdict_from_name(name: str) -> Verdict:
    try:
        return _VERDICT_NAMES[name.strip().lower()]
    except KeyError:
        raise ValueError(
            f"unknown verdict {name!r}; expected one of {', '.join(_VERDICT_NAMES)}") from None


def _escape(text: str) -> str:
    """Escape for HTML text context. The block page echoes attacker-chosen
    filenames, so this is not optional."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))
