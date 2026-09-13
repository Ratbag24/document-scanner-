"""Structural detector: finds files that are not what they claim to be.

This is the only detector that needs no external dependency, and it catches the
delivery tricks that signature databases miss because the payload is novel:
disguised extensions, executables appended to images, macro-bearing documents,
PDFs with active content, and obfuscated scripts.

Nothing here is proof of malice on its own -- findings are SUSPICIOUS unless the
combination is one that has no legitimate explanation.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..filetype import (
    RISKY_EXTENSIONS,
    describe,
    extension_matches,
    extension_of,
    identify,
)
from ..result import Finding, Verdict
from .base import Detector, ScanTarget

# Unicode characters used to visually reverse a filename so "gpj.exe" renders as
# "exe.jpg". No legitimate download filename needs them.
_BIDI_OVERRIDES = "‪‫‬‭‮⁦⁧⁨⁩"

# The DOS stub string present in essentially every Windows PE binary.
_DOS_STUB = b"This program cannot be run in DOS mode"

# Extensions where an executable payload hidden inside is unambiguously wrong.
_PASSIVE_MEDIA = frozenset({
    "image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp",
    "image/tiff", "audio/mpeg", "audio/ogg", "audio/flac", "video/mp4",
})

_SCRIPT_OBFUSCATION = [
    (re.compile(rb"(?i)powershell[^\n]{0,80}\s-e(nc|ncoded|ncodedcommand)?\s"),
     "powershell_encoded_command"),
    (re.compile(rb"(?i)\bfrombase64string\b"), "base64_decode_to_execute"),
    (re.compile(rb"(?i)\biex\b|\binvoke-expression\b"), "powershell_invoke_expression"),
    (re.compile(rb"(?i)\bdownloadstring\b|\bdownloadfile\b|\bwebclient\b"), "script_downloader"),
    (re.compile(rb"(?i)\bwscript\.shell\b|\bshell\.application\b"), "wsh_shell_object"),
    (re.compile(rb"(?i)\beval\s*\(\s*(atob|unescape|decodeuricomponent)"),
     "js_eval_of_encoded_data"),
    (re.compile(rb"(?i)\bchr\s*\(\s*\d+\s*\)\s*(&|\+)\s*chr\s*\("),
     "char_code_string_building"),
    (re.compile(rb"(?i)certutil[^\n]{0,40}-(urlcache|decode)"), "certutil_abuse"),
    (re.compile(rb"(?i)\bmshta\b[^\n]{0,40}(http|javascript:)"), "mshta_remote_payload"),
    (re.compile(rb"(?i)\brundll32\b[^\n]{0,40}javascript:"), "rundll32_javascript"),
    (re.compile(rb"(?i)\bbitsadmin\b[^\n]{0,40}/transfer"), "bitsadmin_transfer"),
    (re.compile(rb"(?i)-w(indowstyle)?\s+hidden|-nop\b|-noprofile\b"), "hidden_window_execution"),
]

_PDF_ACTIVE_CONTENT = [
    (rb"/JavaScript", "pdf_javascript", Verdict.SUSPICIOUS),
    (rb"/JS\b", "pdf_javascript", Verdict.SUSPICIOUS),
    (rb"/OpenAction", "pdf_auto_open_action", Verdict.SUSPICIOUS),
    (rb"/AA\b", "pdf_additional_action", Verdict.SUSPICIOUS),
    (rb"/Launch", "pdf_launch_action", Verdict.MALICIOUS),
    (rb"/EmbeddedFile", "pdf_embedded_file", Verdict.SUSPICIOUS),
    (rb"/RichMedia", "pdf_rich_media", Verdict.SUSPICIOUS),
    (rb"/SubmitForm", "pdf_submit_form", Verdict.SUSPICIOUS),
]


def shannon_entropy(data: bytes) -> float:
    """Bits of entropy per byte (0.0-8.0). Compressed or encrypted data is >7.5."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class StructureDetector(Detector):
    """Content-vs-claim analysis, active-content and obfuscation checks."""

    name = "structure"

    def __init__(self, entropy_threshold: float = 7.5, min_entropy_size: int = 4096):
        self.entropy_threshold = entropy_threshold
        self.min_entropy_size = min_entropy_size

    def inspect(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for check in (
            self._check_name,
            self._check_type_mismatch,
            self._check_trailing_data,
            self._check_embedded_executable,
            self._check_office_macros,
            self._check_pdf,
            self._check_scripts,
            self._check_entropy,
        ):
            try:
                findings.extend(check(target))
            except Exception as exc:  # a detector must never break a scan
                findings.append(Finding(self.name, "check_error", Verdict.UNKNOWN,
                                        f"{check.__name__}: {exc}", target.path))
        return findings

    # -- filename tricks ----------------------------------------------------

    def _check_name(self, t: ScanTarget) -> list[Finding]:
        out: list[Finding] = []
        name = t.name or ""
        if any(c in name for c in _BIDI_OVERRIDES):
            out.append(Finding(self.name, "filename_bidi_override", Verdict.MALICIOUS,
                               "filename contains a right-to-left override, which disguises "
                               "the real extension", t.path))
        ext = extension_of(name)
        # Double extension: a document-looking extension followed by an executable one.
        parts = name.lower().rsplit(".", 2)
        if len(parts) == 3 and ext in RISKY_EXTENSIONS:
            inner = "." + parts[1]
            if inner in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
                         ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".zip", ".rtf", ".csv"}:
                out.append(Finding(self.name, "double_extension", Verdict.MALICIOUS,
                                   f"looks like a {inner} file but is really {ext}", t.path))
        if ext in RISKY_EXTENSIONS:
            out.append(Finding(self.name, "risky_extension", Verdict.SUSPICIOUS,
                               f"{ext} is executed by the OS on open", t.path))
        if "\x00" in name or "\n" in name or "\r" in name:
            out.append(Finding(self.name, "filename_control_characters", Verdict.SUSPICIOUS,
                               "filename contains control characters", t.path))
        return out

    def _check_type_mismatch(self, t: ScanTarget) -> list[Finding]:
        if extension_matches(t.ftype, t.name):
            return []
        ext = extension_of(t.name)
        verdict = Verdict.MALICIOUS if t.ftype.executable else Verdict.SUSPICIOUS
        return [Finding(self.name, "extension_content_mismatch", verdict,
                        f"named {ext} but the bytes are {describe(t.ftype)}", t.path)]

    # -- appended / embedded payloads ---------------------------------------

    def _check_trailing_data(self, t: ScanTarget) -> list[Finding]:
        """Data past a format's logical end -- the classic stego/polyglot carrier."""
        data, media = t.data, t.ftype.media_type
        trailer_at: int | None = None

        if media == "image/png":
            idx = data.rfind(b"IEND")
            if idx != -1:
                trailer_at = idx + 8  # IEND + 4-byte CRC
        elif media == "image/jpeg":
            idx = data.rfind(b"\xff\xd9")
            if idx != -1:
                trailer_at = idx + 2
        elif media == "image/gif":
            idx = data.rfind(b"\x3b")
            if idx == len(data) - 1:
                trailer_at = len(data)
        elif media == "application/pdf":
            idx = data.rfind(b"%%EOF")
            if idx != -1:
                trailer_at = idx + 5

        if trailer_at is None:
            return []
        extra = data[trailer_at:].strip(b"\r\n\x00 ")
        if len(extra) < 16:  # padding and line endings are normal
            return []

        out = [Finding(self.name, "data_after_end_of_file", Verdict.SUSPICIOUS,
                       f"{len(extra)} bytes appended after the {t.ftype.label} ends", t.path)]
        hidden = identify(extra)
        if hidden.executable or hidden.container:
            out.append(Finding(self.name, "polyglot_file", Verdict.MALICIOUS,
                               f"{describe(hidden)} is concealed after "
                               f"the {t.ftype.label}", t.path))
        return out

    def _check_embedded_executable(self, t: ScanTarget) -> list[Finding]:
        """A Windows PE inside something that should never contain one."""
        if t.ftype.media_type not in _PASSIVE_MEDIA:
            return []
        if _DOS_STUB not in t.data and b"PE\x00\x00" not in t.data:
            return []
        return [Finding(self.name, "executable_inside_media_file", Verdict.MALICIOUS,
                        f"Windows executable code found inside {describe(t.ftype)}", t.path)]

    # -- documents ----------------------------------------------------------

    def _check_office_macros(self, t: ScanTarget) -> list[Finding]:
        media = t.ftype.media_type
        out: list[Finding] = []
        if media.startswith("application/vnd.openxmlformats"):
            # Macro projects live at a fixed path; the name survives in the
            # ZIP central directory even without decompressing.
            if b"vbaProject.bin" in t.data:
                out.append(Finding(self.name, "office_macro_project", Verdict.SUSPICIOUS,
                                   "document carries a VBA macro project", t.path))
            if b"vbaProject.bin" in t.data and extension_of(t.name) in {".docx", ".xlsx", ".pptx"}:
                out.append(Finding(self.name, "macro_in_macro_free_extension", Verdict.MALICIOUS,
                                   "macros present in a format that cannot legitimately hold them",
                                   t.path))
            if b"Microsoft.XMLHTTP" in t.data or b"externalLink" in t.data:
                out.append(Finding(self.name, "office_external_reference",
                                   Verdict.SUSPICIOUS,
                                   "document fetches remote content when opened", t.path))
        elif media == "application/x-ole-storage":
            lowered = t.data.lower()
            if b"vba" in lowered or b"macros" in lowered:
                out.append(Finding(self.name, "legacy_office_macro", Verdict.SUSPICIOUS,
                                   "legacy Office document containing macro streams", t.path))
            if (b"\x00e\x00q\x00u\x00a\x00t\x00i\x00o\x00n" in lowered
                    or b"equation.3" in lowered):
                out.append(Finding(self.name, "office_equation_editor_object", Verdict.SUSPICIOUS,
                                   "embeds Equation Editor, a common exploit vector", t.path))
        return out

    def _check_pdf(self, t: ScanTarget) -> list[Finding]:
        if t.ftype.media_type != "application/pdf":
            return []
        out: list[Finding] = []
        seen: set[str] = set()
        for pattern, rule, verdict in _PDF_ACTIVE_CONTENT:
            if re.search(pattern, t.data) and rule not in seen:
                seen.add(rule)
                out.append(Finding(self.name, rule, verdict,
                                   "PDF contains active content that runs on open", t.path))
        if re.search(rb"/ObjStm", t.data) and re.search(rb"/JavaScript|/JS\b", t.data) is None:
            # Object streams legitimately compress content but also hide it from
            # naive scanners; only worth noting alongside other oddities.
            out.append(Finding(self.name, "pdf_compressed_object_streams", Verdict.UNKNOWN,
                               "PDF body is in object streams; contents not fully inspected",
                               t.path))
        return out

    def _check_scripts(self, t: ScanTarget) -> list[Finding]:
        media = t.ftype.media_type
        if not (media.startswith("text/") or media == "application/rtf"):
            return []
        out: list[Finding] = []
        for pattern, rule in _SCRIPT_OBFUSCATION:
            if pattern.search(t.data):
                out.append(Finding(self.name, rule, Verdict.SUSPICIOUS,
                                   "script uses a technique associated with droppers", t.path))
        # A very long unbroken base64 run in a script is an embedded payload.
        for match in re.finditer(rb"[A-Za-z0-9+/]{512,}={0,2}", t.data):
            out.append(Finding(self.name, "large_base64_blob", Verdict.SUSPICIOUS,
                               f"{len(match.group())} bytes of base64 embedded in a script",
                               t.path))
            break
        if media == "application/rtf" and re.search(rb"(?i)\\objupdate|\\objdata", t.data):
            out.append(Finding(self.name, "rtf_embedded_object", Verdict.SUSPICIOUS,
                               "RTF auto-updating embedded object", t.path))
        return out

    def _check_entropy(self, t: ScanTarget) -> list[Finding]:
        """High entropy where the format does not explain it means packed data."""
        if len(t.data) < self.min_entropy_size:
            return []
        if t.ftype.container or t.ftype.media_type in _PASSIVE_MEDIA:
            return []  # compression legitimately produces high entropy
        entropy = shannon_entropy(t.data)
        if entropy < self.entropy_threshold:
            return []
        return [Finding(self.name, "high_entropy_content", Verdict.SUSPICIOUS,
                        f"entropy {entropy:.2f}/8.00 suggests packed or encrypted content",
                        t.path)]
