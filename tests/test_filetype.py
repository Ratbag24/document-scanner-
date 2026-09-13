from netscan.core.filetype import (
    TEXT,
    UNKNOWN,
    extension_matches,
    extension_of,
    identify,
    is_probably_text,
)

from .conftest import FAKE_PE, JPEG, PNG, make_zip


class TestIdentify:
    def test_detects_windows_executable(self):
        assert identify(FAKE_PE, "a.exe").executable

    def test_detects_elf(self):
        ftype = identify(b"\x7fELF\x02\x01\x01" + b"\x00" * 40, "prog")
        assert ftype.media_type == "application/x-elf"
        assert ftype.executable

    def test_detects_png_and_jpeg(self):
        assert identify(PNG, "a.png").media_type == "image/png"
        assert identify(JPEG, "a.jpg").media_type == "image/jpeg"

    def test_detects_pdf(self):
        assert identify(b"%PDF-1.7\n...", "a.pdf").media_type == "application/pdf"

    def test_zip_refined_to_ooxml(self):
        data = make_zip({"word/document.xml": b"<x/>", "[Content_Types].xml": b"<y/>"})
        assert "wordprocessingml" in identify(data, "a.docx").media_type

    def test_plain_zip_stays_zip(self):
        data = make_zip({"notes.txt": b"hello"})
        ftype = identify(data, "a.zip")
        assert ftype.media_type == "application/zip"
        assert ftype.container

    def test_tar_magic_at_offset_257(self):
        data = b"\x00" * 257 + b"ustar" + b"\x00" * 100
        assert identify(data, "a.tar").media_type == "application/x-tar"

    def test_text_and_unknown_fallbacks(self):
        assert identify(b"hello world\n", "a.txt") is TEXT
        assert identify(b"\x81\x00\x00\x82\xff\xfe\x00\x00" * 4, "a.bin") is UNKNOWN

    def test_empty_input_does_not_crash(self):
        assert identify(b"", None) is TEXT


class TestExtensions:
    def test_extension_of(self):
        assert extension_of("a/b/report.PDF") == ".pdf"
        assert extension_of("archive.tar.gz") == ".gz"
        assert extension_of("Makefile") == ""
        assert extension_of(None) == ""
        assert extension_of(".bashrc") == ""

    def test_mismatch_detected(self):
        assert not extension_matches(identify(FAKE_PE), "invoice.pdf")

    def test_match_accepted(self):
        assert extension_matches(identify(PNG), "logo.png")

    def test_no_extension_is_never_a_mismatch(self):
        assert extension_matches(identify(FAKE_PE), "payload")

    def test_zip_aliases_accepted(self):
        data = make_zip({"a.txt": b"x"})
        for name in ("a.zip", "a.jar", "a.apk", "a.whl"):
            assert extension_matches(identify(data, name), name)


class TestIsProbablyText:
    def test_utf8(self):
        assert is_probably_text("héllo wörld\n".encode())

    def test_utf16(self):
        assert is_probably_text("hello".encode("utf-16-le"))

    def test_binary_rejected(self):
        assert not is_probably_text(bytes(range(256)) * 4)

    def test_empty_is_text(self):
        assert is_probably_text(b"")
