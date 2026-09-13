import bz2
import gzip
import io
import lzma
import tarfile

from netscan.core.filetype import identify
from netscan.core.result import Verdict
from netscan.core.unpack import UnpackLimits, unpack

from .conftest import FAKE_PE, make_zip


def run(data: bytes, name: str, limits: UnpackLimits | None = None):
    return unpack(data, name, identify(data, name), limits)


def rule_set(findings) -> set[str]:
    return {f.rule for f in findings}


class TestZip:
    def test_extracts_entries(self):
        data = make_zip({"a.txt": b"one", "b/c.txt": b"two"})
        members, findings = run(data, "a.zip")
        assert {m.name for m in members} == {"a.txt", "b/c.txt"}
        assert findings == []

    def test_nested_archives_are_recursed(self):
        inner = make_zip({"payload.exe": FAKE_PE})
        data = make_zip({"stage.zip": inner, "readme.txt": b"hi"})
        members, _ = run(data, "outer.zip")
        paths = {m.path for m in members}
        assert "outer.zip -> stage.zip -> payload.exe" in paths
        assert max(m.depth for m in members) == 2

    def test_depth_limit_stops_recursion(self):
        data = make_zip({"l1.zip": make_zip({"l2.zip": make_zip({"deep.txt": b"x"})})})
        members, findings = run(data, "a.zip", UnpackLimits(max_depth=2))
        assert "max_depth_reached" in rule_set(findings)
        assert all(m.depth <= 2 for m in members)

    def test_real_bomb_is_refused(self):
        """Absurd ratio AND large absolute output: refuse to expand it."""
        data = make_zip({"pad.bin": b"\x00" * (48 * 1024 * 1024)})
        members, findings = run(data, "bomb.zip")
        assert "compression_bomb" in rule_set(findings)
        assert members == []
        bomb = next(f for f in findings if f.rule == "compression_bomb")
        assert bomb.verdict == Verdict.MALICIOUS

    def test_merely_compressible_entry_is_still_scanned(self):
        """A high ratio alone must not stop extraction.

        Regression: a zero-padded 250KB executable compresses ~900x, which
        tripped the bomb check and skipped the entry -- so the payload inside it
        was never scanned and the real finding was lost. The byte budget, not the
        ratio, is what protects against bombs.
        """
        padded_exe = FAKE_PE + b"\x00" * (250 * 1024)
        data = make_zip({"invoice.pdf.exe": padded_exe})
        members, findings = run(data, "documents.zip")
        assert [m.name for m in members] == ["invoice.pdf.exe"]
        assert members[0].data == padded_exe
        assert "compression_bomb" not in rule_set(findings)
        note = next(f for f in findings if f.rule == "highly_compressible_entry")
        assert note.verdict == Verdict.SUSPICIOUS

    def test_payload_hidden_behind_padding_is_still_caught(self):
        """The end-to-end version of the regression above."""
        from netscan.core.detectors.structure import StructureDetector
        from netscan.core.engine import ScanEngine

        data = make_zip({"invoice.pdf.exe": FAKE_PE + b"\x00" * (250 * 1024)})
        result = ScanEngine([StructureDetector()]).scan(data, "documents.zip")
        assert result.verdict == Verdict.MALICIOUS
        assert "double_extension" in {f.rule for f in result.findings}

    def test_entry_count_limit(self):
        data = make_zip({f"f{i}.txt": b"x" for i in range(50)})
        members, findings = run(data, "many.zip", UnpackLimits(max_entries=10))
        assert len(members) == 10
        assert "unpack_budget_exhausted" in rule_set(findings)

    def test_total_bytes_limit(self):
        data = make_zip({f"f{i}.bin": b"A" * 4096 for i in range(20)}, compress=False)
        members, findings = run(data, "big.zip", UnpackLimits(max_total_bytes=8192))
        assert len(members) <= 2
        assert "unpack_budget_exhausted" in rule_set(findings)

    def test_path_traversal_entry_reported(self):
        buf = io.BytesIO()
        import zipfile
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../etc/passwd", b"root:x:0:0")
        _, findings = run(buf.getvalue(), "evil.zip")
        assert "path_traversal_entry" in rule_set(findings)

    def test_encrypted_entry_reported_as_unknown(self):
        # Minimal ZIP with the encryption bit set in the local and central headers.
        data = bytearray(make_zip({"secret.exe": FAKE_PE}, compress=False))
        for magic in (b"PK\x03\x04", b"PK\x01\x02"):
            idx = data.find(magic)
            flag_offset = idx + (6 if magic == b"PK\x03\x04" else 8)
            data[flag_offset] |= 0x01
        _, findings = run(bytes(data), "locked.zip")
        assert "encrypted_archive_entry" in rule_set(findings)
        assert next(f for f in findings
                    if f.rule == "encrypted_archive_entry").verdict == Verdict.UNKNOWN

    def test_corrupt_archive_is_reported_not_raised(self):
        _, findings = run(b"PK\x03\x04" + b"\xff" * 200, "broken.zip")
        assert "container_unreadable" in rule_set(findings)


class TestTar:
    def test_extracts_entries(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("payload.exe")
            info.size = len(FAKE_PE)
            tf.addfile(info, io.BytesIO(FAKE_PE))
        members, _ = run(buf.getvalue(), "a.tar")
        assert [m.name for m in members] == ["payload.exe"]
        assert members[0].ftype.executable


class TestSingleStream:
    def test_gzip(self):
        members, _ = run(gzip.compress(FAKE_PE), "payload.exe.gz")
        assert len(members) == 1
        assert members[0].name == "payload.exe"
        assert members[0].data == FAKE_PE

    def test_bzip2(self):
        members, _ = run(bz2.compress(b"hello world"), "note.txt.bz2")
        assert members[0].name == "note.txt"

    def test_xz(self):
        members, _ = run(lzma.compress(b"hello world"), "note.txt.xz")
        assert members[0].name == "note.txt"

    def test_tgz_becomes_tar_and_recurses(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("inner.exe")
            info.size = len(FAKE_PE)
            tf.addfile(info, io.BytesIO(FAKE_PE))
        members, _ = run(gzip.compress(buf.getvalue()), "bundle.tgz")
        assert "bundle.tgz -> bundle.tar -> inner.exe" in {m.path for m in members}

    def test_gzip_bomb_flagged(self):
        members, findings = run(gzip.compress(b"\x00" * (48 * 1024 * 1024)), "b.gz")
        assert "compression_bomb" in rule_set(findings)

    def test_modestly_compressible_gzip_is_only_noted(self):
        members, findings = run(gzip.compress(b"\x00" * (1024 * 1024)), "b.gz")
        assert "compression_bomb" not in rule_set(findings)
        assert "highly_compressible_entry" in rule_set(findings)
        assert len(members) == 1

    def test_name_without_known_suffix_gets_marker(self):
        members, _ = run(gzip.compress(b"hello"), "blob")
        assert members[0].name == "blob.decompressed"


class TestUnsupported:
    def test_rar_reported_as_uninspectable(self):
        _, findings = run(b"Rar!\x1a\x07\x00" + b"\x00" * 64, "a.rar")
        assert "unsupported_container" in rule_set(findings)

    def test_non_container_yields_nothing(self):
        members, findings = run(FAKE_PE, "a.exe")
        assert members == [] and findings == []
