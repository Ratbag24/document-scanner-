
from netscan.core.detectors.base import Detector, ScanTarget
from netscan.core.detectors.hashes import HashDetector, sha256_of
from netscan.core.detectors.structure import StructureDetector
from netscan.core.engine import EngineConfig, ScanEngine
from netscan.core.result import Finding, ScanResult, Verdict

from .conftest import FAKE_PE, PNG, make_zip


class ExplodingDetector(Detector):
    name = "exploding"

    def inspect(self, target):
        raise RuntimeError("boom")


class AlwaysFlags(Detector):
    name = "always"

    def inspect(self, target):
        return [Finding(self.name, "flagged", Verdict.MALICIOUS, path=target.path)]


class UnavailableDetector(Detector):
    name = "missing"

    @property
    def available(self):
        return False

    def unavailable_reason(self):
        return "dependency absent"

    def inspect(self, target):  # pragma: no cover - must never be called
        raise AssertionError("unavailable detector was run")


class TestVerdictRollup:
    def test_clean_file(self, engine):
        result = engine.scan(b"hello there\n" * 20, "notes.txt")
        assert result.verdict == Verdict.CLEAN
        assert not result.blocked

    def test_worst_finding_wins(self):
        result = ScanResult(name="x", size=0, sha256="")
        result.add(Finding("a", "r1", Verdict.SUSPICIOUS))
        result.add(Finding("a", "r2", Verdict.MALICIOUS))
        result.add(Finding("a", "r3", Verdict.CLEAN))
        assert result.verdict == Verdict.MALICIOUS

    def test_finding_inside_archive_raises_whole_verdict(self, engine):
        data = make_zip({"readme.txt": b"hi", "invoice.pdf.exe": FAKE_PE})
        result = engine.scan(data, "attachment.zip")
        assert result.blocked
        assert any("invoice.pdf.exe" in (f.path or "") for f in result.findings)

    def test_metadata_recorded(self, engine):
        result = engine.scan(PNG, "logo.png")
        assert result.sha256 == sha256_of(PNG)
        assert result.size == len(PNG)
        assert result.media_type == "image/png"
        assert result.meta["file_type"] == "PNG image"


class TestResilience:
    def test_detector_exception_is_captured_not_raised(self):
        engine = ScanEngine([ExplodingDetector(), AlwaysFlags()])
        result = engine.scan(b"data", "x.bin")
        assert result.errors and "boom" in result.errors[0]
        # The healthy detector still ran.
        assert result.verdict == Verdict.MALICIOUS

    def test_unavailable_detectors_are_skipped(self):
        engine = ScanEngine([UnavailableDetector(), StructureDetector()])
        assert engine.status()["missing"] == "dependency absent"
        assert len(engine.active_detectors) == 1
        engine.scan(FAKE_PE, "a.exe")  # must not raise

    def test_empty_file(self, engine):
        result = engine.scan(b"", "empty.bin")
        assert result.size == 0
        assert result.verdict == Verdict.CLEAN


class TestLimits:
    def test_oversize_file_is_hashed_but_not_scanned(self):
        engine = ScanEngine([AlwaysFlags()], EngineConfig(max_scan_bytes=1024))
        result = engine.scan(b"A" * 2048, "big.bin")
        assert {f.rule for f in result.findings} == {"too_large_to_scan"}
        assert result.verdict == Verdict.UNKNOWN
        assert result.sha256  # still recorded for the audit trail

    def test_unpacking_can_be_disabled(self):
        engine = ScanEngine([StructureDetector()],
                            EngineConfig(unpack_containers=False))
        data = make_zip({"invoice.pdf.exe": FAKE_PE})
        assert engine.scan(data, "a.zip").verdict == Verdict.CLEAN

    def test_unknown_can_be_escalated(self):
        engine = ScanEngine([AlwaysFlags()], EngineConfig(max_scan_bytes=10,
                                                          unknown_is_suspicious=True))
        result = engine.scan(b"A" * 100, "big.bin")
        assert result.verdict == Verdict.SUSPICIOUS


class TestHashDetector:
    def test_blocklist_hit(self, tmp_path):
        payload = b"known bad payload"
        blocklist = tmp_path / "bad.txt"
        blocklist.write_text(f"# a comment\n{sha256_of(payload)}  Trojan.Test\n\n")
        detector = HashDetector(blocklists=[blocklist])
        assert detector.available
        engine = ScanEngine([detector])
        result = engine.scan(payload, "x.bin")
        assert result.blocked
        assert result.findings[0].detail == "Trojan.Test"

    def test_allowlist_does_not_raise_verdict(self, tmp_path):
        payload = b"a known good file"
        allowlist = tmp_path / "good.txt"
        allowlist.write_text(f"{sha256_of(payload)} vendor installer\n")
        engine = ScanEngine([HashDetector(allowlists=[allowlist])])
        assert engine.scan(payload, "x.bin").verdict == Verdict.CLEAN

    def test_malformed_lines_ignored(self, tmp_path):
        listing = tmp_path / "bad.txt"
        listing.write_text("not-a-hash\nzz\n" + "a" * 64 + "\n")
        detector = HashDetector(blocklists=[listing])
        assert list(detector.blocked) == ["a" * 64]

    def test_missing_file_is_not_an_error(self, tmp_path):
        detector = HashDetector(blocklists=[tmp_path / "nope.txt"])
        assert not detector.available
        assert "no usable entries" in detector.unavailable_reason()

    def test_reload_picks_up_changes(self, tmp_path):
        payload = b"later-added payload"
        listing = tmp_path / "bad.txt"
        listing.write_text("# empty for now\n")
        detector = HashDetector(blocklists=[listing])
        target = ScanTarget(data=payload, name="x", ftype=None)  # ftype unused here
        assert detector.inspect(target) == []
        listing.write_text(f"{sha256_of(payload)} Added.Later\n")
        assert detector.reload_if_changed()
        assert detector.inspect(target)[0].verdict == Verdict.MALICIOUS


class TestSerialization:
    def test_json_round_trip(self, engine):
        import json
        result = engine.scan(FAKE_PE, "invoice.pdf")
        parsed = json.loads(result.to_json())
        assert parsed["verdict"] == "malicious"
        assert parsed["name"] == "invoice.pdf"
        assert parsed["findings"][0]["verdict"] in {"malicious", "suspicious"}

    def test_summary_is_single_line(self, engine):
        assert "\n" not in engine.scan(FAKE_PE, "invoice.pdf").summary()
