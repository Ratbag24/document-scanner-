import json

from netscan import cli
from netscan.config import Config
from netscan.report import Reporter
from netscan.selftest import run_selftest

from .conftest import FAKE_PE, PNG


class TestScanCommand:
    def test_clean_file_exits_zero(self, tmp_path, capsys):
        (tmp_path / "notes.txt").write_bytes(b"hello\n" * 20)
        assert cli.main(["scan", str(tmp_path / "notes.txt")]) == cli.EXIT_CLEAN

    def test_malicious_file_exits_one(self, tmp_path):
        (tmp_path / "invoice.pdf").write_bytes(FAKE_PE)
        assert cli.main(["scan", str(tmp_path / "invoice.pdf")]) == cli.EXIT_MALICIOUS

    def test_suspicious_file_exits_two(self, tmp_path):
        pdf = b"%PDF-1.7\n<</OpenAction<</S/JavaScript/JS(x())>>>>\n%%EOF"
        (tmp_path / "a.pdf").write_bytes(pdf)
        assert cli.main(["scan", str(tmp_path / "a.pdf")]) == cli.EXIT_SUSPICIOUS

    def test_directory_needs_recursive_flag(self, tmp_path, capsys):
        (tmp_path / "invoice.pdf").write_bytes(FAKE_PE)
        assert cli.main(["scan", str(tmp_path)]) == cli.EXIT_CLEAN
        assert "use -r" in capsys.readouterr().err

    def test_recursive_finds_nested_file(self, tmp_path):
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "invoice.pdf").write_bytes(FAKE_PE)
        assert cli.main(["scan", "-r", str(tmp_path)]) == cli.EXIT_MALICIOUS

    def test_missing_path_reported(self, tmp_path, capsys):
        cli.main(["scan", str(tmp_path / "absent")])
        assert "no such file" in capsys.readouterr().err

    def test_jsonl_log_written(self, tmp_path):
        (tmp_path / "invoice.pdf").write_bytes(FAKE_PE)
        log = tmp_path / "scan.jsonl"
        cli.main(["--log", str(log), "scan", str(tmp_path / "invoice.pdf")])
        record = json.loads(log.read_text().splitlines()[0])
        assert record["verdict"] == "malicious"
        assert "timestamp" in record

    def test_quiet_suppresses_clean_results(self, tmp_path, capsys):
        (tmp_path / "logo.png").write_bytes(PNG)
        cli.main(["-q", "scan", str(tmp_path / "logo.png")])
        out = capsys.readouterr().out
        assert "logo.png" not in out
        assert "scanned 1 file(s)" in out


class TestStatusCommand:
    def test_lists_detectors(self, capsys):
        cli.main(["status"])
        out = capsys.readouterr().out
        assert "structure" in out
        assert "detectors ready" in out


class TestSelftest:
    def test_all_samples_behave_as_documented(self, tmp_path, capsys):
        config = Config.load()
        reporter = Reporter(log_file=None, quiet_clean=True)
        assert run_selftest(config, reporter) == 0
        assert "failed" in capsys.readouterr().out


class TestConfig:
    def test_toml_is_applied(self, tmp_path):
        cfg_file = tmp_path / "netscan.toml"
        cfg_file.write_text(
            "[clamav]\nenabled = false\nport = 9999\n"
            "[scan]\nmax_depth = 2\nunknown_is_suspicious = true\n"
            "[icap]\nport = 2000\nblock_at = \"suspicious\"\n")
        config = Config.load(cfg_file)
        assert config.clamd_enabled is False
        assert config.clamd_port == 9999
        assert config.max_depth == 2
        assert config.unknown_is_suspicious is True
        assert config.icap_port == 2000
        assert config.block_at == "suspicious"

    def test_env_overrides_toml(self, tmp_path, monkeypatch):
        cfg_file = tmp_path / "netscan.toml"
        cfg_file.write_text("[icap]\nport = 2000\n")
        monkeypatch.setenv("NETSCAN_ICAP_PORT", "3000")
        assert Config.load(cfg_file).icap_port == 3000

    def test_disabling_clamav_removes_the_detector(self, monkeypatch):
        monkeypatch.setenv("NETSCAN_CLAMD_ENABLED", "false")
        engine = Config.load().engine()
        assert "clamav" not in engine.status()

    def test_structure_detector_is_always_present(self):
        assert "structure" in Config.load().engine().status()

    def test_bad_env_int_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("NETSCAN_ICAP_PORT", "not-a-number")
        assert Config.load().icap_port == 1344


class TestReporter:
    def test_quarantine_writes_a_sidecar_verdict(self, tmp_path):
        from netscan.core.detectors.structure import StructureDetector
        from netscan.core.engine import ScanEngine
        from netscan.report import quarantine

        source = tmp_path / "invoice.pdf"
        source.write_bytes(FAKE_PE)
        result = ScanEngine([StructureDetector()]).scan(FAKE_PE, "invoice.pdf")
        target = quarantine(source, result, tmp_path / "q")
        assert target.suffix == ".quarantined"
        assert not source.exists()
        sidecar = json.loads(target.with_suffix(".quarantined.json").read_text())
        assert sidecar["verdict"] == "malicious"

    def test_quarantine_sanitizes_hostile_names(self, tmp_path):
        from netscan.core.result import ScanResult
        from netscan.report import quarantine

        source = tmp_path / "payload"
        source.write_bytes(b"x")
        result = ScanResult(name="../../etc/passwd", size=1, sha256="ab" * 32)
        target = quarantine(source, result, tmp_path / "q")
        assert target.parent == tmp_path / "q"
        assert ".." not in target.name
