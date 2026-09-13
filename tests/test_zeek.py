import io

import pytest

from netscan.core.detectors.structure import StructureDetector
from netscan.core.engine import ScanEngine
from netscan.ingest.zeek_files import FilesLogIndex, ZeekFileWatcher, parse_extract_name
from netscan.report import Reporter

from .conftest import FAKE_PE, PNG

FILES_LOG_TSV = """#separator \\x09
#fields\tts\tfuid\ttx_hosts\trx_hosts\tsource\tmime_type\tfilename
1700000000.1\tFabc123\t93.184.216.34\t192.168.1.42\tHTTP\tapplication/pdf\tinvoice.pdf
1700000001.2\tFdef456\t203.0.113.7\t192.168.1.55\tHTTP\timage/png\t-
"""


class TestParseExtractName:
    @pytest.mark.parametrize("name,expected", [
        # The name deploy/zeek/netscan-extract.zeek writes.
        ("extract-HTTP-FQ3rKF1tRJ5XnHhLSc", ("HTTP", "FQ3rKF1tRJ5XnHhLSc")),
        ("extract-FTP_DATA-Fxyz", ("FTP_DATA", "Fxyz")),
        # Timestamped names from other extraction scripts.
        ("extract-1699999999.123456-HTTP-FabcDEF123", ("HTTP", "FabcDEF123")),
        ("extract-1.2-FTP_DATA-Fxyz", ("FTP_DATA", "Fxyz")),
        ("extract-1.2-SMTP-Fq", ("SMTP", "Fq")),
        ("random.bin", ("", "")),
        ("extract-short", ("", "")),
        ("", ("", "")),
    ])
    def test_parsing(self, name, expected):
        assert parse_extract_name(name) == expected


class TestFilesLogIndex:
    def test_parses_tsv(self, tmp_path):
        log = tmp_path / "files.log"
        log.write_text(FILES_LOG_TSV)
        index = FilesLogIndex(log)
        index.refresh()
        context = index.lookup("Fabc123")
        assert context is not None
        assert context.source == "HTTP"
        assert context.filename == "invoice.pdf"
        assert context.rx_hosts == "192.168.1.42"

    def test_dash_means_absent(self, tmp_path):
        log = tmp_path / "files.log"
        log.write_text(FILES_LOG_TSV)
        index = FilesLogIndex(log)
        index.refresh()
        assert index.lookup("Fdef456").filename == ""

    def test_parses_json_lines(self, tmp_path):
        log = tmp_path / "files.log"
        log.write_text('{"fuid":"Fjson1","source":"HTTP","filename":"a.exe",'
                       '"tx_hosts":["1.2.3.4"],"rx_hosts":["192.168.1.9"]}\n')
        index = FilesLogIndex(log)
        index.refresh()
        context = index.lookup("Fjson1")
        assert context.filename == "a.exe"
        assert context.tx_hosts == "1.2.3.4"

    def test_incremental_tail(self, tmp_path):
        log = tmp_path / "files.log"
        log.write_text(FILES_LOG_TSV)
        index = FilesLogIndex(log)
        index.refresh()
        assert index.lookup("Fnew") is None
        with log.open("a") as fh:
            fh.write("1700000002.3\tFnew\t1.1.1.1\t192.168.1.7\tHTTP\ttext/plain\tnew.txt\n")
        index.refresh()
        assert index.lookup("Fnew").filename == "new.txt"

    def test_partial_line_is_not_consumed(self, tmp_path):
        log = tmp_path / "files.log"
        log.write_text(FILES_LOG_TSV)
        index = FilesLogIndex(log)
        index.refresh()
        with log.open("a") as fh:
            fh.write("1700000003.4\tFhalf\t1.1.1.1\t192.168.1.8\tHTTP")  # no newline
        index.refresh()
        assert index.lookup("Fhalf") is None
        with log.open("a") as fh:
            fh.write("\ttext/plain\tlate.txt\n")
        index.refresh()
        assert index.lookup("Fhalf").filename == "late.txt"

    def test_missing_log_is_not_an_error(self, tmp_path):
        index = FilesLogIndex(tmp_path / "absent.log")
        index.refresh()
        assert index.lookup("x") is None

    def test_index_is_bounded(self, tmp_path):
        log = tmp_path / "files.log"
        lines = ["#fields\tts\tfuid\tsource\n"]
        lines += [f"1.{i}\tF{i}\tHTTP\n" for i in range(50)]
        log.write_text("".join(lines))
        index = FilesLogIndex(log, max_entries=10)
        index.refresh()
        assert len(index._index) == 10
        assert index.lookup("F49") is not None  # newest retained
        assert index.lookup("F0") is None       # oldest evicted


@pytest.fixture
def watcher(tmp_path):
    extract = tmp_path / "extract"
    extract.mkdir()
    quarantine = tmp_path / "quarantine"
    reporter = Reporter(log_file=tmp_path / "scan.jsonl", quiet_clean=True,
                        stream=io.StringIO())
    w = ZeekFileWatcher(
        engine=ScanEngine([StructureDetector()]),
        extract_dir=extract,
        reporter=reporter,
        files_log=tmp_path / "files.log",
        quarantine_dir=quarantine,
        settle_seconds=0,
        poll_interval=0,
    )
    return w, extract, quarantine, tmp_path


class TestWatcher:
    def test_clean_file_is_deleted(self, watcher):
        w, extract, quarantine, _ = watcher
        path = extract / "extract-1.0-HTTP-Fclean"
        path.write_bytes(PNG)
        w.run(once=True)
        assert not path.exists()
        assert w.stats["scanned"] == 1
        assert not quarantine.exists() or not list(quarantine.iterdir())

    def test_flagged_file_is_quarantined(self, watcher):
        w, extract, quarantine, _ = watcher
        path = extract / "extract-1.0-HTTP-Fbad"
        path.write_bytes(PNG + FAKE_PE)
        w.process(path)
        assert not path.exists()
        assert w.stats["malicious"] == 1
        quarantined = list(quarantine.glob("*.quarantined"))
        assert len(quarantined) == 1
        # The verdict sits next to the file so the folder explains itself.
        assert list(quarantine.glob("*.json"))
        assert quarantined[0].stat().st_mode & 0o777 == 0o600

    def test_uses_the_server_declared_filename(self, watcher):
        """Zeek's synthetic name has no extension, so mismatch checks need the
        real one from files.log."""
        w, extract, quarantine, tmp_path = watcher
        (tmp_path / "files.log").write_text(
            "#fields\tts\tfuid\ttx_hosts\trx_hosts\tsource\tmime_type\tfilename\n"
            "1.0\tFabc\t93.184.216.34\t192.168.1.42\tHTTP\tapplication/pdf\tinvoice.pdf\n")
        w.index.refresh()
        path = extract / "extract-1.0-HTTP-Fabc"
        path.write_bytes(FAKE_PE)  # a PE served as invoice.pdf
        w.process(path)
        assert w.stats["malicious"] == 1
        log_lines = (tmp_path / "scan.jsonl").read_text().splitlines()
        import json
        record = json.loads(log_lines[-1])
        assert record["name"] == "invoice.pdf"
        assert record["meta"]["recipient"] == "192.168.1.42"
        assert record["meta"]["sender"] == "93.184.216.34"
        assert any(f["rule"] == "extension_content_mismatch" for f in record["findings"])

    def test_partial_file_is_not_scanned_until_stable(self, tmp_path):
        extract = tmp_path / "extract"
        extract.mkdir()
        w = ZeekFileWatcher(
            engine=ScanEngine([StructureDetector()]),
            extract_dir=extract,
            reporter=Reporter(stream=io.StringIO(), quiet_clean=True),
            settle_seconds=60,   # nothing can settle within the test
            drain_timeout=0,     # so once-mode does a single pass and returns
        )
        (extract / "extract-1.0-HTTP-Fgrow").write_bytes(b"partial")
        w.run(once=True)
        assert w.stats["scanned"] == 0

    def test_unreadable_file_counts_as_an_error(self, watcher):
        w, extract, _, _ = watcher
        w.process(extract / "does-not-exist")
        assert w.stats["errors"] == 1

    def test_vanished_file_is_forgotten(self, tmp_path):
        extract = tmp_path / "extract"
        extract.mkdir()
        w = ZeekFileWatcher(
            engine=ScanEngine([StructureDetector()]),
            extract_dir=extract,
            reporter=Reporter(stream=io.StringIO(), quiet_clean=True),
            settle_seconds=60,
            drain_timeout=0,
        )
        path = extract / "extract-1.0-HTTP-Fgone"
        path.write_bytes(b"x")
        w.run(once=True)
        assert path in w._pending
        path.unlink()
        w.run(once=True)
        assert path not in w._pending


class TestFalsePositives:
    """Zeek's synthetic filenames must not themselves generate findings.

    Regression: `extract-1699999999.123456-HTTP-Fabc` was read as having the
    extension `.123456-http-fabc`, so every clean file Zeek carved out was
    reported as an extension/content mismatch.
    """

    def test_synthetic_name_does_not_flag_a_clean_png(self, watcher):
        w, extract, quarantine, _ = watcher
        path = extract / "extract-1699999999.123456-HTTP-Fclean"
        path.write_bytes(PNG)
        w.process(path)
        assert w.stats["malicious"] == 0
        assert w.stats["suspicious"] == 0
        assert not path.exists()  # deleted as clean, not quarantined
        assert not list(quarantine.glob("*.quarantined"))

    def test_on_disk_name_is_still_recorded(self, watcher):
        w, extract, _, tmp_path = watcher
        path = extract / "extract-1699999999.123456-HTTP-Fclean"
        path.write_bytes(PNG)
        w.process(path)
        import json
        record = json.loads((tmp_path / "scan.jsonl").read_text().splitlines()[-1])
        assert record["name"] == "extract-1699999999.123456-HTTP-Fclean"
        assert record["meta"]["zeek_fuid"] == "Fclean"

    def test_real_payload_still_caught_without_files_log(self, watcher):
        """Content-based detection does not depend on knowing the filename."""
        w, extract, quarantine, _ = watcher
        path = extract / "extract-1699999999.123456-HTTP-Fbad"
        path.write_bytes(PNG + FAKE_PE)
        w.process(path)
        assert w.stats["malicious"] == 1
        assert list(quarantine.glob("*.quarantined"))


class TestOnceMode:
    """`--once` must actually drain the backlog.

    Regression: one pass only registered files as pending (a file is scanned
    after its size holds steady across two polls), so `--once` scanned nothing.
    """

    def test_once_drains_the_backlog(self, tmp_path):
        extract = tmp_path / "extract"
        extract.mkdir()
        w = ZeekFileWatcher(
            engine=ScanEngine([StructureDetector()]),
            extract_dir=extract,
            reporter=Reporter(stream=io.StringIO(), quiet_clean=True),
            settle_seconds=0,
            poll_interval=0,
        )
        for i in range(3):
            (extract / f"extract-1.{i}-HTTP-F{i}").write_bytes(PNG)
        w.run(once=True)
        assert w.stats["scanned"] == 3
        assert list(extract.iterdir()) == []

    def test_once_terminates_even_while_files_keep_arriving(self, tmp_path):
        extract = tmp_path / "extract"
        extract.mkdir()
        w = ZeekFileWatcher(
            engine=ScanEngine([StructureDetector()]),
            extract_dir=extract,
            reporter=Reporter(stream=io.StringIO(), quiet_clean=True),
            settle_seconds=60,   # nothing ever settles
            poll_interval=0,
            drain_timeout=0.2,   # so the deadline is what ends the run
        )
        (extract / "extract-1.0-HTTP-Fgrow").write_bytes(b"partial")
        w.run(once=True)  # must return rather than loop forever
        assert w.stats["scanned"] == 0
