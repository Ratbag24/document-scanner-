"""Command-line entry point: netscan <scan|watch|icap|status|selftest>."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Config
from .core.result import Verdict
from .report import Reporter

# Exit codes chosen so shell scripts and CI can branch on the verdict.
EXIT_CLEAN = 0
EXIT_MALICIOUS = 1
EXIT_SUSPICIOUS = 2
EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan",
        description="Scan files carried over your network for malware and disguised content.",
    )
    parser.add_argument("-c", "--config", type=Path, metavar="FILE",
                        help="TOML config file (see netscan.example.toml)")
    parser.add_argument("--log", type=Path, metavar="FILE",
                        help="append one JSON result per line to FILE")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only print suspicious and malicious results")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan files or directories on disk")
    p_scan.add_argument("paths", nargs="+", type=Path)
    p_scan.add_argument("-r", "--recursive", action="store_true",
                        help="descend into directories")

    p_watch = sub.add_parser(
        "watch", help="watch a Zeek extraction directory (passive, cannot block)")
    p_watch.add_argument("--dir", type=Path, help="override the extraction directory")
    p_watch.add_argument("--files-log", type=Path,
                         help="Zeek files.log, used to attribute files to hosts")
    p_watch.add_argument("--quarantine", type=Path, help="move flagged files here")
    p_watch.add_argument("--keep-clean", action="store_true",
                         help="do not delete files that scan clean")
    p_watch.add_argument("--once", action="store_true",
                         help="process the current backlog and exit")

    p_icap = sub.add_parser("icap", help="run the ICAP service for a proxy (can block)")
    p_icap.add_argument("--host")
    p_icap.add_argument("--port", type=int)
    p_icap.add_argument("--block-at", choices=["suspicious", "malicious"],
                        help="lowest verdict that blocks a download")

    sub.add_parser("status", help="show which detectors are ready")
    sub.add_parser("selftest", help="scan built-in samples to prove the pipeline works")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = Config.load(args.config)
    log_file = args.log or config.log_file
    reporter = Reporter(log_file=log_file, quiet_clean=args.quiet)

    if args.command == "status":
        return _cmd_status(config)
    if args.command == "scan":
        return _cmd_scan(args, config, reporter)
    if args.command == "watch":
        return _cmd_watch(args, config, reporter)
    if args.command == "icap":
        return _cmd_icap(args, config, reporter)
    if args.command == "selftest":
        return _cmd_selftest(config, reporter)
    return EXIT_ERROR


def _cmd_status(config: Config) -> int:
    engine = config.engine()
    print("detectors:")
    ready = 0
    for name, state in engine.status().items():
        mark = "+" if state == "ready" else "-"
        print(f"  [{mark}] {name}: {state}")
        ready += state == "ready"
    print(f"\n{ready} of {len(engine.detectors)} detectors ready")
    if ready == 0:
        print("no detectors are usable; see docs/DEPLOYMENT.md", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_CLEAN


def _iter_paths(paths: list[Path], recursive: bool):
    for path in paths:
        if path.is_dir():
            if not recursive:
                print(f"skipping directory {path} (use -r)", file=sys.stderr)
                continue
            yield from (p for p in sorted(path.rglob("*")) if p.is_file())
        elif path.is_file():
            yield path
        else:
            print(f"no such file: {path}", file=sys.stderr)


def _cmd_scan(args, config: Config, reporter: Reporter) -> int:
    engine = config.engine()
    _warn_unavailable(engine)
    worst = Verdict.CLEAN
    count = 0
    for path in _iter_paths(args.paths, args.recursive):
        try:
            data = path.read_bytes()
        except OSError as exc:
            print(f"could not read {path}: {exc}", file=sys.stderr)
            continue
        result = engine.scan(data, path.name)
        reporter.report(result, source=str(path.parent))
        worst = max(worst, result.verdict)
        count += 1
    print(f"\nscanned {count} file(s); worst verdict: {worst.label}")
    return _exit_code(worst)


def _cmd_watch(args, config: Config, reporter: Reporter) -> int:
    from .ingest.zeek_files import ZeekFileWatcher

    extract_dir = args.dir or config.zeek_extract_dir
    engine = config.engine()
    _warn_unavailable(engine)
    watcher = ZeekFileWatcher(
        engine=engine,
        extract_dir=extract_dir,
        reporter=reporter,
        files_log=args.files_log,
        quarantine_dir=args.quarantine or config.quarantine_dir,
        delete_clean=not args.keep_clean,
    )
    print(f"watching {extract_dir} for files extracted from traffic")
    if not (args.quarantine or config.quarantine_dir):
        print("note: no quarantine directory set; flagged files are left in place")
    print("this path is passive -- it reports on downloads, it does not block them")
    try:
        watcher.run(once=args.once)
    except KeyboardInterrupt:
        print()
    print(f"scanned {watcher.stats['scanned']}, "
          f"malicious {watcher.stats['malicious']}, "
          f"suspicious {watcher.stats['suspicious']}, "
          f"errors {watcher.stats['errors']}")
    return EXIT_CLEAN


def _cmd_icap(args, config: Config, reporter: Reporter) -> int:
    from .ingest.icap import make_server, verdict_from_name

    host = args.host or config.icap_host
    port = args.port or config.icap_port
    block_at = verdict_from_name(args.block_at or config.block_at)
    engine = config.engine()
    _warn_unavailable(engine)

    server, stats = make_server(engine, reporter, host=host, port=port, block_at=block_at)
    print(f"ICAP service on icap://{host}:{port}/netscan")
    print(f"blocking downloads at verdict '{block_at.label}' and above")
    print("point your proxy at this service; see deploy/squid.conf")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.shutdown()
        server.server_close()
    print("stats:", ", ".join(f"{k}={v}" for k, v in sorted(stats.items())) or "none")
    return EXIT_CLEAN


def _cmd_selftest(config: Config, reporter: Reporter) -> int:
    from .selftest import run_selftest

    return run_selftest(config, reporter)


def _warn_unavailable(engine) -> None:
    for name, state in engine.status().items():
        if state != "ready":
            print(f"warning: detector '{name}' is not active: {state}", file=sys.stderr)


def _exit_code(verdict: Verdict) -> int:
    if verdict >= Verdict.MALICIOUS:
        return EXIT_MALICIOUS
    if verdict == Verdict.SUSPICIOUS:
        return EXIT_SUSPICIOUS
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
