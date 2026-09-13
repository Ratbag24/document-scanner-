# netscan

A scanner that tells you whether a file is hiding something — wired up to see
the files crossing your own network.

It answers two different questions at once:

- **Is this a known-bad file?** — ClamAV signatures, YARA rules, hash blocklists.
- **Is this file pretending to be something it isn't?** — a `.pdf` that's
  actually a Windows executable, an executable stitched onto the end of a
  holiday photo, macros in a `.docx` that can't legitimately hold them, a
  filename using a Unicode trick to render `gpj.exe` as `exe.jpg`.

The second question is the interesting one. It needs no signature database, so
it works on payloads nobody has ever seen before, and it's where most real
delivery tricks live.

## Read this before you plan a deployment

**You cannot scan encrypted traffic, and almost all your traffic is encrypted.**
90–98% of a typical home network is HTTPS/QUIC. A box between your router and the
internet sees encrypted bytes — no filenames, no file contents. Nothing changes
that except intercepting TLS with your own CA installed on every device, which
breaks banking apps, Windows Update, and most mobile apps, and makes your scanner
box the most sensitive machine you own.

So there are three honest options:

| | Sees file contents | Can block | Breaks things |
|---|---|---|---|
| **Passive tap** — Zeek carves files out of a mirrored copy of traffic | Unencrypted only: HTTP, FTP, SMTP, SMB | No | No |
| **Inline proxy** — Squid + ICAP, TLS interception | Most HTTPS | Yes | Yes, significantly |
| **Endpoint agent** — scan on each machine | Everything | Yes | No |

**Start with the passive tap.** It can't break your internet, and it's genuinely
good at the thing network scanning is uniquely good at: noticing that a device on
your LAN is *already* compromised and spreading. IoT malware, LAN-to-LAN
transfers, and plaintext C2 are all invisible to an endpoint scanner and wide
open to a tap.

netscan supports all three ingestion paths through the same engine.
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) walks through the trade-offs properly.

## Quick start

No dependencies are required — the structural detector runs on the standard
library alone.

```bash
git clone <this repo> && cd document-scanner-
python3 -m venv .venv && .venv/bin/pip install -e .

.venv/bin/netscan status      # which detectors are ready
.venv/bin/netscan selftest    # prove detection works on 12 synthetic samples
.venv/bin/netscan scan -r ~/Downloads
```

Add the optional backends for real coverage:

```bash
.venv/bin/pip install -e '.[yara]'
sudo apt install clamav-daemon && sudo freshclam    # ~250MB of signatures
```

### What it looks like

```
$ netscan scan ~/Downloads/invoice.pdf ~/Downloads/documents.zip
[BAD ] invoice.pdf from /home/you/Downloads (242.6KB, PE/DOS executable)
         MALICIOUS: extension_content_mismatch (structure) named .pdf but the bytes are a PE/DOS executable
         SUSPICIOUS: high_entropy_content (structure) entropy 8.00/8.00 suggests packed or encrypted content
[BAD ] documents.zip from /home/you/Downloads (1.5KB, ZIP archive)
         MALICIOUS: double_extension [documents.zip -> invoice.pdf.exe] (structure) looks like a .pdf file but is really .exe
         SUSPICIOUS: risky_extension [documents.zip -> invoice.pdf.exe] (structure) .exe is executed by the OS on open

scanned 2 file(s); worst verdict: malicious
```

The path in brackets is where inside a container the finding sits, so a payload
buried three archives deep still tells you exactly where it is.

Exit codes are `0` clean, `1` malicious, `2` suspicious, `3` error — so it drops
into a script or a CI step without parsing output.

## Running it on network traffic

**Passive** (recommended). Zeek carves files out of traffic; netscan scans them:

```bash
echo '@load /opt/netscan/deploy/zeek/netscan-extract.zeek' \
  >> /opt/zeek/share/zeek/site/local.zeek
zeekctl deploy

netscan --log /var/log/netscan/scan.jsonl --quiet watch \
    --files-log /opt/zeek/logs/current/files.log \
    --quarantine /var/lib/netscan/quarantine
```

Alerts name the host that received the file, because `files.log` is correlated by
Zeek's file UID:

```
[BAD ] setup.exe from HTTP 203.0.113.9 -> 192.168.1.42 (1.2MB, PE/DOS executable)
         MALICIOUS: Win.Trojan.Agent-1234567 (clamav) matched a ClamAV signature
```

**Inline** (can actually block). netscan runs as an ICAP service behind Squid:

```bash
netscan icap --port 1344 --block-at malicious
# then merge deploy/squid.conf into your squid.conf
```

Blocked downloads get an HTML page naming the file, its SHA-256, and the reason.

Docker for either path:

```bash
docker compose -f deploy/docker-compose.yml up -d           # passive
docker compose -f deploy/docker-compose.inline.yml up -d    # inline
```

## Configuration

Every setting has a working default. Copy `netscan.example.toml` to
`/etc/netscan/netscan.toml` and edit, or use `NETSCAN_*` environment variables,
which override the file.

The one setting worth thinking about is `[icap].block_at`. It defaults to
`malicious`. Setting it to `suspicious` will block macro-bearing documents and
password-protected archives — run at the default for a week, read the log, then
decide.

## Output

One JSON object per line, ready for any log collector:

```json
{"verdict":"malicious","name":"invoice.pdf","sha256":"3b1f…","size":248320,
 "media_type":"application/vnd.microsoft.portable-executable",
 "findings":[{"detector":"structure","rule":"extension_content_mismatch",
              "verdict":"malicious","detail":"named .pdf but the bytes are a PE/DOS executable",
              "path":null}],
 "meta":{"zeek_source":"HTTP","sender":"203.0.113.9","recipient":"192.168.1.42"},
 "duration_ms":34,"timestamp":1757764800.1}
```

```bash
# what's firing most
jq -r '.findings[].rule' scan.jsonl | sort | uniq -c | sort -rn
```

## What it deliberately does not do

- **Doesn't see encrypted traffic** without TLS interception.
- **Doesn't detect novel malware by behaviour.** No sandbox, no emulation. It
  catches delivery *tricks* structurally and *known* code by signature. A clean
  novel binary gets through.
- **Doesn't open RAR or 7-Zip** itself — those are reported as uninspectable
  rather than silently passed (clamd will look inside them if built for it).
- **Doesn't block in the passive deployment.** That's the point of it.

A scanner you trust more than it deserves is worse than no scanner, so those
limits are in the docs rather than the footnotes.

## Verification status

What has actually been run, versus what has only been written:

**Verified end to end**

- **Inline blocking through a real proxy.** Squid 6.14 in front of a real origin
  server: malicious downloads returned `403` with the block page, clean ones
  returned `200` byte-identical, and Squid's own log recorded `TCP_MISS/403`.
  Scans took 1–9ms. Reproduce with
  `NETSCAN_INTEGRATION=1 pytest tests/test_squid_integration.py`.
- **The clamd path**, against a live clamd 1.5.3 over its INSTREAM protocol,
  including detection inside nested archives.
- **The engine, structural detector and unpacker** — 157 unit tests.
- **The passive watcher**, against a simulated Zeek extraction directory and a
  real `files.log`: correct verdicts, host attribution, quarantine at 0600 with
  a sidecar verdict, clean files deleted.

**Not verified here — treat as untested**

- **`deploy/zeek/netscan-extract.zeek` has never been run by Zeek.** Zeek was not
  installable in the environment this was built in. The script follows the
  documented API and one real bug was found by review (`FileExtract::prefix` is
  `const &redef` and cannot be assigned in an event handler), but **validate it
  against a pcap before relying on it**:
  `zeek -C -r some.pcap deploy/zeek/netscan-extract.zeek && ls extract_files/`
- **Real ClamAV signature coverage.** `freshclam` was blocked by the build
  environment's network policy, so clamd was exercised with a minimal custom
  test database. The protocol integration is proven; the breadth of the official
  signature set is not.
- **The Docker and compose files** — no Docker daemon was available.
- **TLS interception.** The commented block in `deploy/squid.conf` is written
  from the documentation, not from a working deployment.

## Docs

- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — network placement, TLS trade-off,
  hardware sizing, tuning out false positives
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the pieces fit, every
  structural check, how to add a detector
- [rules/README.md](rules/README.md) — YARA rules, and where to get real rulesets

## Development

```bash
pip install -e '.[dev]'
pytest          # 157 tests; no network, proxy or clamd needed
ruff check .
netscan selftest

# End-to-end against a real Squid proxy (needs squid installed).
# Skipped by default because it binds ports and needs writable squid dirs.
NETSCAN_INTEGRATION=1 pytest tests/test_squid_integration.py -v
```
