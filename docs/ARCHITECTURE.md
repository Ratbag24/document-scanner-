# Architecture

## Shape

```
   ingestion                    engine                     detectors
 ┌───────────────┐        ┌──────────────────┐       ┌──────────────────┐
 │ zeek_files.py │        │                  │       │ structure        │ no deps
 │ (passive)     ├───┐    │  identify type   │   ┌──►│ (disguises,      │
 └───────────────┘   │    │       ↓          │   │   │  active content) │
                     ├───►│  unpack (bounded)├───┤   ├──────────────────┤
 ┌───────────────┐   │    │       ↓          │   ├──►│ hashes           │ files
 │ icap.py       ├───┤    │  run detectors   │   │   ├──────────────────┤
 │ (inline)      │   │    │  over every part │   ├──►│ clamav           │ clamd
 └───────────────┘   │    │       ↓          │   │   ├──────────────────┤
                     │    │  roll up verdict │   └──►│ yara             │ rules
 ┌───────────────┐   │    └────────┬─────────┘       └──────────────────┘
 │ cli.py scan   ├───┘             │
 │ (files)       │                 ▼
 └───────────────┘         ScanResult → Reporter → console + JSONL + quarantine
```

Three ingestion paths feed one engine. Adding a fourth (an email gateway, an
S3 bucket, a download folder) means writing something that produces bytes and a
claimed filename; nothing else changes.

## Design decisions worth knowing

**Verdicts are ordered, and the worst wins.**
`CLEAN < UNKNOWN < SUSPICIOUS < MALICIOUS`. A finding anywhere inside a
container — at any nesting depth — raises the verdict of the whole object. This
is the only sane default: an archive whose fifth nested entry is a trojan is a
malicious archive.

`UNKNOWN` exists as a distinct state because "I could not look inside this" is
different information from "I looked and it was fine". A password-protected
archive is `UNKNOWN`, never `CLEAN`.

**Detectors never raise.** Every detector's contract is to return findings for
hostile, truncated, and malformed input. The engine wraps each call anyway, so a
bug in one detector cannot suppress another's findings — it lands in
`ScanResult.errors` instead. A scanner that crashes on a malformed file is a
scanner an attacker can turn off with a malformed file.

**Missing dependencies degrade, they do not fail.** No clamd, no YARA rules, no
hash lists: those detectors report `available == False`, the engine skips them,
and the CLI says so once at startup. The structural detector needs nothing but
the standard library, so there is always at least one working detector.

**Unpacking is bounded on every axis.** Depth, entry count, total output bytes,
per-entry bytes, and compression ratio, all accounted against a single budget
per top-level object (`UnpackBudget`). Extraction is entirely in memory, which
means archive entry names are never used as filesystem paths — path traversal is
structurally impossible rather than defended against. Traversal-shaped entries
are still *reported*, because an archive built to escape an extractor tells you
something about intent.

**The filename is untrusted input, and it matters anyway.** Most of the
structural checks compare the claimed name against the actual bytes, so the name
has to be the one the user's machine would save the file under — from
`Content-Disposition`, the URL path, or Zeek's `files.log` — not a synthetic one.
When no real name is available the engine gets `None` rather than a placeholder:
a made-up name produces made-up findings.

## Where each check lives

| Question | Module |
|---|---|
| What type is this really? | `core/filetype.py` |
| Does it match what it claims to be? | `core/detectors/structure.py` |
| What is inside it? | `core/unpack.py` |
| Is it known bad? | `core/detectors/clamav.py`, `core/detectors/hashes.py` |
| Does it match a family pattern? | `core/detectors/yara_rules.py` |
| How do findings become one verdict? | `core/engine.py`, `core/result.py` |
| Where do files come from? | `ingest/zeek_files.py`, `ingest/icap.py` |
| What happens to the verdict? | `report.py` |

## The structural detector

This is the part that answers the original question — "is this file hiding
something?" — and it needs no signature database, so it works on payloads that
have never been seen before:

| Check | What it catches |
|---|---|
| `extension_content_mismatch` | `invoice.pdf` that is a Windows executable |
| `double_extension` | `invoice.pdf.exe` |
| `filename_bidi_override` | Unicode RTL override making `gpj.exe` render as `exe.jpg` |
| `data_after_end_of_file` | Payload appended past a PNG's `IEND` or a JPEG's `FFD9` |
| `polyglot_file` | That appended payload being itself an executable or archive |
| `executable_inside_media_file` | PE code inside an image or audio file |
| `macro_in_macro_free_extension` | VBA in a `.docx`, which cannot legitimately hold macros |
| `pdf_launch_action` | A PDF that runs a program on open |
| `powershell_encoded_command` etc. | Dropper techniques in scripts |
| `high_entropy_content` | Packed or encrypted payload where the format does not explain it |
| `compression_bomb` | Archive that expands beyond its declared ratio |

Verdict assignment is deliberate: things with no legitimate explanation
(`double_extension`, `polyglot_file`, macros in a macro-free format) are
`MALICIOUS`; things with an innocent reading (`risky_extension`,
`office_macro_project`, `high_entropy_content`) are `SUSPICIOUS`, so they show up
in the log without blocking at the default threshold.

## Extending it

A new detector is one class:

```python
from netscan.core.detectors.base import Detector, ScanTarget
from netscan.core.result import Finding, Verdict

class MyDetector(Detector):
    name = "mine"

    @property
    def available(self) -> bool:
        return True                      # False when a backend is missing

    def inspect(self, target: ScanTarget) -> list[Finding]:
        # target.data, target.name, target.ftype, target.path, target.depth
        # Called once per object, including every unpacked archive member.
        # Must not raise.
        return []
```

Add it in `Config.detectors()`. It will be run over every object and every
unpacked member automatically, and its findings roll into the verdict like any
other.

## Testing

```bash
pytest                              # 155 tests, no network or clamd needed
netscan selftest                    # end-to-end against 12 synthetic samples
ruff check .
```

The test suite deliberately avoids requiring clamd, so it runs anywhere; the
`selftest` command is what proves a real deployment works, and it reports which
detectors were actually exercised. The ICAP tests run a real server on a real
socket, because protocol bugs do not show up in unit tests of the parser.
