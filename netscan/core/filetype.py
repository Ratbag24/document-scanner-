"""Content-based file type identification.

Deliberately does not use libmagic: we need a small, predictable table we can
reason about, and we care about a specific question libmagic does not answer
directly -- "does the declared extension agree with the actual bytes?".
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FileType:
    media_type: str
    label: str
    extensions: tuple[str, ...]
    executable: bool = False
    container: bool = False


# (offset, magic bytes, FileType). Order matters: longer/more specific first.
def _ft(media_type: str, label: str, extensions: str, *,
        executable: bool = False, container: bool = False) -> FileType:
    """Table helper: extensions are given as one space-separated string."""
    return FileType(media_type, label, tuple(extensions.split()),
                    executable=executable, container=container)


# (offset, magic bytes, FileType). Order matters: longer/more specific first.
_MAGIC: list[tuple[int, bytes, FileType]] = [
    # --- executables -------------------------------------------------------
    (0, b"MZ", _ft("application/vnd.microsoft.portable-executable", "PE/DOS executable",
                   ".exe .dll .sys .scr .ocx .cpl .msi", executable=True)),
    (0, b"\x7fELF", _ft("application/x-elf", "ELF executable",
                        ".so .elf .bin", executable=True)),
    (0, b"\xca\xfe\xba\xbe", _ft("application/x-mach-binary", "Mach-O universal binary",
                                  ".dylib", executable=True)),
    (0, b"\xcf\xfa\xed\xfe", _ft("application/x-mach-binary", "Mach-O 64-bit",
                                  ".dylib", executable=True)),
    (0, b"\xce\xfa\xed\xfe", _ft("application/x-mach-binary", "Mach-O 32-bit",
                                  ".dylib", executable=True)),
    (0, b"\xde\xc0\x17\x0b", _ft("application/x-llvm-bitcode", "LLVM bitcode", ".bc")),
    (0, b"#!", _ft("text/x-shellscript", "script with shebang",
                   ".sh .py .pl .rb .bash", executable=True)),

    # --- archives / containers --------------------------------------------
    (0, b"PK\x03\x04", _ft("application/zip", "ZIP archive",
                            ".zip .jar .apk .docx .xlsx .pptx .odt .ods .epub .ipa .war "
                            ".xpi .whl .nupkg", container=True)),
    (0, b"PK\x05\x06", _ft("application/zip", "ZIP archive (empty)", ".zip", container=True)),
    (0, b"Rar!\x1a\x07", _ft("application/vnd.rar", "RAR archive", ".rar", container=True)),
    (0, b"7z\xbc\xaf\x27\x1c", _ft("application/x-7z-compressed", "7-Zip archive",
                                    ".7z", container=True)),
    (0, b"\x1f\x8b", _ft("application/gzip", "gzip stream",
                         ".gz .tgz .svgz", container=True)),
    (0, b"BZh", _ft("application/x-bzip2", "bzip2 stream", ".bz2 .tbz2", container=True)),
    (0, b"\xfd7zXZ\x00", _ft("application/x-xz", "xz stream", ".xz .txz", container=True)),
    (0, b"\x04\x22\x4d\x18", _ft("application/x-lz4", "LZ4 stream", ".lz4", container=True)),
    (0, b"\x28\xb5\x2f\xfd", _ft("application/zstd", "zstd stream", ".zst", container=True)),
    (257, b"ustar", _ft("application/x-tar", "tar archive", ".tar", container=True)),
    (0, b"MSCF", _ft("application/vnd.ms-cab-compressed", "MS cabinet",
                     ".cab .msu", container=True)),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", _ft("application/x-ole-storage",
                                                  "OLE2 compound document",
                                                  ".doc .xls .ppt .msi .msg", container=True)),
    (0, b"ITSF", _ft("application/vnd.ms-htmlhelp", "compiled HTML help",
                     ".chm", container=True)),

    # --- documents ---------------------------------------------------------
    (0, b"%PDF-", _ft("application/pdf", "PDF document", ".pdf")),
    (0, b"{\\rtf", _ft("application/rtf", "RTF document", ".rtf .doc")),

    # --- images / media (benign-by-default, but watch for polyglots) -------
    (0, b"\x89PNG\r\n\x1a\n", _ft("image/png", "PNG image", ".png")),
    (0, b"\xff\xd8\xff", _ft("image/jpeg", "JPEG image", ".jpg .jpeg")),
    (0, b"GIF87a", _ft("image/gif", "GIF image", ".gif")),
    (0, b"GIF89a", _ft("image/gif", "GIF image", ".gif")),
    (0, b"BM", _ft("image/bmp", "BMP image", ".bmp")),
    (0, b"\x00\x00\x01\x00", _ft("image/vnd.microsoft.icon", "Windows icon", ".ico")),
    (0, b"II*\x00", _ft("image/tiff", "TIFF image", ".tif .tiff")),
    (0, b"MM\x00*", _ft("image/tiff", "TIFF image", ".tif .tiff")),
    (8, b"WEBP", _ft("image/webp", "WebP image", ".webp")),
    (4, b"ftyp", _ft("video/mp4", "ISO base media", ".mp4 .m4a .mov .m4v .heic")),
    (0, b"ID3", _ft("audio/mpeg", "MP3 with ID3", ".mp3")),
    (0, b"OggS", _ft("audio/ogg", "Ogg stream", ".ogg .opus .oga")),
    (0, b"RIFF", _ft("audio/wav", "RIFF container", ".wav .avi .webp")),
    (0, b"\x1aE\xdf\xa3", _ft("video/x-matroska", "Matroska/WebM", ".mkv .webm")),
    (0, b"fLaC", _ft("audio/flac", "FLAC audio", ".flac")),
    (0, b"\x00\x01\x00\x00\x00", _ft("font/ttf", "TrueType font", ".ttf")),
    (0, b"OTTO", _ft("font/otf", "OpenType font", ".otf")),
    (0, b"wOFF", _ft("font/woff", "WOFF font", ".woff")),
    (0, b"wOF2", _ft("font/woff2", "WOFF2 font", ".woff2")),
]

UNKNOWN = FileType("application/octet-stream", "unknown binary", ())
TEXT = _ft("text/plain", "plain text file",
           ".txt .md .csv .log .json .xml .html .htm .js .css .svg .yml .yaml .ini .conf "
           ".sql .ps1 .bat .cmd .vbs .hta .sh .py .pl .rb .php .c .h")

# Extensions that are dangerous regardless of what the bytes turn out to be,
# because the OS decides how to run them from the extension alone.
RISKY_EXTENSIONS = frozenset({
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".msi", ".msp", ".jar", ".lnk", ".cpl",
    ".reg", ".inf", ".scf", ".url", ".application", ".appref-ms", ".iso", ".img",
    ".vhd", ".vhdx", ".ace", ".apk", ".dll", ".sys", ".ocx", ".chm", ".msc", ".gadget",
})

# ZIP is the transport for a lot of formats; these tell us which one from content.
_OOXML = "application/vnd.openxmlformats-officedocument"

_ZIP_CONTENT_HINTS: list[tuple[bytes, FileType]] = [
    (b"word/", _ft(f"{_OOXML}.wordprocessingml.document", "OOXML Word document",
                   ".docx .docm .dotm", container=True)),
    (b"xl/", _ft(f"{_OOXML}.spreadsheetml.sheet", "OOXML Excel workbook",
                 ".xlsx .xlsm .xltm", container=True)),
    (b"ppt/", _ft(f"{_OOXML}.presentationml.presentation", "OOXML PowerPoint",
                  ".pptx .pptm", container=True)),
    (b"AndroidManifest.xml", _ft("application/vnd.android.package-archive", "Android package",
                                 ".apk", executable=True, container=True)),
    (b"META-INF/MANIFEST.MF", _ft("application/java-archive", "Java archive",
                                  ".jar .war .apk", executable=True, container=True)),
]


def identify(data: bytes, name: str | None = None) -> FileType:
    """Identify `data` by content. `name` is only used to refine ambiguous types."""
    for offset, magic, ftype in _MAGIC:
        if data[offset:offset + len(magic)] == magic:
            if ftype.media_type == "application/zip":
                return _refine_zip(data) or ftype
            return ftype
    if is_probably_text(data):
        return TEXT
    return UNKNOWN


def _refine_zip(data: bytes) -> FileType | None:
    """Look in the first few KB of central-directory-ish data for format hints."""
    head = data[:65536]
    for needle, ftype in _ZIP_CONTENT_HINTS:
        if needle in head:
            return ftype
    return None


def is_probably_text(data: bytes, sample: int = 8192) -> bool:
    """True if the leading bytes decode as UTF-8/UTF-16 and are mostly printable."""
    chunk = data[:sample]
    if not chunk:
        return True
    if b"\x00\x00" in chunk:
        return False
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        try:
            text = chunk.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
        if printable / max(len(text), 1) > 0.90:
            return True
    return False


# A real extension is short and alphanumeric. Requiring that avoids reading
# version numbers and timestamps as extensions -- "report.v1.2-final" and Zeek's
# own "extract-1699999999.123456-HTTP-Fabc" would otherwise each appear to carry
# a bogus extension and produce a mismatch finding on every clean file.
_EXTENSION_RE = re.compile(r"^[a-z0-9]{1,8}$")


def article_for(label: str) -> str:
    """"a" or "an" for a type label, so findings read as sentences."""
    return "an" if label[:1].lower() in "aeiou" else "a"


def describe(ftype: FileType) -> str:
    """Type label with its article, e.g. "a PNG image", "an ELF executable"."""
    return f"{article_for(ftype.label)} {ftype.label}"


def extension_of(name: str | None) -> str:
    """Lowercase final extension of `name`, or "" when it has no plausible one."""
    if not name:
        return ""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in base.strip("."):
        return ""
    candidate = base.rsplit(".", 1)[-1].lower()
    if not _EXTENSION_RE.match(candidate):
        return ""
    return "." + candidate


def extension_matches(ftype: FileType, name: str | None) -> bool:
    """Whether `name`'s extension is consistent with the identified type.

    Unknown types and extensionless names never count as a mismatch -- we only
    want to report a disagreement we are confident about.
    """
    ext = extension_of(name)
    if not ext or ftype is UNKNOWN:
        return True
    if ftype is TEXT:
        # Text is a legitimate carrier for a great many extensions.
        return ext not in {".exe", ".dll", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip"}
    return ext in ftype.extensions
