"""
Log source registry, parsing into records, and merge / filter / paginate logic.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from timestamps import ParserConfig, parse_timestamp

# Fixed high-contrast palette; cycled if there are more sources than colors.
PALETTE = [
    "#e6194b", "#3cb44b", "#4363d8", "#f58231", "#911eb4",
    "#008080", "#9a6324", "#800000", "#808000", "#000075",
    "#e6beff", "#aaffc3", "#ffd8b1", "#42d4f4", "#f032e6",
]


@dataclass
class LogRecord:
    epoch: Optional[float]   # canonical timestamp (None until inherited)
    source_id: int
    seq: int                 # line index within its source
    text: str                # original line text (without trailing newline)
    has_own_ts: bool         # True if this line carried its own timestamp
    level: str = ""          # severity: error|warn|info|debug|"" (none)


# --- Severity detection ---------------------------------------------------------

LEVEL_RANK = {"error": 4, "warn": 3, "info": 2, "debug": 1, "": 0}
LEVEL_ORDER = ["error", "warn", "info", "debug"]

# RDK logs carry a single-letter level marker like `...<I> init_wifi_hal`.
_RDK_MARK = re.compile(r"<([FEWNIDT])>")
_RDK_LEVEL = {"F": "error", "E": "error", "W": "warn",
              "N": "info", "I": "info", "D": "debug", "T": "debug"}
# Fallback: word-based detection (first/highest match wins by group order).
_WORD_RE = re.compile(
    r"\b(?P<error>FATAL|PANIC|CRITICAL|CRIT|ERROR|ERR)\b"
    r"|\b(?P<warn>WARNING|WARN)\b"
    r"|\b(?P<info>INFO|NOTICE)\b"
    r"|\b(?P<debug>DEBUG|TRACE|VERBOSE)\b", re.IGNORECASE)


def detect_level(text: str) -> str:
    """Best-effort severity for a log line (RDK `<E>`-style marker first, then
    common level words). Returns '' when nothing recognizable is present."""
    m = _RDK_MARK.search(text)
    if m:
        return _RDK_LEVEL.get(m.group(1).upper(), "")
    m = _WORD_RE.search(text)
    if m:
        return m.lastgroup or ""
    return ""


def filter_by_level(records: list["LogRecord"], min_level: str) -> list["LogRecord"]:
    """Keep records whose severity is at least ``min_level`` (e.g. 'warn' keeps
    warnings and errors). Empty/unknown level => no filtering."""
    threshold = LEVEL_RANK.get(min_level, 0)
    if threshold <= 0:
        return records
    return [r for r in records if LEVEL_RANK.get(r.level, 0) >= threshold]


def level_counts(records: list["LogRecord"]) -> dict:
    counts = {"error": 0, "warn": 0, "info": 0, "debug": 0}
    for r in records:
        if r.level in counts:
            counts[r.level] += 1
    return counts


@dataclass
class LogSource:
    source_id: int
    name: str                # display name (relative path / filename)
    path: str                # absolute path on disk
    color: str
    records: list[LogRecord] = field(default_factory=list)
    line_count: int = 0
    parsed_count: int = 0    # how many lines had their own timestamp
    is_log: bool = True      # False for non-log files (images, configs, binaries)
    category: str = "log"    # 'log' or a non-log group: conf/xml/db/pid/…


def color_for(index: int) -> str:
    return PALETTE[index % len(PALETTE)]


# --- Log vs. non-log file classification ---------------------------------------
# A device dump mixes real logs with images, configs, certs, PID/lock/flag files
# and binaries. Keep only files that actually contain logs; the rest are bundled
# aside. Known non-log extensions are excluded outright, known log extensions are
# kept, and anything else — including files with NO extension — is kept only when
# it carried at least one parseable timestamp.
_LOG_EXTS = {
    "log", "txt", "out", "err", "trace", "console", "dmesg", "syslog",
    "messages", "klog", "boot",
}
_LOG_BASENAMES = {"messages", "dmesg", "syslog", "console", "kernel"}
_NONLOG_EXTS = {
    # web / markup / structured data
    "js", "css", "html", "htm", "xml", "json", "yaml", "yml", "toml",
    "ini", "properties", "md", "rst",
    # images / media
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "tiff",
    # binaries / captures / archives
    "bin", "so", "o", "a", "ko", "exe", "dll", "class", "pyc", "pcap",
    "pcapng", "tar", "gz", "tgz", "bz2", "xz", "zip", "7z", "rar", "img",
    "dat",
    # databases
    "db", "sqlite", "sqlite3", "sql",
    # crypto / keys / certs / hashes
    "pem", "pk12", "p12", "cert", "crt", "key", "der", "csr", "cr",
    "hash", "hashvalue", "sig",
    # config / state / ipc / locks / command dumps
    "conf", "cfg", "cmd", "pid", "lock", "semid", "shmid", "state",
    "lease", "persist", "eventid", "eventsem",
}


def _real_ext(base: str) -> str:
    """Lowercased extension with trailing rotation numbers stripped:
    ``ADVSEClog.txt.0`` -> ``txt``, ``foo.log.1`` -> ``log``, ``bar`` -> ``""``."""
    b = base.lower()
    while True:
        stripped = re.sub(r"\.\d+$", "", b)
        if stripped == b:
            break
        b = stripped
    return b.rsplit(".", 1)[1] if "." in b else ""


# Known RDKB log basenames that legitimately carry NO timestamps (so the
# timestamp heuristic alone would miss them) — e.g. hostapd's wifilibhostap.
_LOG_STEM_HINTS = {
    "wifilibhostap", "libhostap", "hostapd", "hostapdlog",
    "wpa_supplicant", "wpasupplicant", "wifilog",
}


def _name_stem(base: str) -> str:
    """Basename lowercased with rotation numbers and a trailing log/text
    extension removed: ``wifilibhostap.txt.0`` -> ``wifilibhostap``."""
    b = base.lower()
    while True:
        s = re.sub(r"\.\d+$", "", b)
        if s == b:
            break
        b = s
    return re.sub(r"\.(log|txt|out|err|trace|console)$", "", b)


# Non-log file categories keyed by (rotation-stripped) extension, so configs /
# xml / databases / pid files etc. can be presented as their own separate
# groups instead of being merged into the log timeline.
_CATEGORY_BY_EXT: dict[str, str] = {}
for _cat_name, _cat_exts in [
    ("conf", ("conf", "cfg", "ini", "properties", "toml", "yaml", "yml")),
    ("xml", ("xml",)),
    ("db", ("db", "sqlite", "sqlite3", "sql")),
    ("pid", ("pid", "lock", "semid", "shmid", "state", "lease")),
    ("cert", ("pem", "pk12", "p12", "cert", "crt", "key", "der", "csr",
              "cr", "hash", "hashvalue", "sig")),
    ("image", ("png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "tiff")),
    ("web", ("js", "css", "html", "htm", "json")),
    ("capture", ("pcap", "pcapng", "bin", "so", "o", "a", "ko", "exe", "dll",
                 "class", "pyc", "dat", "img", "tar", "gz", "tgz", "bz2",
                 "xz", "zip", "7z", "rar")),
]:
    for _e in _cat_exts:
        _CATEGORY_BY_EXT[_e] = _cat_name


def file_category(name: str, is_log: bool) -> str:
    """Coarse category for grouping: 'log' for logs, else by extension
    ('conf', 'xml', 'db', 'pid', 'cert', 'image', 'web', 'capture', 'other')."""
    if is_log:
        return "log"
    return _CATEGORY_BY_EXT.get(_real_ext(name.rsplit("/", 1)[-1]), "other")


def classify_is_log(name: str, line_count: int, parsed_count: int) -> bool:
    """Whether a parsed source actually holds log data.

    Order: hidden dotfiles and empty files are not logs; known non-log
    extensions are excluded; known log extensions (and bare ``messages`` /
    ``dmesg`` style names) are included; everything else — including
    extension-less files — is included only when it carried a timestamp.
    """
    base = name.rsplit("/", 1)[-1]
    if base.startswith("."):          # .bootcomplete, .brcm_wifi_ready, certs…
        return False
    if line_count <= 0:               # empty file — nothing to show
        return False
    ext = _real_ext(base)
    if ext in _NONLOG_EXTS:
        return False
    if ext in _LOG_EXTS:
        return True
    if not ext and base.lower() in _LOG_BASENAMES:
        return True
    # Known logs that carry no timestamps (hostapd / wpa_supplicant / wifi*).
    stem = _name_stem(base)
    if stem in _LOG_STEM_HINTS or "hostap" in stem or "supplicant" in stem:
        return True
    return parsed_count > 0           # unknown / extension-less: need a timestamp


def parse_source(source: LogSource, cfg: ParserConfig,
                 max_lines: Optional[int] = None) -> None:
    """Read a source file and populate its records.

    Lines without their own recognizable timestamp inherit the most recent
    preceding timestamp within the same source (continuation handling).
    """
    records: list[LogRecord] = []
    last_epoch: Optional[float] = None
    parsed = 0
    seq = 0
    with open(source.path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            text = line.rstrip("\n").rstrip("\r")
            pt = parse_timestamp(text, cfg)
            if pt is not None:
                epoch = pt.epoch
                last_epoch = epoch
                has_own = True
                parsed += 1
            else:
                epoch = last_epoch  # inherit (may still be None at file start)
                has_own = False
            records.append(LogRecord(epoch=epoch, source_id=source.source_id,
                                     seq=seq, text=text, has_own_ts=has_own,
                                     level=detect_level(text)))
            seq += 1
            if max_lines is not None and seq >= max_lines:
                break
    source.records = records
    source.line_count = len(records)
    source.parsed_count = parsed


def _sort_key(rec: LogRecord):
    # Records with no timestamp at all (before any parsed line) sort first,
    # keeping their original position via (source_id, seq).
    epoch = rec.epoch if rec.epoch is not None else float("-inf")
    return (epoch, rec.source_id, rec.seq)


def merge_records(sources: Iterable[LogSource]) -> list[LogRecord]:
    """Stable chronological merge across sources by (epoch, source_id, seq)."""
    all_records: list[LogRecord] = []
    for src in sources:
        all_records.extend(src.records)
    all_records.sort(key=_sort_key)
    return all_records


def filter_records(records: list[LogRecord],
                   start: Optional[float],
                   end: Optional[float]) -> list[LogRecord]:
    """Inclusive timestamp-range filter on the canonical epoch value.

    Records with no timestamp (None) are excluded when any bound is set,
    since they cannot be placed in the window reliably.
    """
    if start is None and end is None:
        return records
    out: list[LogRecord] = []
    for rec in records:
        if rec.epoch is None:
            continue
        if start is not None and rec.epoch < start:
            continue
        if end is not None and rec.epoch > end:
            continue
        out.append(rec)
    return out


def filter_by_text(records: list[LogRecord], query: str) -> list[LogRecord]:
    """Case-insensitive substring filter on the line text.

    Empty query returns records unchanged. Matches line-by-line (grep-like),
    so only lines whose text contains the query are kept.
    """
    if not query:
        return records
    needle = query.casefold()
    return [rec for rec in records if needle in rec.text.casefold()]


@dataclass
class Page:
    records: list[LogRecord]
    page: int
    page_size: int
    total: int
    total_pages: int


def paginate(records: list[LogRecord], page: int,
             page_size: Optional[int]) -> Page:
    total = len(records)
    # page_size None or <= 0 means "show everything on a single page".
    if not page_size or page_size <= 0:
        return Page(records=records, page=1, page_size=(total or 1),
                    total=total, total_pages=1)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))
    start = (page - 1) * page_size
    end = start + page_size
    return Page(records=records[start:end], page=page, page_size=page_size,
                total=total, total_pages=total_pages)
