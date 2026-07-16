"""
Timestamp detection and normalization for RDKB device logs.

Supports the human-readable timestamp formats observed in RDKB logs and
converts each to a canonical float (epoch seconds, UTC) used for ordering,
merging and filtering. Kernel dmesg uptime timestamps are intentionally
NOT supported (out of scope).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone, tzinfo
from typing import Callable, NamedTuple, Optional

# Canonical display format shown in every view and accepted by the filter.
CANONICAL_DISPLAY = "%Y-%m-%d %H:%M:%S.%f"

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# Any 4-digit year outside this range is treated as implausible / no-timestamp.
_MIN_YEAR = 1970
_MAX_YEAR = 2100


class ParsedTimestamp(NamedTuple):
    epoch: float          # canonical sortable value (epoch seconds, UTC)
    format_name: str      # which format matched
    match_len: int        # number of leading chars consumed by the timestamp


def _to_epoch(
    year: int, month: int, day: int, hour: int, minute: int, second: int,
    micro: int = 0, tz: Optional[tzinfo] = timezone.utc,
) -> Optional[float]:
    if not (_MIN_YEAR <= year <= _MAX_YEAR):
        return None
    try:
        dt = datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)
    except ValueError:
        return None
    return dt.timestamp()


class _Format(NamedTuple):
    name: str
    regex: re.Pattern
    build: Callable[[re.Match, "ParserConfig"], Optional[float]]


class ParserConfig:
    """Configurable assumptions used when a format lacks explicit fields."""

    def __init__(self, assumed_year: Optional[int] = None,
                 tz: tzinfo = timezone.utc):
        self.assumed_year = assumed_year if assumed_year is not None else datetime.now(timezone.utc).year
        self.tz = tz


# --- Individual format builders -------------------------------------------------

def _b_iso8601(m: re.Match, cfg: ParserConfig) -> Optional[float]:
    # 2026-05-05T11:14:00.619Z  (Z optional, fractional optional)
    year, month, day = int(m["y"]), int(m["mo"]), int(m["d"])
    hour, minute, sec = int(m["h"]), int(m["mi"]), int(m["s"])
    micro = _frac_to_micro(m["frac"])
    return _to_epoch(year, month, day, hour, minute, sec, micro, timezone.utc)


def _b_rdk_compact(m: re.Match, cfg: ParserConfig) -> Optional[float]:
    # 260505-11:14:07.729256  ->  YYMMDD-HH:MM:SS.ffffff
    # 2-digit year pivot (POSIX %y): 69-99 -> 19xx, 00-68 -> 20xx, so that
    # boot/epoch times like 700101 map to 1970 (not 2070) and sort first.
    yy = int(m["y"])
    year = 1900 + yy if yy >= 69 else 2000 + yy
    month, day = int(m["mo"]), int(m["d"])
    hour, minute, sec = int(m["h"]), int(m["mi"]), int(m["s"])
    micro = _frac_to_micro(m["frac"])
    return _to_epoch(year, month, day, hour, minute, sec, micro, cfg.tz)


def _b_year_first(m: re.Match, cfg: ParserConfig) -> Optional[float]:
    # 1970 Jan 01 00:00:25  ->  YYYY Mon DD HH:MM:SS
    month = _MONTHS.get(m["mon"].lower())
    if month is None:
        return None
    return _to_epoch(int(m["y"]), month, int(m["d"]),
                     int(m["h"]), int(m["mi"]), int(m["s"]), 0, cfg.tz)


def _b_bracketed(m: re.Match, cfg: ParserConfig) -> Optional[float]:
    # [Thu Jan  1 00:00:39 UTC 1970]  ->  [Ddd Mon DD HH:MM:SS TZ YYYY]
    month = _MONTHS.get(m["mon"].lower())
    if month is None:
        return None
    return _to_epoch(int(m["y"]), month, int(m["d"]),
                     int(m["h"]), int(m["mi"]), int(m["s"]), 0, cfg.tz)


def _b_syslog(m: re.Match, cfg: ParserConfig) -> Optional[float]:
    # Jan  1 00:01:03  ->  Mon DD HH:MM:SS  (year assumed)
    month = _MONTHS.get(m["mon"].lower())
    if month is None:
        return None
    return _to_epoch(cfg.assumed_year, month, int(m["d"]),
                     int(m["h"]), int(m["mi"]), int(m["s"]), 0, cfg.tz)


def _b_compact_dt(m: re.Match, cfg: ParserConfig) -> Optional[float]:
    # 20260505 111501.905999  ->  YYYYMMDD HHMMSS.ffffff
    year, month, day = int(m["y"]), int(m["mo"]), int(m["d"])
    hour, minute, sec = int(m["h"]), int(m["mi"]), int(m["s"])
    micro = _frac_to_micro(m["frac"])
    return _to_epoch(year, month, day, hour, minute, sec, micro, cfg.tz)


def _frac_to_micro(frac: Optional[str]) -> int:
    if not frac:
        return 0
    # frac is digits after the dot; pad/truncate to 6 for microseconds.
    return int((frac + "000000")[:6])


# --- Ordered format table (first match wins) -----------------------------------
# NOTE: order matters. More specific / anchored patterns first.

_FORMATS: list[_Format] = [
    _Format(
        "iso8601",
        re.compile(
            r"^(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})T"
            r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
            r"(?:\.(?P<frac>\d+))?Z?"
        ),
        _b_iso8601,
    ),
    _Format(
        # 2026-05-05 11:15:18[.frac]  (ISO date, space separator)
        "iso_space",
        re.compile(
            r"^(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})[ ]"
            r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d+))?"
        ),
        _b_iso8601,
    ),
    _Format(
        # 2026.05.05 11:27:31[.frac]  (dot-separated date, e.g. stunnel)
        "iso_dot",
        re.compile(
            r"^(?P<y>\d{4})\.(?P<mo>\d{2})\.(?P<d>\d{2})[ ]"
            r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d+))?"
        ),
        _b_iso8601,
    ),
    _Format(
        # 1970-01-01:00:01:22:946410  ->  YYYY-MM-DD:HH:MM:SS[:ffffff]
        "date_colon",
        re.compile(
            r"^(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2}):"
            r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?::(?P<frac>\d+))?"
        ),
        _b_iso8601,
    ),
    _Format(
        # [2026-05-05 11:27:32]  ->  [YYYY-MM-DD HH:MM:SS]
        "bracketed_iso",
        re.compile(
            r"^\[(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})[ T]"
            r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d+))?\]"
        ),
        _b_iso8601,
    ),
    _Format(
        "compact_dt",
        re.compile(
            r"^(?P<y>\d{4})(?P<mo>\d{2})(?P<d>\d{2})\s+"
            r"(?P<h>\d{2})(?P<mi>\d{2})(?P<s>\d{2})(?:\.(?P<frac>\d+))?"
        ),
        _b_compact_dt,
    ),
    _Format(
        # 2026-May-05_11-14-30  ->  YYYY-Mon-DD_HH-MM-SS (telemetry)
        "telemetry",
        re.compile(
            r"^(?P<y>\d{4})-(?P<mon>[A-Za-z]{3})-(?P<d>\d{2})_"
            r"(?P<h>\d{2})-(?P<mi>\d{2})-(?P<s>\d{2})"
        ),
        _b_year_first,
    ),
    _Format(
        "year_first",
        re.compile(
            r"^(?P<y>\d{4})\s+(?P<mon>[A-Za-z]{3})\s+(?P<d>\d{1,2})\s+"
            r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
        ),
        _b_year_first,
    ),
    _Format(
        "rdk_compact",
        re.compile(
            r"^(?P<y>\d{2})(?P<mo>\d{2})(?P<d>\d{2})-"
            r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d+))?"
        ),
        _b_rdk_compact,
    ),
    _Format(
        # [Thu Jan  1 00:00:39 UTC 1970] or [Thu Jan  1 00:00:44 1970] (TZ optional)
        "bracketed",
        re.compile(
            r"^\[[A-Za-z]{3}\s+(?P<mon>[A-Za-z]{3})\s+(?P<d>\d{1,2})\s+"
            r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})\s+"
            r"(?:[A-Za-z]+\s+)?(?P<y>\d{4})\]"
        ),
        _b_bracketed,
    ),
    _Format(
        # Tue May  5 11:14:12 2026  or  Tue May  5 11:15:14 UTC 2026 (ctime, TZ optional)
        "ctime",
        re.compile(
            r"^[A-Za-z]{3}\s+(?P<mon>[A-Za-z]{3})\s+(?P<d>\d{1,2})\s+"
            r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})\s+"
            r"(?:[A-Za-z]+\s+)?(?P<y>\d{4})"
        ),
        _b_year_first,
    ),
    _Format(
        "syslog",
        re.compile(
            r"^(?P<mon>[A-Za-z]{3})\s+(?P<d>\d{1,2})\s+"
            r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
        ),
        _b_syslog,
    ),
]

# A leading bracketed tag such as "[OneWifi] " that precedes the timestamp in
# some logs (timestamp is not in the first column).
_PREFIX_RE = re.compile(r"\[[^\]]*\]\s+")


def parse_timestamp(line: str, cfg: ParserConfig) -> Optional[ParsedTimestamp]:
    """Try each known format; return the first plausible match.

    The timestamp is matched at the start of the line, or — if the line begins
    with a bracketed tag like ``[OneWifi] `` — immediately after that tag.
    Returns None when no format matches or the matched fields are implausible
    (e.g. a pre-time-sync token such as ``-300101-...`` or a bare number).
    """
    if not line:
        return None
    offsets = [0]
    pm = _PREFIX_RE.match(line)
    if pm is not None and pm.end() > 0:
        offsets.append(pm.end())
    for off in offsets:
        seg = line if off == 0 else line[off:]
        for fmt in _FORMATS:
            m = fmt.regex.match(seg)
            if not m:
                continue
            epoch = fmt.build(m, cfg)
            if epoch is None:
                # Matched the shape but values were implausible: keep trying.
                continue
            return ParsedTimestamp(epoch=epoch, format_name=fmt.name,
                                   match_len=off + m.end())
    return None


def format_canonical(epoch: float) -> str:
    """Render a canonical epoch value in the canonical display format (UTC)."""
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    # Trim microseconds to milliseconds for compact display.
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def parse_filter_bound(text: str) -> Optional[float]:
    """Parse a user-entered filter bound in the canonical display format.

    Accepts, flexibly:
      YYYY-MM-DD HH:MM:SS.mmm | YYYY-MM-DD HH:MM:SS | YYYY-MM-DD HH:MM
      YYYY-MM-DDTHH:MM:SS(.fff)(Z)
    Returns epoch seconds (UTC) or None if empty/unparseable.
    """
    if not text:
        return None
    text = text.strip()
    if not text:
        return None
    candidates = (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    )
    cleaned = text.rstrip("Z")
    for fmt in candidates:
        try:
            dt = datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return None
