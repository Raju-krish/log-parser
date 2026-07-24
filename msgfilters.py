"""
Per-user saved "message contains" filters: named boolean query expressions the
user reuses often (e.g. a "Client connectivity" filter =
``received auth || send auth || device associated``).

Each filter is a small record ``{id, label, expr}`` where ``expr`` is a raw
query string for the "Message contains" box (querylang syntax: ``&&`` / ``||`` /
parentheses / quoted or bare terms). Stored per user as JSON under the data
root, alongside the user's presets / bookmarks / settings, so saved filters
follow the account across sessions and logins. A couple of ready-to-use example
filters are seeded the first time a user has none; they can be renamed, edited,
or removed like any other filter.
"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")
# Collapse any run of whitespace (incl. newlines/tabs) to a single space so a
# saved filter is always one logical line, like the box that consumes it.
_WS_RE = re.compile(r"\s+")
# Strip ASCII/Unicode control characters that could corrupt the JSON store or
# the rendered HTML attribute; the expression is otherwise free text.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")

MAX_LABEL = 60
MAX_EXPR = 500

# Seeded for every new user as ready-to-use examples; each is editable and
# deletable like any user filter.
DEFAULT_FILTERS = [
    {"id": "connectivity", "label": "Client connectivity",
     "expr": "received auth || send auth || device associated"},
    {"id": "gotip", "label": "Client got IP",
     "expr": "IP Address || IP from DNSMASQ"},
]


def _user_slug(name: str) -> str:
    slug = _SLUG_RE.sub("-", (name or "").strip()).strip("-._")
    return slug[:80] or "user"


def clean_expr(expr) -> str:
    """Normalize a filter expression: coerce to str, strip control chars, fold
    whitespace to single spaces, trim, and cap length. Non-strings become ''."""
    if not isinstance(expr, str):
        return ""
    v = _CTRL_RE.sub(" ", expr)
    v = _WS_RE.sub(" ", v).strip()
    return v[:MAX_EXPR]


class MessageFilterStore:
    """Per-user saved 'message contains' filters, persisted as JSON."""

    def __init__(self, data_root: str):
        self.data_root = os.path.realpath(data_root)
        self._lock = threading.RLock()

    def _path(self, username: str) -> str:
        udir = os.path.join(self.data_root, _user_slug(username))
        os.makedirs(udir, exist_ok=True)
        return os.path.join(udir, "msgfilters.json")

    def _load_raw(self, username: str):
        path = self._path(username)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None
        items = data.get("filters") if isinstance(data, dict) else None
        return items if isinstance(items, list) else None

    def _save(self, username: str, items: list) -> None:
        with open(self._path(username), "w", encoding="utf-8") as fh:
            json.dump({"filters": items}, fh, indent=2)

    @staticmethod
    def _norm(item) -> dict | None:
        if not isinstance(item, dict):
            return None
        fid = str(item.get("id") or "").strip()
        label = str(item.get("label") or "").strip()
        expr = clean_expr(item.get("expr"))
        if not fid or not label or not expr:
            return None
        return {"id": fid, "label": label[:MAX_LABEL], "expr": expr}

    def list(self, username: str) -> list:
        """Return the user's filters, seeding the defaults on first use."""
        with self._lock:
            raw = self._load_raw(username)
            if raw is None:
                seeded = [dict(f) for f in DEFAULT_FILTERS]
                self._save(username, seeded)
                return [dict(f) for f in seeded]
            out: list = []
            seen = set()
            for it in raw:
                n = self._norm(it)
                if n and n["id"] not in seen:
                    seen.add(n["id"])
                    out.append(n)
            return out

    def get(self, username: str, fid: str) -> dict | None:
        for f in self.list(username):
            if f["id"] == fid:
                return f
        return None

    def add(self, username: str, label: str, expr) -> dict:
        label = (label or "").strip()
        expr = clean_expr(expr)
        if not label:
            raise ValueError("A filter name is required.")
        if not expr:
            raise ValueError("Enter the filter expression to save.")
        with self._lock:
            items = self.list(username)
            existing = {f["id"] for f in items}
            fid = uuid.uuid4().hex[:8]
            while fid in existing:
                fid = uuid.uuid4().hex[:8]
            rec = {"id": fid, "label": label[:MAX_LABEL], "expr": expr}
            items.append(rec)
            self._save(username, items)
            return rec

    def update(self, username: str, fid: str, label: str, expr) -> dict:
        label = (label or "").strip()
        expr = clean_expr(expr)
        if not label:
            raise ValueError("A filter name is required.")
        if not expr:
            raise ValueError("Enter the filter expression to save.")
        with self._lock:
            items = self.list(username)
            for f in items:
                if f["id"] == fid:
                    f["label"] = label[:MAX_LABEL]
                    f["expr"] = expr
                    self._save(username, items)
                    return f
            raise KeyError(fid)

    def delete(self, username: str, fid: str) -> bool:
        with self._lock:
            items = self.list(username)
            new = [f for f in items if f["id"] != fid]
            if len(new) == len(items):
                return False
            self._save(username, new)
            return True
