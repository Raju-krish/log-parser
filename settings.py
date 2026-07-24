"""
Per-user UI settings (theme, font) persisted server-side so a user's chosen
appearance follows their account across browsers and private windows, instead
of living only in one browser's localStorage.

Stored per user as a small JSON file under the data root, alongside the user's
bookmarks / notepad / presets.
"""

from __future__ import annotations

import json
import os
import re
import threading

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")
# Setting values are opaque short ids (theme/font ids) rendered into an HTML
# attribute, so keep them to a safe character set.
_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def _user_slug(name: str) -> str:
    slug = _SLUG_RE.sub("-", (name or "").strip()).strip("-._")
    return slug[:80] or "user"


class SettingsStore:
    """Per-user UI settings, persisted as JSON under the data root."""

    ALLOWED = ("theme", "font")

    def __init__(self, data_root: str):
        self.data_root = os.path.realpath(data_root)
        self._lock = threading.RLock()

    def _path(self, username: str) -> str:
        udir = os.path.join(self.data_root, _user_slug(username))
        os.makedirs(udir, exist_ok=True)
        return os.path.join(udir, "settings.json")

    def _load(self, username: str) -> dict:
        path = self._path(username)
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def get(self, username: str) -> dict:
        """Return the user's valid settings as {key: value}."""
        raw = self._load(username)
        out = {}
        for key in self.ALLOWED:
            val = raw.get(key)
            if isinstance(val, str) and _VALUE_RE.match(val):
                out[key] = val
        return out

    def set(self, username: str, key: str, value: str) -> bool:
        """Persist one setting. Returns False for unknown keys / invalid values."""
        if key not in self.ALLOWED:
            return False
        value = (value or "").strip()
        if not _VALUE_RE.match(value):
            return False
        with self._lock:
            data = self._load(username)
            data[key] = value
            # Drop anything that isn't a recognized, valid setting.
            clean = {k: v for k, v in data.items()
                     if k in self.ALLOWED and isinstance(v, str) and _VALUE_RE.match(v)}
            with open(self._path(username), "w", encoding="utf-8") as fh:
                json.dump(clean, fh, indent=2)
        return True
