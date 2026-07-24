"""
Per-user source presets: named sets of log-file name patterns that select a
subset of the uploaded sources in one click (e.g. a "WiFi Analysis" preset that
picks wifihal, wifimgr, messages, …).

Stored per user as a small JSON file under the data root so a user's presets
survive across sessions and logins. A default WiFi preset is seeded the first
time a user has no presets of their own; it can be renamed, edited, or removed
like any other preset.
"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")
_SPLIT_RE = re.compile(r"[\s,;]+")

MAX_LABEL = 60
MAX_STEMS = 200

# Seeded for every new user; editable and deletable like any user preset. File
# names are matched by normalized stem on the app side, so extensions/rotation
# suffixes here are optional.
DEFAULT_PRESETS = [
    {
        "id": "wifi",
        "label": "WiFi Analysis",
        "stems": [
            "wifidmcli", "wifihal", "wifimgr", "wifimon",
            "wifiwebconfig", "wifictrl", "messages",
        ],
    },
]


def _user_slug(name: str) -> str:
    slug = _SLUG_RE.sub("-", (name or "").strip()).strip("-._")
    return slug[:80] or "user"


def clean_stems(stems) -> list:
    """Normalize file-name stems: split a string on whitespace/comma/semicolon,
    lowercase, strip, de-duplicate (order preserved). Non-strings are dropped."""
    if isinstance(stems, str):
        stems = _SPLIT_RE.split(stems.strip())
    out: list = []
    seen = set()
    for s in stems or []:
        if not isinstance(s, str):
            continue
        v = s.strip().lower()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
        if len(out) >= MAX_STEMS:
            break
    return out


class PresetStore:
    """Per-user named source presets, persisted as JSON under the data root."""

    def __init__(self, data_root: str):
        self.data_root = os.path.realpath(data_root)
        self._lock = threading.RLock()

    def _path(self, username: str) -> str:
        udir = os.path.join(self.data_root, _user_slug(username))
        os.makedirs(udir, exist_ok=True)
        return os.path.join(udir, "presets.json")

    def _load_raw(self, username: str):
        path = self._path(username)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None
        items = data.get("presets") if isinstance(data, dict) else None
        return items if isinstance(items, list) else None

    def _save(self, username: str, items: list) -> None:
        with open(self._path(username), "w", encoding="utf-8") as fh:
            json.dump({"presets": items}, fh, indent=2)

    @staticmethod
    def _norm(item) -> dict | None:
        if not isinstance(item, dict):
            return None
        pid = str(item.get("id") or "").strip()
        label = str(item.get("label") or "").strip()
        stems = clean_stems(item.get("stems"))
        if not pid or not label or not stems:
            return None
        return {"id": pid, "label": label[:MAX_LABEL], "stems": stems}

    def list(self, username: str) -> list:
        """Return the user's presets, seeding the defaults on first use."""
        with self._lock:
            raw = self._load_raw(username)
            if raw is None:
                seeded = [dict(p) for p in DEFAULT_PRESETS]
                self._save(username, seeded)
                return [dict(p) for p in seeded]
            out: list = []
            seen = set()
            for it in raw:
                n = self._norm(it)
                if n and n["id"] not in seen:
                    seen.add(n["id"])
                    out.append(n)
            return out

    def get(self, username: str, pid: str) -> dict | None:
        for p in self.list(username):
            if p["id"] == pid:
                return p
        return None

    def add(self, username: str, label: str, stems) -> dict:
        label = (label or "").strip()
        stems = clean_stems(stems)
        if not label:
            raise ValueError("A preset name is required.")
        if not stems:
            raise ValueError("List at least one file name for the preset.")
        with self._lock:
            items = self.list(username)
            existing = {p["id"] for p in items}
            pid = uuid.uuid4().hex[:8]
            while pid in existing:
                pid = uuid.uuid4().hex[:8]
            rec = {"id": pid, "label": label[:MAX_LABEL], "stems": stems}
            items.append(rec)
            self._save(username, items)
            return rec

    def update(self, username: str, pid: str, label: str, stems) -> dict:
        label = (label or "").strip()
        stems = clean_stems(stems)
        if not label:
            raise ValueError("A preset name is required.")
        if not stems:
            raise ValueError("List at least one file name for the preset.")
        with self._lock:
            items = self.list(username)
            for p in items:
                if p["id"] == pid:
                    p["label"] = label[:MAX_LABEL]
                    p["stems"] = stems
                    self._save(username, items)
                    return p
            raise KeyError(pid)

    def delete(self, username: str, pid: str) -> bool:
        with self._lock:
            items = self.list(username)
            new = [p for p in items if p["id"] != pid]
            if len(new) == len(items):
                return False
            self._save(username, new)
            return True
