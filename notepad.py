"""
Per-user, per-workspace freeform notepad.

A single block of scratch text stored per (user, scope), where ``scope`` is the
same identity bookmarks use (``ws:<name>`` for a saved workspace, ``up:<hash>``
for a fresh upload). Persisted as a small JSON file under the data root so the
pad survives sessions and logins, and a shared workspace shares the owner's pad.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")

# Cap a single pad so a runaway paste can't bloat the store (~100 KB of text).
_MAX_LEN = 100_000


def _user_slug(name: str) -> str:
    slug = _SLUG_RE.sub("-", (name or "").strip()).strip("-._")
    return slug[:80] or "user"


class NotepadStore:
    def __init__(self, data_root: str):
        self.data_root = os.path.realpath(data_root)
        self._lock = threading.RLock()

    def _path(self, username: str) -> str:
        udir = os.path.join(self.data_root, _user_slug(username))
        os.makedirs(udir, exist_ok=True)
        return os.path.join(udir, "notepad.json")

    def _load(self, username: str) -> dict:
        path = self._path(username)
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}
        pads = data.get("pads") if isinstance(data, dict) else None
        return pads if isinstance(pads, dict) else {}

    def _save(self, username: str, pads: dict) -> None:
        path = self._path(username)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"pads": pads}, fh, indent=2)
        os.replace(tmp, path)

    @staticmethod
    def _text_of(entry) -> str:
        """Text from a stored entry, tolerating a legacy bare-string value."""
        if isinstance(entry, dict):
            return entry.get("text", "") or ""
        if isinstance(entry, str):
            return entry
        return ""

    def get(self, username: str, scope: str) -> dict:
        if not scope:
            return {"text": "", "updated_at": ""}
        with self._lock:
            pads = self._load(username)
        entry = pads.get(scope)
        if isinstance(entry, dict):
            return {"text": entry.get("text", "") or "",
                    "updated_at": entry.get("updated_at", "") or ""}
        return {"text": self._text_of(entry), "updated_at": ""}

    def set(self, username: str, scope: str, text: str) -> dict:
        if not scope:
            return {"text": "", "updated_at": ""}
        text = (text or "")[:_MAX_LEN]
        with self._lock:
            pads = self._load(username)
            if text.strip():
                entry = {"text": text,
                         "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
                pads[scope] = entry
            else:
                # Empty pad — drop the key so the store stays tidy.
                entry = {"text": "", "updated_at": ""}
                pads.pop(scope, None)
            self._save(username, pads)
        return entry

    def rescope(self, username: str, old_scope: str, new_scope: str) -> bool:
        """Move a fresh upload's pad into a newly saved workspace's scope.

        Mirrors ``BookmarkStore.rescope`` so a pad written before saving follows
        the logs into the workspace. If the destination already has text, the
        two are merged (destination first) rather than lost. Returns True if
        anything moved.
        """
        if not old_scope or old_scope == new_scope:
            return False
        with self._lock:
            pads = self._load(username)
            src_text = self._text_of(pads.get(old_scope))
            if not src_text.strip():
                if pads.pop(old_scope, None) is not None:
                    self._save(username, pads)
                return False
            dst_text = self._text_of(pads.get(new_scope))
            if dst_text.strip():
                merged = dst_text.rstrip() + "\n\n" + src_text.lstrip()
            else:
                merged = src_text
            pads[new_scope] = {"text": merged[:_MAX_LEN],
                               "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
            pads.pop(old_scope, None)
            self._save(username, pads)
            return True
