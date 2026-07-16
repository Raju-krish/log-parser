"""
Per-user investigation bookmarks: pinned log lines with notes.

Each bookmark records enough to redisplay and jump back to a line
(source basename, line index, timestamp, a text snippet) plus the user's note
and the workspace context it was taken in. Stored per user as a small JSON file
under the data root, so notes survive across sessions and logins.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _user_slug(name: str) -> str:
    slug = _SLUG_RE.sub("-", (name or "").strip()).strip("-._")
    return slug[:80] or "user"


class BookmarkStore:
    def __init__(self, data_root: str):
        self.data_root = os.path.realpath(data_root)
        self._lock = threading.RLock()

    def _path(self, username: str) -> str:
        udir = os.path.join(self.data_root, _user_slug(username))
        os.makedirs(udir, exist_ok=True)
        return os.path.join(udir, "bookmarks.json")

    def _load(self, username: str) -> list:
        path = self._path(username)
        if not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []
        items = data.get("bookmarks") if isinstance(data, dict) else None
        return items if isinstance(items, list) else []

    def _save(self, username: str, items: list) -> None:
        with open(self._path(username), "w", encoding="utf-8") as fh:
            json.dump({"bookmarks": items}, fh, indent=2)

    def list(self, username: str, scope=None) -> list:
        with self._lock:
            items = self._load(username)
        if scope is not None:
            items = [b for b in items if b.get("scope", "") == scope]
        items.sort(key=lambda b: b.get("created_at", ""), reverse=True)
        return items

    def keys(self, username: str, scope=None) -> set:
        """Set of (source, seq) identifying pinned lines — including every line
        of a range bookmark — for marking the view."""
        out = set()
        for b in self.list(username, scope):
            try:
                out.add((b.get("source", ""), int(b.get("seq", -1))))
            except (TypeError, ValueError):
                pass
            for m in (b.get("members") or []):
                try:
                    out.add((m.get("source", ""), int(m.get("seq", -1))))
                except (TypeError, ValueError):
                    pass
        return out

    def add(self, username: str, bm: dict) -> dict:
        """Add a bookmark, or update the note if this exact line is already
        pinned within the same scope (log folder / workspace).

        Identity includes the unique ``srcid`` so two different sources that
        share a basename/display name (e.g. several capture sessions' own
        ``wifiCtrl.txt``) never collapse into one bookmark. Legacy notes with
        no ``srcid`` (``None``) still upsert against each other by
        (scope, source, seq)."""
        with self._lock:
            items = self._load(username)
            scope = bm.get("scope", "")
            new_srcid = bm.get("srcid")
            try:
                seq_val = int(bm.get("seq", -1))
            except (TypeError, ValueError):
                seq_val = -1
            key = ((scope, new_srcid, bm.get("source", ""), seq_val)
                   if seq_val >= 0 else None)
            if key is not None:
                for b in items:
                    try:
                        bkey = (b.get("scope", ""), b.get("srcid"),
                                b.get("source", ""), int(b.get("seq", -1)))
                    except (TypeError, ValueError):
                        continue
                    if bkey == key:
                        b["note"] = bm.get("note", b.get("note", ""))
                        b["text"] = bm.get("text", b.get("text", ""))
                        if "srcid" in bm:
                            b["srcid"] = bm["srcid"]
                        if "members" in bm:
                            b["members"] = bm["members"]
                        self._save(username, items)
                        return b
            rec = dict(bm)
            rec["id"] = uuid.uuid4().hex
            rec["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            items.append(rec)
            self._save(username, items)
            return rec

    def get_by_line(self, username: str, source: str, seq: int) -> dict | None:
        for b in self.list(username):
            try:
                if b.get("source", "") == source and int(b.get("seq", -1)) == seq:
                    return b
            except (TypeError, ValueError):
                continue
        return None

    def update(self, username: str, bid: str, note: str) -> dict | None:
        with self._lock:
            items = self._load(username)
            for b in items:
                if b.get("id") == bid:
                    b["note"] = note
                    self._save(username, items)
                    return b
            return None

    def delete(self, username: str, bid: str) -> None:
        with self._lock:
            items = self._load(username)
            kept = [b for b in items if b.get("id") != bid]
            if len(kept) != len(items):
                self._save(username, kept)

    def delete_by_line(self, username: str, source: str, seq: int,
                       scope=None, srcid=None) -> bool:
        with self._lock:
            items = self._load(username)
            kept = []
            removed = False
            for b in items:
                try:
                    same = (b.get("source", "") == source
                            and int(b.get("seq", -1)) == seq)
                except (TypeError, ValueError):
                    same = False
                if same and scope is not None and b.get("scope", "") != scope:
                    same = False
                # When a unique source_id is supplied, only remove the matching
                # source so sibling sessions sharing a basename are left intact.
                if same and srcid is not None and b.get("srcid") != srcid:
                    same = False
                if same:
                    removed = True
                else:
                    kept.append(b)
            if removed:
                self._save(username, kept)
            return removed

    def rescope(self, username: str, old_scope: str, new_scope: str) -> int:
        """Move a user's bookmarks from ``old_scope`` to ``new_scope``.

        Used when a fresh upload's notes (keyed by an ``up:<hash>`` scope) must
        follow the logs into a newly saved workspace (``ws:<name>``) so they are
        not orphaned when the workspace is later reloaded. A bookmark whose line
        is already pinned in the destination scope is dropped as a duplicate.
        Returns the number of bookmarks moved.
        """
        if not old_scope or old_scope == new_scope:
            return 0
        with self._lock:
            items = self._load(username)

            def ident(b):
                try:
                    seq = int(b.get("seq", -1))
                except (TypeError, ValueError):
                    seq = -1
                return (b.get("srcid"), b.get("source", ""), seq)

            existing = {ident(b) for b in items if b.get("scope", "") == new_scope}
            kept = []
            moved = 0
            for b in items:
                if b.get("scope", "") == old_scope:
                    if ident(b) in existing:
                        continue  # destination already pins this line — drop dup
                    b["scope"] = new_scope
                    existing.add(ident(b))
                    moved += 1
                kept.append(b)
            if moved or len(kept) != len(items):
                self._save(username, kept)
            return moved
