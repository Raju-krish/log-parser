"""
Per-user persistent workspace storage for the Log Parser.

A *workspace* is a named, saved copy of a parsed upload's raw source files plus
a small ``manifest.json``. Layout::

    DATA_ROOT/<user-slug>/<workspace-slug>/
        manifest.json
        sources/000__messages.txt
        sources/001__wifiHal.txt
        ...

Everything is scoped to the acting user (identity comes from the session, never
from a request parameter). Names are slugified and every resolved path is
verified to stay within the user's directory, defending against path traversal.
A configurable per-user quota (default 500 MB) is enforced at save time.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")

# Hard ceiling on any per-user quota override so an admin typo can't hand out an
# absurd amount of space.
_MAX_QUOTA_BYTES = 2 * 1024 * 1024 * 1024 * 1024  # 2 TB


class WorkspaceError(Exception):
    """Raised for invalid names, quota violations, or missing workspaces."""


def slugify(name: str) -> str:
    """Reduce an arbitrary name to a safe path segment (or '' if nothing safe)."""
    slug = _SLUG_RE.sub("-", (name or "").strip()).strip("-._")
    return slug[:80]


def human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num} B"


class WorkspaceStore:
    def __init__(self, data_root: str, quota_bytes: int):
        self.data_root = os.path.realpath(data_root)
        self.quota_bytes = quota_bytes
        self._lock = threading.RLock()

    @staticmethod
    def _sanitize_shares(shares) -> list:
        """Coerce a stored/incoming share list into a clean, de-duplicated list
        of non-empty usernames (order preserved)."""
        out: list[str] = []
        seen = set()
        if isinstance(shares, list):
            for s in shares:
                if isinstance(s, str):
                    name = s.strip()
                    if name and name not in seen:
                        seen.add(name)
                        out.append(name)
        return out

    # --- path helpers (all containment-checked) ---------------------------------

    def _user_dir(self, username: str) -> str:
        slug = slugify(username)
        if not slug:
            raise WorkspaceError("Invalid user identity")
        path = os.path.realpath(os.path.join(self.data_root, slug))
        if path != self.data_root and not path.startswith(self.data_root + os.sep):
            raise WorkspaceError("Resolved user path escapes the data root")
        return path

    def _ws_dir(self, username: str, slug: str) -> str:
        if not slug:
            raise WorkspaceError("Invalid workspace name")
        udir = self._user_dir(username)
        path = os.path.realpath(os.path.join(udir, slug))
        if path != udir and not path.startswith(udir + os.sep):
            raise WorkspaceError("Resolved workspace path escapes the user directory")
        return path

    @staticmethod
    def _dir_size(path: str) -> int:
        total = 0
        for root, _dirs, files in os.walk(path):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                except OSError:
                    pass
        return total

    # --- queries ----------------------------------------------------------------

    def usage(self, username: str) -> int:
        udir = self._user_dir(username)
        return self._dir_size(udir) if os.path.isdir(udir) else 0

    # --- per-user quota overrides (admin-adjustable) ----------------------------
    # Overrides live in a single JSON file at the data-root ({user: bytes}); the
    # global default applies to anyone without an entry. Changing a quota only
    # rewrites this file — it never reads, moves, or deletes stored workspaces.

    def _quota_path(self) -> str:
        return os.path.join(self.data_root, "quotas.json")

    def _load_quotas(self) -> dict:
        path = self._quota_path()
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}
        q = data.get("quotas") if isinstance(data, dict) else None
        return q if isinstance(q, dict) else {}

    def _save_quotas(self, quotas: dict) -> None:
        os.makedirs(self.data_root, exist_ok=True)
        path = self._quota_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"quotas": quotas}, fh, indent=2)
        os.replace(tmp, path)

    def quota(self, username: str) -> int:
        """Effective quota for ``username`` — a per-user override when set,
        otherwise the global default."""
        with self._lock:
            quotas = self._load_quotas()
        try:
            v = int(quotas.get(username))
            if v > 0:
                return v
        except (TypeError, ValueError):
            pass
        return self.quota_bytes

    def set_quota(self, username: str, total_bytes: int) -> int:
        """Set an absolute quota for ``username`` — may be above OR below the
        global default. A value of 0 or less clears the override, restoring the
        default. Only rewrites quotas.json — stored workspaces and their data are
        never read, moved, or deleted."""
        if not username:
            raise WorkspaceError("Invalid user identity")
        total = min(int(total_bytes), _MAX_QUOTA_BYTES)
        with self._lock:
            quotas = self._load_quotas()
            if total <= 0:
                quotas.pop(username, None)   # reset to the global default
            else:
                quotas[username] = total
            self._save_quotas(quotas)
        return self.quota(username)

    def add_quota(self, username: str, extra_bytes: int) -> int:
        """Grant ``extra_bytes`` more space on top of the user's current quota.
        Additive only — existing logs and data are left intact."""
        return self.set_quota(username, self.quota(username) + int(extra_bytes))

    def get(self, username: str, slug: str) -> dict | None:
        wdir = self._ws_dir(username, slug)
        manifest = os.path.join(wdir, "manifest.json")
        if not os.path.isfile(manifest):
            return None
        try:
            with open(manifest, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkspaceError(f"Corrupt workspace manifest: {exc}") from exc
        meta["slug"] = slug
        meta["size"] = self._dir_size(wdir)
        meta["shared_with"] = self._sanitize_shares(meta.get("shared_with"))
        return meta

    def exists(self, username: str, slug: str) -> bool:
        return os.path.isfile(os.path.join(self._ws_dir(username, slug), "manifest.json"))

    def list_workspaces(self, username: str) -> list[dict]:
        udir = self._user_dir(username)
        out: list[dict] = []
        if not os.path.isdir(udir):
            return out
        for name in os.listdir(udir):
            wdir = os.path.join(udir, name)
            if not os.path.isfile(os.path.join(wdir, "manifest.json")):
                continue
            try:
                meta = self.get(username, name)
            except WorkspaceError:
                continue
            if meta is not None:
                out.append(meta)
        out.sort(key=lambda m: m.get("created_at", ""), reverse=True)
        return out

    # --- mutations --------------------------------------------------------------

    def save(self, username: str, name: str,
             sources: list[tuple[str, str]], overwrite: bool = False) -> str:
        """Persist ``sources`` (list of ``(display_name, abs_path)``) under ``name``.

        Enforces the per-user quota. Raises ``WorkspaceError`` on invalid name,
        an existing name without ``overwrite``, or quota violation.
        """
        slug = slugify(name)
        if not slug:
            raise WorkspaceError("Please enter a workspace name using letters or digits.")
        wdir = self._ws_dir(username, slug)
        if self.exists(username, slug) and not overwrite:
            raise WorkspaceError(
                f"A workspace named '{slug}' already exists — choose another name "
                f"or tick 'Replace if exists'.")

        # Preserve an existing workspace's share list across an overwrite so
        # re-saving the same name doesn't silently revoke everyone's access.
        existing_shares: list = []
        if self.exists(username, slug):
            try:
                prev = self.get(username, slug)
            except WorkspaceError:
                prev = None
            if prev:
                existing_shares = self._sanitize_shares(prev.get("shared_with"))

        incoming = 0
        for _disp, path in sources:
            try:
                incoming += os.path.getsize(path)
            except OSError:
                pass
        used = self.usage(username)
        existing = self._dir_size(wdir) if os.path.isdir(wdir) else 0
        quota = self.quota(username)
        if used - existing + incoming > quota:
            raise WorkspaceError(
                f"Saving would exceed your {human_size(quota)} quota "
                f"(in use {human_size(used - existing)}, this workspace "
                f"{human_size(incoming)}). Delete a workspace and try again.")

        tmp = wdir + ".tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        src_dir = os.path.join(tmp, "sources")
        os.makedirs(src_dir, exist_ok=True)
        manifest_sources = []
        try:
            for i, (disp, path) in enumerate(sources):
                base = slugify(os.path.basename(disp)) or f"source-{i}"
                fname = f"{i:03d}__{base}"
                dest = os.path.join(src_dir, fname)
                shutil.copyfile(path, dest)
                manifest_sources.append(
                    {"name": disp, "file": fname, "size": os.path.getsize(dest)})
            manifest = {
                "name": name.strip(),
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "source_count": len(manifest_sources),
                "sources": manifest_sources,
                "shared_with": existing_shares,
            }
            with open(os.path.join(tmp, "manifest.json"), "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, indent=2)
        except OSError as exc:
            shutil.rmtree(tmp, ignore_errors=True)
            raise WorkspaceError(f"Could not write workspace: {exc}") from exc

        # Swap the freshly written temp dir into place atomically.
        if os.path.isdir(wdir):
            shutil.rmtree(wdir, ignore_errors=True)
        os.replace(tmp, wdir)
        return slug

    def materialize(self, username: str, slug: str, dest_dir: str) -> list[tuple[str, str]]:
        """Copy a saved workspace's raw sources into ``dest_dir``.

        Returns ``(display_name, copied_path)`` pairs for registration. Stored
        file names are containment-checked before use.
        """
        meta = self.get(username, slug)
        if meta is None:
            raise WorkspaceError("Workspace not found.")
        src_dir = os.path.realpath(os.path.join(self._ws_dir(username, slug), "sources"))
        os.makedirs(dest_dir, exist_ok=True)
        pairs: list[tuple[str, str]] = []
        for entry in meta.get("sources", []):
            fname = entry.get("file")
            disp = entry.get("name") or fname
            if not fname:
                continue
            stored = os.path.realpath(os.path.join(src_dir, fname))
            if stored != src_dir and not stored.startswith(src_dir + os.sep):
                continue  # refuse anything that escapes the sources dir
            if not os.path.isfile(stored):
                continue
            out = os.path.join(dest_dir, os.path.basename(fname))
            shutil.copyfile(stored, out)
            pairs.append((disp, out))
        if not pairs:
            raise WorkspaceError("No source files found in this workspace.")
        return pairs

    def delete(self, username: str, slug: str) -> None:
        wdir = self._ws_dir(username, slug)
        if not os.path.isdir(wdir):
            raise WorkspaceError("Workspace not found.")
        shutil.rmtree(wdir, ignore_errors=True)

    def rename(self, username: str, slug: str, new_name: str) -> str:
        """Rename a saved workspace's display name, moving its directory when the
        new name slugifies differently. Returns the new slug. Owner only.
        """
        new_slug = slugify(new_name)
        if not new_slug:
            raise WorkspaceError("Please enter a workspace name using letters or digits.")
        with self._lock:
            wdir = self._ws_dir(username, slug)
            mpath = os.path.join(wdir, "manifest.json")
            if not os.path.isfile(mpath):
                raise WorkspaceError("Workspace not found.")
            # A different target slug must not clobber another workspace.
            # normcase avoids a false collision on case-insensitive filesystems
            # (Windows) when only the name's casing changed.
            if os.path.normcase(new_slug) != os.path.normcase(slug) \
                    and self.exists(username, new_slug):
                raise WorkspaceError(
                    f"A workspace named '{new_slug}' already exists \u2014 choose another name.")
            try:
                with open(mpath, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                raise WorkspaceError(f"Corrupt workspace manifest: {exc}") from exc
            meta["name"] = new_name.strip()
            tmp = mpath + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(meta, fh, indent=2)
            os.replace(tmp, mpath)
            if new_slug != slug:
                os.rename(wdir, self._ws_dir(username, new_slug))
            return new_slug

    # --- sharing -----------------------------------------------------------------

    def set_shares(self, username: str, slug: str, usernames) -> list:
        """Replace the share list on a workspace the caller owns. Rewrites only
        the manifest's ``shared_with`` field, atomically."""
        with self._lock:
            wdir = self._ws_dir(username, slug)
            mpath = os.path.join(wdir, "manifest.json")
            if not os.path.isfile(mpath):
                raise WorkspaceError("Workspace not found.")
            try:
                with open(mpath, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                raise WorkspaceError(f"Corrupt workspace manifest: {exc}") from exc
            meta["shared_with"] = self._sanitize_shares(usernames)
            tmp = mpath + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(meta, fh, indent=2)
            os.replace(tmp, mpath)
            return meta["shared_with"]

    def share(self, username: str, slug: str, targets) -> list:
        """Add one or more usernames to a workspace's share list (owner only)."""
        with self._lock:
            meta = self.get(username, slug)
            if meta is None:
                raise WorkspaceError("Workspace not found.")
            current = self._sanitize_shares(meta.get("shared_with"))
            for t in targets:
                name = (t or "").strip()
                if name and name != username and name not in current:
                    current.append(name)
            return self.set_shares(username, slug, current)

    def unshare(self, username: str, slug: str, target: str) -> list:
        """Remove a username from a workspace's share list (owner only)."""
        with self._lock:
            meta = self.get(username, slug)
            if meta is None:
                raise WorkspaceError("Workspace not found.")
            current = [u for u in self._sanitize_shares(meta.get("shared_with"))
                       if u != (target or "").strip()]
            return self.set_shares(username, slug, current)

    def list_shared_with_me(self, username: str) -> list[dict]:
        """Return workspaces other users have shared with ``username``.

        Scans each other user's storage directory for manifests whose
        ``shared_with`` includes this user. Each result carries an ``owner``
        (the owning user's directory slug) used to load it later.
        """
        out: list[dict] = []
        target = (username or "").strip()
        if not target or not os.path.isdir(self.data_root):
            return out
        my_slug = slugify(username)
        for owner_slug in os.listdir(self.data_root):
            if owner_slug == my_slug:
                continue
            odir = os.path.join(self.data_root, owner_slug)
            if not os.path.isdir(odir):
                continue
            for wname in os.listdir(odir):
                mpath = os.path.join(odir, wname, "manifest.json")
                if not os.path.isfile(mpath):
                    continue
                try:
                    with open(mpath, "r", encoding="utf-8") as fh:
                        meta = json.load(fh)
                except (OSError, json.JSONDecodeError):
                    continue
                shares = self._sanitize_shares(meta.get("shared_with"))
                if target not in shares:
                    continue
                meta["slug"] = wname
                meta["owner"] = owner_slug
                meta["shared_with"] = shares
                try:
                    meta["size"] = self._dir_size(os.path.join(odir, wname))
                except OSError:
                    meta["size"] = 0
                out.append(meta)
        out.sort(key=lambda m: m.get("created_at", ""), reverse=True)
        return out
