"""
User authentication for the Log Parser.

Two small, dependency-free pieces:

* ``UserStore`` — loads the allowed users from the local ``users.json`` copy
  (an array of ``{username, pass_hash}`` imported from the shared ``db.json``)
  and verifies a submitted password against the stored **SHA-256** hex digest
  using a constant-time comparison. The shared ``db.json`` is never read here.
* ``LoginThrottle`` — in-memory rate limiting of failed login attempts keyed by
  username + client IP, to blunt online password guessing.

Password hashes are never logged or returned.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time


class UserStoreError(Exception):
    """Raised when the local user store is missing or malformed."""


class UserStore:
    """User records backed by a local JSON file, supporting roles and writes.

    Each record: ``{username, pass_hash, role, must_set_password}``. The file is
    reloaded when its mtime changes and written atomically on updates. Admins are
    users with ``role == 'admin'`` or whose name is in ``admin_usernames``.
    """

    def __init__(self, path: str, admin_usernames=None):
        self.path = path
        self.admins_env = set(admin_usernames or [])
        self._users: dict[str, dict] = {}
        self._mtime = None
        self._lock = threading.RLock()

    # --- loading / saving -------------------------------------------------------

    def _load_locked(self) -> None:
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            # File not created yet — start empty so admins can be bootstrapped.
            self._users = {}
            self._mtime = "missing"
            return
        if self._users and self._mtime == mtime:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise UserStoreError(f"Could not read user store: {exc}") from exc

        raw = data.get("users") if isinstance(data, dict) else None
        if not isinstance(raw, list):
            raise UserStoreError("User store is missing a 'users' array")

        mapping: dict[str, dict] = {}
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            name = entry.get("username")
            if not isinstance(name, str) or not name:
                continue
            mapping[name] = {
                "username": name,
                "pass_hash": (entry.get("pass_hash") or "").strip().lower(),
                "role": entry.get("role") or "user",
                "must_set_password": bool(entry.get("must_set_password", False)),
            }
        self._users = mapping
        self._mtime = mtime

    def _save_locked(self) -> None:
        # Write in place (not temp+rename): the file may be a bind-mounted
        # single file inside a container, where renaming over it fails (EBUSY).
        payload = {"users": list(self._users.values())}
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        try:
            self._mtime = os.path.getmtime(self.path)
        except OSError:
            self._mtime = None

    @staticmethod
    def _hash(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    # --- queries ----------------------------------------------------------------

    def reload_if_changed(self) -> None:
        with self._lock:
            self._load_locked()

    def exists(self, username: str) -> bool:
        with self._lock:
            self._load_locked()
            return username in self._users

    def is_admin(self, username: str) -> bool:
        with self._lock:
            self._load_locked()
            rec = self._users.get(username)
        return bool(username) and (
            (rec is not None and rec.get("role") == "admin") or username in self.admins_env)

    def needs_password(self, username: str) -> bool:
        """True when the account exists but has no usable password yet (freshly
        added or admin-reset), so the user must set one before signing in."""
        with self._lock:
            self._load_locked()
            rec = self._users.get(username)
        if not rec:
            return False
        return bool(rec.get("must_set_password")) or not rec.get("pass_hash")

    def verify(self, username: str, password: str) -> bool:
        if not username or password is None:
            return False
        with self._lock:
            self._load_locked()
            rec = self._users.get(username)
        if not rec:
            return False
        stored = rec.get("pass_hash")
        if not stored or rec.get("must_set_password"):
            return False
        return hmac.compare_digest(self._hash(password), stored)

    def list_users(self) -> list[dict]:
        with self._lock:
            self._load_locked()
            out = []
            for rec in self._users.values():
                out.append({
                    "username": rec["username"],
                    "role": "admin" if (rec.get("role") == "admin"
                                        or rec["username"] in self.admins_env) else "user",
                    "needs_password": bool(rec.get("must_set_password") or not rec.get("pass_hash")),
                })
            out.sort(key=lambda r: r["username"].lower())
            return out

    # --- mutations --------------------------------------------------------------

    def set_password(self, username: str, password: str) -> None:
        with self._lock:
            self._load_locked()
            rec = self._users.get(username)
            if not rec:
                raise UserStoreError("No such user")
            rec["pass_hash"] = self._hash(password)
            rec["must_set_password"] = False
            self._save_locked()

    def add_user(self, username: str, password: str | None = None,
                 admin: bool = False) -> None:
        with self._lock:
            self._load_locked()
            if username in self._users:
                raise UserStoreError(f"User '{username}' already exists")
            rec = {"username": username, "pass_hash": "",
                   "role": "admin" if admin else "user", "must_set_password": True}
            if password:
                rec["pass_hash"] = self._hash(password)
                rec["must_set_password"] = False
            self._users[username] = rec
            self._save_locked()

    def reset_password(self, username: str) -> None:
        with self._lock:
            self._load_locked()
            rec = self._users.get(username)
            if not rec:
                raise UserStoreError("No such user")
            rec["pass_hash"] = ""
            rec["must_set_password"] = True
            self._save_locked()

    def delete_user(self, username: str) -> None:
        with self._lock:
            self._load_locked()
            if username in self._users:
                del self._users[username]
                self._save_locked()

    def ensure_admins(self, usernames) -> None:
        """Bootstrap: make sure each configured admin username exists and is
        flagged admin. Missing ones are created awaiting a first-login password."""
        with self._lock:
            self._load_locked()
            changed = False
            for u in usernames:
                if not u:
                    continue
                rec = self._users.get(u)
                if rec is None:
                    self._users[u] = {"username": u, "pass_hash": "",
                                      "role": "admin", "must_set_password": True}
                    changed = True
                elif rec.get("role") != "admin":
                    rec["role"] = "admin"
                    changed = True
            if changed:
                self._save_locked()


class LoginThrottle:
    """Best-effort in-memory failed-login limiter (per username + client IP)."""

    def __init__(self, max_attempts: int = 5, lockout_seconds: int = 300):
        self.max_attempts = max_attempts
        self.lockout = lockout_seconds
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(username: str, ip: str) -> str:
        return f"{username}\x00{ip}"

    def _recent(self, key: str, now: float) -> list[float]:
        return [t for t in self._fails.get(key, []) if now - t < self.lockout]

    def is_locked(self, username: str, ip: str) -> bool:
        now = time.time()
        key = self._key(username, ip)
        with self._lock:
            recent = self._recent(key, now)
            self._fails[key] = recent
            return len(recent) >= self.max_attempts

    def record_failure(self, username: str, ip: str) -> None:
        now = time.time()
        key = self._key(username, ip)
        with self._lock:
            recent = self._recent(key, now)
            recent.append(now)
            self._fails[key] = recent

    def reset(self, username: str, ip: str) -> None:
        with self._lock:
            self._fails.pop(self._key(username, ip), None)
