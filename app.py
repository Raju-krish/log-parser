#!/usr/bin/env python3
"""
Log Parser — standalone Flask web app.

Upload a tar/tar.gz/zip archive or multiple individual RDKB device logs,
then view them separately or merged into one chronological, color-coded,
paginated timeline with timestamp-range filtering.

Run:  python app.py   (listens on 0.0.0.0:5100 by default)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import uuid

from flask import (
    Flask, Response, flash, jsonify, redirect, render_template, request, session,
    url_for,
)
from markupsafe import Markup, escape
from werkzeug.utils import secure_filename

import ingest
from auth import LoginThrottle, UserStore, UserStoreError
from logmodel import (
    LEVEL_ORDER, LogSource, Page, classify_is_log, color_for, file_category,
    filter_by_level, filter_by_text, filter_records, level_counts,
    merge_records, paginate, parse_source,
)
from timestamps import (
    ParserConfig, format_canonical, parse_filter_bound,
)
from workspaces import WorkspaceError, WorkspaceStore, slugify as ws_slugify
from bookmarks import BookmarkStore
from notepad import NotepadStore

# --- Configuration --------------------------------------------------------------

PORT = int(os.environ.get("LOG_PARSER_PORT", "5100"))
MAX_CONTENT_LENGTH = int(os.environ.get("LOG_PARSER_MAX_UPLOAD", str(256 * 1024 * 1024)))  # 256 MB
DEFAULT_PAGE_SIZE = int(os.environ.get("LOG_PARSER_PAGE_SIZE", "1000"))
# Pagination is ON by default (1000 lines/page) so huge logs don't load at once.
# Set LOG_PARSER_PAGINATE=0 to render everything on one page instead.
PAGINATE = os.environ.get("LOG_PARSER_PAGINATE", "1") == "1"
ASSUMED_YEAR = os.environ.get("LOG_PARSER_ASSUMED_YEAR")  # for yearless syslog
# Optional: constrain server-side path reads to within this root (realpath).
# Empty = unrestricted (this is a local single-user tool reading your own logs).
ALLOWED_ROOT = os.environ.get("LOG_PARSER_ALLOWED_ROOT", "").strip()
HERE = os.path.dirname(os.path.abspath(__file__))
# Local copy of allowed users (username + SHA-256 pass_hash), imported from the
# shared db.json via import_users.py. The app never reads the shared file.
USERS_DB = os.environ.get("LOG_PARSER_USERS_DB", os.path.join(HERE, "users.json"))
# Root of per-user persistent workspace storage.
DATA_ROOT = os.environ.get("LOG_PARSER_DATA_ROOT", os.path.join(HERE, "data"))
# Per-user storage quota (default 500 MB).
USER_QUOTA = int(os.environ.get("LOG_PARSER_USER_QUOTA", str(500 * 1024 * 1024)))
WORK_ROOT = os.path.join(tempfile.gettempdir(), "log-parser")
SESSION_MAX_AGE = 6 * 3600  # sweep working dirs older than 6h on startup

# Named source presets (quick templates). Files are matched by normalized
# basename stem — case-insensitive and ignoring extensions / rotation suffixes —
# so `wifiHal.txt`, `wifiHAL`, and `wifiHal.txt.0` all match `wifihal`.
PRESETS = {
    "wifi": {
        "label": "WiFi Analysis",
        "files": {
            "wifidmcli", "wifihal", "wifimgr", "wifimon",
            "wifiwebconfig", "wifictrl", "messages",
        },
    },
}

# Display order / labels / icons for the non-log file categories (the chips
# shown above the logs). Only categories that actually have files are shown.
_CAT_META = [
    ("conf", "Config", "\u2699"),
    ("xml", "XML", "\u25c7"),
    ("db", "Database", "\U0001f5c3"),
    ("pid", "PID / state", "\U0001f516"),
    ("cert", "Certs / keys", "\U0001f511"),
    ("image", "Images", "\U0001f5bc"),
    ("web", "Web", "\U0001f310"),
    ("capture", "Binary", "\U0001f4e6"),
    ("other", "Other", "\u2022"),
]


def _log_stem(name: str) -> str:
    """Normalize a source name to a comparable stem: basename, lowercased, with
    extensions (.txt/.log/.out/.err/.gz) and rotation suffixes (.0/.1…) removed."""
    base = name.rsplit("/", 1)[-1].lower()
    prev = None
    while prev != base:
        prev = base
        base = re.sub(r"\.\d+$", "", base)                       # rotation .0/.1
        base = re.sub(r"\.(txt|log|out|err|gz|bz2|xz)$", "", base)  # extension
    return base


def _preset_matches(name: str, wanted_stems: set) -> bool:
    return _log_stem(name) in wanted_stems

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = os.environ.get("LOG_PARSER_SECRET", os.urandom(24).hex())
# Session-cookie hardening. Set LOG_PARSER_COOKIE_SECURE=1 when served over HTTPS.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("LOG_PARSER_COOKIE_SECURE", "0") == "1",
)

# Authentication + persistent per-user workspace storage.
ADMIN_USERS = [u.strip() for u in os.environ.get("LOG_PARSER_ADMINS", "admin").split(",") if u.strip()]
USERS = UserStore(USERS_DB, admin_usernames=ADMIN_USERS)
THROTTLE = LoginThrottle()
WORKSPACES = WorkspaceStore(DATA_ROOT, USER_QUOTA)
BOOKMARKS = BookmarkStore(DATA_ROOT)
NOTEPAD = NotepadStore(DATA_ROOT)
try:
    USERS.ensure_admins(ADMIN_USERS)
except Exception as _exc:  # noqa: BLE001 (best-effort bootstrap; store may be read-only)
    app.logger.warning("Could not bootstrap admin accounts: %s", _exc)

# In-memory registry: session_id -> {"dir": str, "sources": {id: LogSource}}
_SESSIONS: dict[str, dict] = {}


@app.context_processor
def _inject_user():
    username = session.get("username")
    admin = False
    if username:
        try:
            admin = USERS.is_admin(username)
        except Exception:  # noqa: BLE001
            admin = False
    return {"current_user": username, "is_admin": admin}


# Endpoints reachable without an authenticated session.
_PUBLIC_ENDPOINTS = {"login", "static", "about", "set_password"}


def _is_safe_next(target: str) -> bool:
    """Only allow local, relative redirect targets (guards against open redirects)."""
    return bool(target) and target.startswith("/") and not target.startswith("//")


@app.before_request
def _require_login():
    if request.endpoint in _PUBLIC_ENDPOINTS:
        return None
    if session.get("username"):
        return None
    if request.method == "GET":
        nxt = request.full_path if request.query_string else request.path
        return redirect(url_for("login", next=nxt))
    return redirect(url_for("login"))


@app.template_filter("highlight")
def _highlight(text: str, query: str, jump: str = ""):
    """Escape line text, then wrap case-insensitive matches of the search
    term(s) in <mark>. Multiple ``query`` terms may be separated by ``|``; the
    ``jump`` term (Global search) gets a distinct <mark class="jmark">.
    Escaping happens before insertion (XSS-safe)."""
    escaped = str(escape(text))
    alts = []
    seen = set()
    if jump:
        j = str(escape(jump))
        alts.append(("j", re.escape(j)))
        seen.add(j.casefold())
    # Collect the distinct "message contains" terms; longer ones first so they
    # win over shorter overlapping terms in the alternation.
    terms = []
    for term in query.split("|"):
        term = term.strip()
        if not term:
            continue
        esc = str(escape(term))
        key = esc.casefold()
        if key in seen:
            continue
        seen.add(key)
        terms.append(esc)
    terms.sort(key=len, reverse=True)
    for i, esc in enumerate(terms):
        alts.append((f"q{i}", re.escape(esc)))
    if not alts:
        return Markup(escaped)
    pattern = re.compile("|".join(f"(?P<{n}>{p})" for n, p in alts), re.IGNORECASE)

    def _repl(m):
        if m.lastgroup == "j":
            return f'<mark class="jmark">{m.group(0)}</mark>'
        return f"<mark>{m.group(0)}</mark>"

    return Markup(pattern.sub(_repl, escaped))


# Origin path segments surfaced in a source's short label. Matched as exact
# path components (case-insensitive) so unrelated names like "mytmp" don't hit.
# ``rdklogs`` is checked first as it is the more specific origin.
_ORIGIN_SEGMENTS = ("rdklogs", "tmp")


@app.template_filter("short_source")
def _short_source(name: str) -> str:
    """Compact label for a source: just the filename plus a ``/tmp`` or
    ``/rdklogs`` origin tag when the path carries one.

    Log dumps use deep relative paths (optionally prefixed with a bundle
    label), e.g. ``2026-05-05 06:00:00/rdklogs/logs/WiFilog.txt.0``. Showing
    those in full clutters the log view, so each collapses to::

        rdklogs/logs/WiFilog.txt.0    -> /rdklogs/WiFilog.txt.0
        run/tmp/CcspWifiSsp.txt.0     -> /tmp/CcspWifiSsp.txt.0
        nvram/logs/dhd.log            -> dhd.log
    """
    if not name:
        return name
    base = name.rsplit("/", 1)[-1]
    segments = name.lower().split("/")
    for origin in _ORIGIN_SEGMENTS:
        if origin in segments:
            return f"/{origin}/{base}"
    return base


def _parser_config() -> ParserConfig:
    year = int(ASSUMED_YEAR) if ASSUMED_YEAR else None
    return ParserConfig(assumed_year=year)


def _sweep_stale_dirs() -> None:
    """Best-effort removal of working dirs left over from old sessions."""
    if not os.path.isdir(WORK_ROOT):
        return
    now = time.time()
    for name in os.listdir(WORK_ROOT):
        path = os.path.join(WORK_ROOT, name)
        try:
            if now - os.path.getmtime(path) > SESSION_MAX_AGE:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass


def _get_session_id() -> str:
    sid = session.get("sid")
    if not sid:
        sid = uuid.uuid4().hex
        session["sid"] = sid
    return sid


def _reset_workdir(sid: str) -> str:
    """Create a fresh isolated working directory for this session."""
    prev = _SESSIONS.get(sid)
    if prev and os.path.isdir(prev["dir"]):
        shutil.rmtree(prev["dir"], ignore_errors=True)
    os.makedirs(WORK_ROOT, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix=f"{sid}-", dir=WORK_ROOT)
    _SESSIONS[sid] = {"dir": workdir, "sources": {}}
    return workdir


def _current(sid: str) -> dict | None:
    return _SESSIONS.get(sid)


def _bookmark_scope(state) -> str:
    """Identity for the currently loaded logs so notes stay per log folder.

    Saved workspaces are keyed by their slug; a fresh upload is keyed by a
    stable hash of its source file names, so re-uploading the same folder
    reuses its notes while a different folder keeps its own separate set."""
    if not state:
        return ""
    # A shared workspace uses the OWNER's stable scope (set at load time) so
    # everyone with access reads/writes the same note set. Owned workspaces set
    # the same "ws:<name>" scope, keeping existing notes intact.
    scope = state.get("ws_scope")
    if scope:
        return scope
    slug = state.get("loaded_from")
    if slug:
        return "ws:" + str(slug)
    sources = state.get("sources") or {}
    names = sorted(s.name for s in sources.values())
    if not names:
        return ""
    digest = hashlib.sha1("\n".join(names).encode("utf-8")).hexdigest()
    return "up:" + digest[:16]


def _notes_owner(state) -> str:
    """Whose bookmark store holds the current view's notes. For a workspace
    shared with the caller this is the workspace OWNER (so shared notes are
    visible and collaborative); otherwise it's the current user."""
    if state and state.get("ws_owner"):
        return state["ws_owner"]
    return session.get("username", "")


def _bundle_label(name: str) -> str:
    """Derive a short, readable label for a nested archive bundle.

    Bundle filenames look like
    ``2026-05-07 06:00:00-4075C33AE01E_Logs_05-07-26-06-37AM.tgz`` — use the
    leading timestamp when present, otherwise the filename without extension.
    """
    base = os.path.basename(name)
    m = re.match(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", base)
    if m:
        return m.group(1)
    for ext in (".tar.gz", ".tgz", ".tar", ".zip"):
        if base.lower().endswith(ext):
            return base[: -len(ext)]
    return base


def _human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num} B"


def _register_source_groups(sid: str, groups: list[tuple]) -> None:
    """Register sources from one or more (label, root, files) groups.

    When more than one group is provided, each source name is prefixed with the
    group's label so bundles from different time windows stay distinguishable.
    """
    cfg = _parser_config()
    sources: dict[int, LogSource] = {}
    idx = 0
    multi = len(groups) > 1
    for label, root, files in groups:
        for path in sorted(files, key=lambda p: os.path.relpath(p, root).lower()):
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            name = f"{label}/{rel}" if (multi and label) else rel
            src = LogSource(source_id=idx, name=name, path=path, color=color_for(idx))
            try:
                parse_source(src, cfg)
            except OSError:
                continue
            src.is_log = classify_is_log(src.name, src.line_count, src.parsed_count)
            src.category = file_category(src.name, src.is_log)
            sources[idx] = src
            idx += 1
    _SESSIONS[sid]["sources"] = sources


def _split_counts(sid: str) -> tuple:
    """(#log files, #non-log files) currently registered for this session."""
    srcs = list(_SESSIONS[sid]["sources"].values())
    logs = sum(1 for s in srcs if getattr(s, "is_log", True))
    return logs, len(srcs) - logs


def _collect_from_path(path: str, workdir: str) -> list[str]:
    """Collect log files from a server-side path (directory or file).

    Directories are walked recursively; a single archive file is extracted into
    the working directory. Raises ``ingest.IngestError`` for invalid, missing,
    or (when a root is configured) forbidden paths.
    """
    real = os.path.realpath(os.path.expanduser(path))
    if ALLOWED_ROOT:
        root = os.path.realpath(ALLOWED_ROOT)
        if real != root and not real.startswith(root + os.sep):
            raise ingest.IngestError(
                f"Path is outside the allowed root ({ALLOWED_ROOT})")
    if not os.path.exists(real):
        raise ingest.IngestError(f"Path does not exist: {path}")

    if os.path.isdir(real):
        files = ingest.collect_log_files(real)
        if not files:
            raise ingest.IngestError(f"No files found in directory: {path}")
        return files

    # A single file: extract if it is an archive, otherwise use it directly.
    if ingest.is_archive(os.path.basename(real)):
        extract_dir = os.path.join(workdir, "extracted", os.path.basename(real))
        os.makedirs(extract_dir, exist_ok=True)
        return ingest.extract_archive(real, extract_dir)
    return [real]


def _expand_deep_archives(archives: list[str], workdir: str,
                          depth: int = 0) -> list[tuple]:
    """Recursively extract incidental/nested archives (e.g. nvram/logs/dhd_*.tar.gz)
    and return ``(label, root, files)`` groups of the plain files inside them.

    These are archives that are NOT top-level selectable bundles — they should be
    unpacked and shown as sources rather than cluttering the bundle picker."""
    groups: list[tuple] = []
    if depth > 4:
        return groups
    for i, arc in enumerate(archives):
        edir = os.path.join(workdir, "deep", str(depth),
                            f"{i}_{os.path.basename(arc)}")
        os.makedirs(edir, exist_ok=True)
        try:
            files = ingest.extract_archive(arc, edir)
        except ingest.IngestError:
            continue
        inner = [f for f in files if ingest.is_archive(os.path.basename(f))]
        plain = [f for f in files if f not in set(inner)]
        if plain:
            groups.append((_bundle_label(arc), edir, plain))
        groups.extend(_expand_deep_archives(inner, edir, depth + 1))
    return groups


def _finalize_collected(sid: str, collected: list[str]):
    """Show the bundle picker only when the upload is primarily a *collection of
    archives* (a zip/folder of per-time-window bundles). Archives that are merely
    incidental among log files (e.g. ``nvram/logs/dhd_*.tar.gz``) are auto-extracted
    and registered as sources instead of appearing in the picker."""
    if not collected:
        flash("No log files were found.", "error")
        return redirect(url_for("index"))

    archives = [p for p in collected if ingest.is_archive(os.path.basename(p))]
    plain = [p for p in collected if p not in set(archives)]

    # Bundle picker only when archives dominate the content (few/no plain logs
    # alongside). A handful of archives among many logs => auto-extract them.
    if archives and len(archives) > len(plain):
        archives_meta = [
            {"id": i, "path": p, "name": os.path.basename(p),
             "label": _bundle_label(p), "size": os.path.getsize(p),
             "size_h": _human_size(os.path.getsize(p))}
            for i, p in enumerate(sorted(archives, key=lambda x: os.path.basename(x).lower()))
        ]
        _SESSIONS[sid]["pending"] = {"archives": archives_meta, "plain": plain}
        flash(f"Found {len(archives_meta)} log bundle(s) — choose which to analyze.", "info")
        return redirect(url_for("select"))

    # Otherwise register the plain logs plus anything inside incidental archives.
    workdir = _SESSIONS[sid]["dir"]
    groups: list[tuple] = []
    if plain:
        proot = os.path.commonpath(plain) if len(plain) > 1 else os.path.dirname(plain[0])
        groups.append((None, proot, plain))
    groups.extend(_expand_deep_archives(archives, workdir))

    if not groups:
        flash("No readable log files were found.", "error")
        return redirect(url_for("index"))
    _register_source_groups(sid, groups)
    logs, others = _split_counts(sid)
    msg = f"Loaded {logs} log file(s)."
    if others:
        msg += f" {others} non-log file(s) set aside \u2014 use \u201cShow other files\u201d to view them."
    flash(msg, "info")
    return redirect(url_for("view"))


# --- Routes ---------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("username"):
        return redirect(url_for("index"))
    next_url = request.values.get("next", "")
    if not _is_safe_next(next_url):
        next_url = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr or "?"
        if THROTTLE.is_locked(username, ip):
            flash("Too many failed attempts. Please wait a few minutes and try again.", "error")
            return render_template("login.html", next_url=next_url), 429
        try:
            # Accounts freshly added / reset by an admin have no password yet:
            # send them to set one instead of failing the login.
            if USERS.needs_password(username):
                return redirect(url_for("set_password", username=username, next=next_url))
            ok = USERS.verify(username, password)
        except UserStoreError as exc:
            app.logger.error("User store unavailable: %s", exc)
            flash("Login is temporarily unavailable \u2014 contact the administrator.", "error")
            return render_template("login.html", next_url=next_url), 503
        if ok:
            THROTTLE.reset(username, ip)
            session.clear()
            session["username"] = username
            return redirect(next_url or url_for("index"))
        THROTTLE.record_failure(username, ip)
        flash("Invalid username or password.", "error")
    return render_template("login.html", next_url=next_url)


@app.route("/set-password", methods=["GET", "POST"])
def set_password():
    """First-time / post-reset password setup for an account awaiting one."""
    if session.get("username"):
        return redirect(url_for("index"))
    username = request.values.get("username", "").strip()
    next_url = request.values.get("next", "")
    if not _is_safe_next(next_url):
        next_url = ""
    try:
        awaiting = USERS.needs_password(username)
    except UserStoreError:
        awaiting = False
    if not username or not awaiting:
        flash("That account is not awaiting a password (or does not exist).", "info")
        return redirect(url_for("login"))

    if request.method == "POST":
        pw1 = request.form.get("password", "")
        pw2 = request.form.get("password2", "")
        if len(pw1) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template("set_password.html", username=username, next_url=next_url)
        if pw1 != pw2:
            flash("Passwords do not match.", "error")
            return render_template("set_password.html", username=username, next_url=next_url)
        try:
            USERS.set_password(username, pw1)
        except UserStoreError as exc:
            flash(f"Could not set password: {exc}", "error")
            return render_template("set_password.html", username=username, next_url=next_url)
        session.clear()
        session["username"] = username
        flash("Password set — you're signed in.", "info")
        return redirect(next_url or url_for("index"))

    return render_template("set_password.html", username=username, next_url=next_url)


def _require_admin() -> bool:
    u = session.get("username")
    try:
        return bool(u) and USERS.is_admin(u)
    except Exception:  # noqa: BLE001
        return False


@app.route("/admin")
def admin():
    if not _require_admin():
        flash("Administrator access is required for that page.", "error")
        return redirect(url_for("index"))
    return render_template("admin.html", users=USERS.list_users())


@app.route("/admin/add", methods=["POST"])
def admin_add():
    if not _require_admin():
        flash("Administrator access is required.", "error")
        return redirect(url_for("index"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    make_admin = request.form.get("is_admin") == "1"
    if not re.match(r"^[A-Za-z0-9._-]{2,40}$", username):
        flash("Username must be 2\u201340 characters: letters, digits, '.', '_' or '-'.", "error")
        return redirect(url_for("admin"))
    try:
        USERS.add_user(username, password or None, admin=make_admin)
    except UserStoreError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin"))
    if password:
        flash(f"Added user '{username}'.", "info")
    else:
        flash(f"Added user '{username}'. They will set their password on first sign-in.", "info")
    return redirect(url_for("admin"))


@app.route("/admin/reset", methods=["POST"])
def admin_reset():
    if not _require_admin():
        flash("Administrator access is required.", "error")
        return redirect(url_for("index"))
    username = request.form.get("username", "").strip()
    try:
        USERS.reset_password(username)
    except UserStoreError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin"))
    flash(f"Password reset for '{username}'. They will choose a new password on next sign-in.", "info")
    return redirect(url_for("admin"))


@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    if not _require_admin():
        flash("Administrator access is required.", "error")
        return redirect(url_for("index"))
    username = request.form.get("username", "").strip()
    if username == session.get("username"):
        flash("You cannot remove your own account.", "error")
        return redirect(url_for("admin"))
    USERS.delete_user(username)
    flash(f"Removed user '{username}'.", "info")
    return redirect(url_for("admin"))


@app.route("/logout")
def logout():
    sid = session.get("sid")
    if sid:
        prev = _SESSIONS.pop(sid, None)
        if prev and os.path.isdir(prev["dir"]):
            shutil.rmtree(prev["dir"], ignore_errors=True)
    session.clear()
    flash("Signed out.", "info")
    return redirect(url_for("login"))


APP_VERSION = "1.0"


@app.route("/about")
def about():
    """Public, shareable overview of everything the tool can do."""
    return render_template("about.html", version=APP_VERSION)


@app.route("/")
def index():
    username = session["username"]
    try:
        workspaces = WORKSPACES.list_workspaces(username)
        used = WORKSPACES.usage(username)
    except WorkspaceError as exc:
        app.logger.warning("Workspace listing failed for %s: %s", username, exc)
        workspaces, used = [], 0
    for w in workspaces:
        w["size_h"] = _human_size(w.get("size", 0))
    shared = []
    try:
        shared = WORKSPACES.list_shared_with_me(username)
    except Exception as exc:  # noqa: BLE001
        app.logger.warning("Shared-workspace listing failed for %s: %s", username, exc)
    for w in shared:
        w["size_h"] = _human_size(w.get("size", 0))
    all_users = []
    try:
        all_users = [u["username"] for u in USERS.list_users()
                     if u["username"] != username]
    except Exception as exc:  # noqa: BLE001
        app.logger.warning("User listing failed for %s: %s", username, exc)
    sid = _get_session_id()
    state = _current(sid)
    sources = list(state["sources"].values()) if state else []
    sources.sort(key=lambda s: s.source_id)
    pct = min(100, round(used * 100 / USER_QUOTA)) if USER_QUOTA else 0
    return render_template(
        "home.html", workspaces=workspaces, shared=shared, sources=sources,
        all_users=all_users,
        used=used, quota=USER_QUOTA, used_h=_human_size(used),
        quota_h=_human_size(USER_QUOTA), pct=pct)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        sid = _get_session_id()
        state = _current(sid)
        sources = list(state["sources"].values()) if state else []
        sources.sort(key=lambda s: s.source_id)
        return render_template("index.html", sources=sources)

    sid = _get_session_id()
    uploaded = request.files.getlist("files")
    uploaded = [f for f in uploaded if f and f.filename]
    path_input = request.form.get("path", "").strip()

    if not uploaded and not path_input:
        flash("Select files to upload or enter a server-side path.", "error")
        return redirect(url_for("index"))

    workdir = _reset_workdir(sid)
    raw_dir = os.path.join(workdir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    collected: list[str] = []
    try:
        # 1) Uploaded files (saved into the workdir; archives extracted).
        for storage in uploaded:
            fname = secure_filename(storage.filename) or "upload.bin"
            saved = os.path.join(raw_dir, fname)
            storage.save(saved)
            if ingest.is_archive(fname):
                extract_dir = os.path.join(workdir, "extracted", fname)
                os.makedirs(extract_dir, exist_ok=True)
                collected.extend(ingest.extract_archive(saved, extract_dir))
            else:
                collected.append(saved)
        # 2) Server-side path (folder or file), read in place.
        if path_input:
            collected.extend(_collect_from_path(path_input, workdir))
    except ingest.IngestError as exc:
        flash(f"Rejected: {exc}", "error")
        return redirect(url_for("index"))

    return _finalize_collected(sid, collected)


@app.route("/select", methods=["GET"])
def select():
    sid = _get_session_id()
    state = _current(sid)
    pending = state.get("pending") if state else None
    if not pending:
        flash("Upload an archive first.", "info")
        return redirect(url_for("index"))
    return render_template("select.html", archives=pending["archives"],
                           has_plain=bool(pending.get("plain")))


@app.route("/select", methods=["POST"])
def select_post():
    sid = _get_session_id()
    state = _current(sid)
    pending = state.get("pending") if state else None
    if not pending:
        flash("Upload an archive first.", "info")
        return redirect(url_for("index"))

    chosen = set(request.form.getlist("archive", type=int))
    if not chosen:
        flash("Select at least one log bundle to analyze.", "error")
        return redirect(url_for("select"))

    workdir = state["dir"]
    by_id = {a["id"]: a for a in pending["archives"]}
    groups: list[tuple] = []
    try:
        for aid in sorted(chosen):
            arc = by_id.get(aid)
            if not arc:
                continue
            bundle_dir = os.path.join(workdir, "bundles", str(aid))
            os.makedirs(bundle_dir, exist_ok=True)
            files = ingest.extract_archive(arc["path"], bundle_dir)
            inner = [f for f in files if ingest.is_archive(os.path.basename(f))]
            flat = [f for f in files if f not in set(inner)]
            if flat:
                groups.append((arc["label"], bundle_dir, flat))
            # Auto-extract incidental archives inside the bundle (e.g. dhd_*.tar.gz).
            groups.extend(_expand_deep_archives(inner, bundle_dir))
    except ingest.IngestError as exc:
        flash(f"Bundle rejected: {exc}", "error")
        return redirect(url_for("select"))

    # Carry any plain (non-archive) files found alongside the bundles.
    plain = pending.get("plain") or []
    if plain:
        proot = os.path.commonpath(plain) if len(plain) > 1 else os.path.dirname(plain[0])
        groups.append(("files", proot, plain))

    if not groups:
        flash("No log files were found in the selected bundle(s).", "error")
        return redirect(url_for("select"))

    _register_source_groups(sid, groups)
    _SESSIONS[sid].pop("pending", None)
    logs, others = _split_counts(sid)
    msg = f"Loaded {logs} log file(s) from {len(chosen)} bundle(s)."
    if others:
        msg += f" {others} non-log file(s) set aside."
    flash(msg, "info")
    return redirect(url_for("view"))


def _resolve_selection(state, args, flash_errors=True):
    """Resolve the selected sources and parsed filters from request args.

    Shared by the view and export routes so both honour the same preset,
    source selection, timestamp range, and text query. Returns a dict.
    """
    all_sources = sorted(state["sources"].values(), key=lambda s: s.source_id)
    existing_ids = {s.source_id for s in all_sources}
    # Split log files from non-log files and group the latter by type (conf,
    # xml, db, pid, …). The default view is the logs; a category filter (?cat=)
    # opens just that non-log group, shown separately rather than merged.
    log_ids = {s.source_id for s in all_sources if getattr(s, "is_log", True)}
    other_ids = existing_ids - log_ids
    cat_of = {s.source_id: getattr(s, "category", "log") for s in all_sources}
    cat_counts = {}
    for _c in cat_of.values():
        if _c != "log":
            cat_counts[_c] = cat_counts.get(_c, 0) + 1
    cat = args.get("cat", "").strip().lower()
    if cat in cat_counts:
        universe = {sid for sid, c in cat_of.items() if c == cat}
        show_others = True
    else:
        cat = "log"
        universe = log_ids or existing_ids
        show_others = False

    explicit_preset = args.get("preset", "").strip()
    want_all = args.get("all") == "1"
    excl_ids = set(args.getlist("excl", type=int))   # excluded ids when want_all
    has_src = bool(args.getlist("src", type=int))
    # lgset: the persisted "legend candidate" source ids (comma-separated) so a
    # manual selection keeps showing excluded sources as re-includable chips.
    # Its presence also signals the controls form has been submitted at least
    # once (the user has interacted), so we don't snap back to the default preset.
    interacted = "lgset" in args
    lgset_raw = args.get("lgset", "").strip()
    lgset_ids = [int(x) for x in lgset_raw.split(",") if x.strip().isdigit()]

    # Default to the WiFi Analysis preset only on a truly fresh log view (no
    # explicit choice / interaction, and not while viewing the non-log bundle).
    preset_key = explicit_preset
    if (not preset_key and not has_src and not want_all and not interacted
            and not show_others and "wifi" in PRESETS):
        preset_key = "wifi"

    preset = PRESETS.get(preset_key) if not show_others else None
    if preset:
        wanted = preset["files"]
        selected_ids = {
            s.source_id for s in all_sources
            if s.source_id in log_ids and _preset_matches(s.name, wanted)
        }
        if not selected_ids:
            # Only warn when the user explicitly asked for a preset.
            if flash_errors and explicit_preset:
                flash(f"No logs matching the {preset['label']} preset were found "
                      f"in this upload.", "info")
            selected_ids = set(universe)
            preset = None
            preset_key = ""
    else:
        sel = args.getlist("src", type=int)
        if want_all:
            selected_ids = universe - excl_ids
        elif sel:
            selected_ids = set(sel)
        elif interacted:
            selected_ids = set()          # user explicitly deselected everything
        else:
            selected_ids = set(universe)
    selected = [s for s in all_sources if s.source_id in selected_ids]

    # Legend candidate ids (the toggle bar above the logs):
    #  - a preset  -> that preset's matched sources (so excluded ones show too)
    #  - lgset      -> the persisted manual working set
    #  - otherwise  -> the currently selected sources
    if show_others:
        legend_ids = [s.source_id for s in all_sources if s.source_id in universe]
    elif preset:
        legend_ids = [s.source_id for s in all_sources
                      if s.source_id in log_ids and _preset_matches(s.name, preset["files"])]
    elif lgset_ids:
        legend_ids = [i for i in lgset_ids if i in existing_ids]
    else:
        legend_ids = [s.source_id for s in selected]

    mode = args.get("mode", "merge")
    if show_others:
        mode = "separate"   # non-log files are shown per-file, never merged
    start_raw = args.get("start", "").strip()
    end_raw = args.get("end", "").strip()
    q_raw = args.get("q", "").strip()
    qmode = args.get("qmode", "any").strip().lower()
    if qmode not in ("any", "all"):
        qmode = "any"
    start = parse_filter_bound(start_raw)
    end = parse_filter_bound(end_raw)
    if flash_errors and start_raw and start is None:
        flash(f"Could not parse start time: {start_raw!r}", "error")
    if flash_errors and end_raw and end is None:
        flash(f"Could not parse end time: {end_raw!r}", "error")

    return {
        "all_sources": all_sources, "selected_ids": selected_ids,
        "selected": selected, "preset_key": preset_key if preset else "",
        "legend_ids": legend_ids,
        "show_others": show_others, "active_cat": cat, "cat_counts": cat_counts,
        "log_count": len(log_ids), "other_count": len(other_ids),
        "universe_ids": universe,
        "mode": mode, "start_raw": start_raw, "end_raw": end_raw, "q_raw": q_raw,
        "qmode": qmode,
        "start": start, "end": end,
    }


@app.route("/view")
def view():
    sid = _get_session_id()
    state = _current(sid)
    if state and state.get("pending") and not state.get("sources"):
        return redirect(url_for("select"))
    if not state or not state["sources"]:
        flash("Upload some logs first.", "info")
        return redirect(url_for("index"))

    sel = _resolve_selection(state, request.args)
    all_sources = sel["all_sources"]
    selected_ids = sel["selected_ids"]
    selected = sel["selected"]
    preset_key = sel["preset_key"]
    legend_ids = sel["legend_ids"]
    mode = sel["mode"]
    start_raw, end_raw, q_raw = sel["start_raw"], sel["end_raw"], sel["q_raw"]
    qmode = sel["qmode"]
    start, end = sel["start"], sel["end"]
    show_others = sel["show_others"]
    other_count = sel["other_count"]
    log_count = sel["log_count"]
    universe_ids = sel["universe_ids"]
    active_cat = sel["active_cat"]
    cat_counts = sel["cat_counts"]

    # Candidate sources for the clickable legend/toggle bar above the logs,
    # ordered per legend_ids; each may be included (selected) or excluded.
    by_id = state["sources"]
    legend_candidates = [by_id[i] for i in legend_ids if i in by_id]

    # Highlight a preset chip whenever the current selection equals that preset's
    # matched set (regardless of how it was chosen).
    active_preset = preset_key
    if not active_preset:
        for k, p in PRESETS.items():
            matched = {s.source_id for s in all_sources
                       if _preset_matches(s.name, p["files"])}
            if matched and matched == selected_ids:
                active_preset = k
                break

    # Compact selection for links so hundreds of sources don't overflow URLs:
    # enumerate whichever set is smaller (included vs. excluded), relative to the
    # current universe (logs, or the non-log bundle when others=1).
    if len(selected_ids) * 2 > len(universe_ids):
        sel_kwargs = {"all": 1, "excl": sorted(universe_ids - selected_ids)}
    else:
        sel_kwargs = {"src": sorted(selected_ids)}
    if show_others:
        sel_kwargs["cat"] = active_cat
    # Only persist an interactive legend set (<=40); larger falls back to a
    # static capped legend, so the hidden field stays small.
    legend_ids_str = ",".join(str(i) for i in legend_ids) if len(legend_ids) <= 40 else ""

    # Pagination is optional. When disabled, page_size=None => one page of all.
    if PAGINATE:
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("page_size", DEFAULT_PAGE_SIZE, type=int)
        page_size = max(50, min(page_size, 5000))
    else:
        page = 1
        page_size = None

    color_map = {s.source_id: s.color for s in all_sources}
    name_map = {s.source_id: s.name for s in all_sources}

    def _base(name):
        return name.split("/")[-1] if name else name

    # Investigation bookmarks: pinned-line keys (basename, seq) + count,
    # scoped to the currently loaded log folder / workspace.
    username = session["username"]
    bm_scope = _bookmark_scope(state)
    user_bookmarks = BOOKMARKS.list(_notes_owner(state), bm_scope)
    # New bookmarks identify a line by its unique source_id; legacy ones only
    # carry a (possibly duplicate) basename. Track both: exact for new, best-
    # effort for old.
    pinned_ids = set()
    pinned_names = set()

    def _index_pin(rec):
        try:
            seq_ = int(rec.get("seq", -1))
        except (TypeError, ValueError):
            return
        sid_ = rec.get("srcid")
        if sid_ is not None:
            try:
                pinned_ids.add((int(sid_), seq_))
                return
            except (TypeError, ValueError):
                pass
        pinned_names.add((rec.get("source", ""), seq_))

    for _b in user_bookmarks:
        _index_pin(_b)
        for _m in (_b.get("members") or []):
            _index_pin(_m)
    bookmark_count = len(user_bookmarks)
    workspace_ctx = state.get("loaded_from") or ""

    # "Jump to line": enter a log-line substring to jump straight to a matching
    # line in its natural place in the timeline (no synthetic context window).
    # jumpn selects which match.
    jump_raw = request.args.get("jump", "").strip()
    # ``jumpn`` explicitly selects a match to navigate to (F3 / next / prev,
    # 1-based). When it is absent, a fresh search lands on the first match
    # at/after the page the user is currently on (``jnear``) — so Ctrl+F from
    # page 10 highlights the match there and reports its true global index
    # (e.g. 100 / total) instead of jumping to match #1 on page 1.
    jump_n = request.args.get("jumpn", type=int)
    jump_near = request.args.get("jnear", type=int)
    # Precise bookmark navigation: locate a line by its unique source_id when
    # available (locsrcid), else by basename (legacy) disambiguated by line text.
    loc_srcid = request.args.get("locsrcid", type=int)
    loc_src = request.args.get("locsrc", "").strip()
    loc_seq = request.args.get("locseq", type=int)
    loc_text = request.args.get("loctext", "").strip()
    # Minimum-severity filter (error|warn|info|debug|"").
    level_raw = request.args.get("level", "").strip().lower()
    level_stats = {"error": 0, "warn": 0, "info": 0, "debug": 0}
    # Filled by _context_window: total matching lines + which one is resolved.
    jump_info = {"total": 0, "n": 1}

    def _page_at(records, idx):
        """The natural paginated page that holds record ``idx``, plus the offset
        of ``idx`` within that page — so the line is shown exactly where it sits
        in the normal view rather than in a repositioned window."""
        if page_size and page_size > 0:
            target_page = idx // page_size + 1
            return (paginate(records, target_page, page_size),
                    idx - (target_page - 1) * page_size)
        return paginate(records, 1, None), idx

    def _context_window(records):
        """Return (page, match_offset) for the jump_n-th line matching jump_raw
        in its natural page, or (None, None) if none. Records the total match
        count and resolved index for the navigator."""
        needle = jump_raw.casefold()
        matches = [i for i, r in enumerate(records) if needle in r.text.casefold()]
        jump_info["total"] = len(matches)
        if not matches:
            return None, None
        if jump_n is not None:
            n = jump_n                                  # explicit navigation
        elif jump_near and page_size:
            near_idx = (jump_near - 1) * page_size      # first record on the user's page
            n = next((k + 1 for k, mi in enumerate(matches) if mi >= near_idx), 1)
        else:
            n = 1
        if n < 1:
            n = len(matches)          # wrap to last
        elif n > len(matches):
            n = 1                     # wrap to first
        jump_info["n"] = n
        idx = matches[n - 1]
        return _page_at(records, idx)

    def _locate_window(records):
        """Find a bookmarked line for 'go to line'. Prefers the exact source_id
        (unique); falls back to basename + line text for legacy bookmarks."""
        if loc_seq is None:
            return None, None
        idx = None
        if loc_srcid is not None:
            for i, r in enumerate(records):
                if r.source_id == loc_srcid and r.seq == loc_seq:
                    idx = i
                    break
        elif loc_src:
            cands = [i for i, r in enumerate(records)
                     if r.seq == loc_seq
                     and _base(name_map.get(r.source_id, "")) == loc_src]
            if loc_text and len(cands) > 1:
                needle = loc_text[:80]
                exact = [i for i in cands if records[i].text.strip().startswith(needle)]
                cands = exact or cands
            idx = cands[0] if cands else None
        if idx is None:
            return None, None
        return _page_at(records, idx)

    jump_found = False
    # Bookmark-locate diagnostics for the notes navigator: does the target's
    # source exist in this workspace, and is it currently in the selection?
    locate_active = loc_seq is not None and (loc_srcid is not None or bool(loc_src))
    locate_src_id = loc_srcid
    if locate_src_id is None and loc_src:
        for _sid, _s in state["sources"].items():
            if _base(_s.name) == loc_src:
                locate_src_id = _sid
                break
    locate_selected = (locate_src_id in selected_ids) if locate_src_id is not None else False
    locate_found = False

    if mode == "separate":
        # Tabbed: show one selected file at a time via clickable file buttons.
        active_src = request.args.get("active", type=int)
        if active_src is None or active_src not in selected_ids:
            active_src = selected[0].source_id if selected else None
        panels = []
        if jump_raw and selected:
            # Global search in the separate view hunts across EVERY selected
            # file (not just the open one) — like the merged view does — then
            # switches to the file that holds the jump_n-th match. Matches are
            # ordered file-by-file (selection order), then by line.
            needle = jump_raw.casefold()
            hits = []                 # (source, local index within its filtered recs)
            per_src = {}              # source_id -> (recs_before_level, recs_after_level)
            for s in selected:
                recs_tq = filter_by_text(filter_records(s.records, start, end), q_raw, qmode)
                recs_lv = filter_by_level(recs_tq, level_raw)
                per_src[s.source_id] = (recs_tq, recs_lv)
                for i, r in enumerate(recs_lv):
                    if needle in r.text.casefold():
                        hits.append((s, i))
            jump_info["total"] = len(hits)
            if hits:
                n = jump_n if jump_n is not None else 1
                if n < 1:
                    n = len(hits)                 # wrap to last
                elif n > len(hits):
                    n = 1                         # wrap to first
                jump_info["n"] = n
                win_src, win_idx = hits[n - 1]
                active_src = win_src.source_id    # follow the match to its file
                recs_tq, recs_lv = per_src[active_src]
                level_stats = level_counts(recs_tq)
                pg, match_offset = _page_at(recs_lv, win_idx)
                jump_found = True
                panels.append({"source": win_src, "page": pg, "match_offset": match_offset})
            elif active_src is not None:
                # No match in any selected file — keep the open file, shown plainly.
                s = state["sources"][active_src]
                recs_tq, recs_lv = per_src[active_src]
                level_stats = level_counts(recs_tq)
                pg = paginate(recs_lv, page, page_size)
                panels.append({"source": s, "page": pg, "match_offset": None})
        elif active_src is not None:
            s = state["sources"][active_src]
            recs = filter_records(s.records, start, end)
            recs = filter_by_text(recs, q_raw, qmode)
            level_stats = level_counts(recs)
            recs = filter_by_level(recs, level_raw)
            match_offset = None
            if loc_seq is not None and (loc_srcid is not None or loc_src):
                pg, match_offset = _locate_window(recs)
                if pg is None:
                    pg = Page(records=[], page=1, page_size=1, total=0, total_pages=1)
                else:
                    locate_found = True
            else:
                pg = paginate(recs, page, page_size)
            panels.append({"source": s, "page": pg, "match_offset": match_offset})
        rendered = None
        merged_page = None
    else:
        active_src = None
        # Merge (a full cross-source sort) is the costliest step. Cache the
        # sorted all-source timeline for this exact source set and reuse it for
        # paging / jumping / filter tweaks instead of re-sorting every request.
        srcs = state["sources"]
        if state.get("_merge_obj") is not srcs or state.get("_merge_len") != len(srcs):
            state["_all_merged"] = merge_records(srcs.values())
            state["_merge_obj"] = srcs
            state["_merge_len"] = len(srcs)
        if len(selected_ids) >= len(srcs):
            merged = state["_all_merged"]
        else:
            sel_set = set(selected_ids)
            merged = [r for r in state["_all_merged"] if r.source_id in sel_set]
        merged = filter_records(merged, start, end)
        merged = filter_by_text(merged, q_raw, qmode)
        level_stats = level_counts(merged)
        merged = filter_by_level(merged, level_raw)
        merged_match = None
        if jump_raw:
            merged_page, merged_match = _context_window(merged)
            if merged_page is None:
                merged_page = paginate(merged, page, page_size)
            else:
                jump_found = True
        elif loc_seq is not None and (loc_srcid is not None or loc_src):
            merged_page, merged_match = _locate_window(merged)
            if merged_page is None:
                merged_page = Page(records=[], page=1, page_size=1, total=0, total_pages=1)
            else:
                locate_found = True
        else:
            merged_page = paginate(merged, page, page_size)
        rendered = [
            {
                "ts": format_canonical(r.epoch) if r.epoch is not None else "",
                "muted": (not r.has_own_ts),
                "color": color_map.get(r.source_id, "#888"),
                "name": name_map.get(r.source_id, "?"),
                "text": r.text,
                "level": r.level,
                "src": _base(name_map.get(r.source_id, "?")),
                "srcid": r.source_id,
                "seq": r.seq,
                "epoch": (r.epoch if r.epoch is not None else ""),
                "pinned": ((r.source_id, r.seq) in pinned_ids
                           or (_base(name_map.get(r.source_id, "?")), r.seq) in pinned_names),
                "match": (merged_match is not None and i == merged_match),
            }
            for i, r in enumerate(merged_page.records)
        ]
        panels = None

    # Pre-merged link parameter sets (include the compact selection) so the
    # template can build pager / file-switcher / export URLs safely.
    pager_base = {"mode": mode, "start": start_raw, "end": end_raw, "q": q_raw,
                  "qmode": qmode, "page_size": page_size, "active": active_src,
                  "lgset": legend_ids_str, "level": level_raw}
    pager_base.update(sel_kwargs)
    sep_base = {"mode": "separate", "start": start_raw, "end": end_raw, "q": q_raw,
                "qmode": qmode, "page_size": page_size, "lgset": legend_ids_str,
                "level": level_raw}
    sep_base.update(sel_kwargs)
    export_base = {"mode": mode, "start": start_raw, "end": end_raw, "q": q_raw,
                   "qmode": qmode, "active": active_src, "level": level_raw,
                   "lgset": legend_ids_str}
    export_base.update(sel_kwargs)

    # Category “template” chips: Logs + each present non-log group (conf, xml,
    # db, pid, …). Each opens that group on its own, shown separately.
    _catfilt = {"start": start_raw, "end": end_raw, "q": q_raw, "qmode": qmode,
                "level": level_raw, "page_size": page_size}
    logs_url = url_for("view", **_catfilt)
    categories = []
    active_cat_label = "Logs"
    for _key, _label, _icon in _CAT_META:
        _n = cat_counts.get(_key, 0)
        if _n:
            categories.append({"key": _key, "label": _label, "icon": _icon,
                               "count": _n,
                               "url": url_for("view", cat=_key, **_catfilt)})
            if _key == active_cat:
                active_cat_label = _label

    # A results-only fragment (frag=1) keeps AJAX / "go to line" responses
    # tiny — no controls, no 600-source list — so the client renders instantly.
    template = "_results.html" if request.args.get("frag") == "1" else "view.html"
    return render_template(
        template,
        all_sources=all_sources,
        selected_ids=selected_ids,
        mode=mode,
        start_raw=start_raw,
        end_raw=end_raw,
        q_raw=q_raw,
        qmode=qmode,
        page_size=page_size,
        paginate_enabled=PAGINATE,
        presets=PRESETS,
        active_preset=active_preset,
        legend_ids=legend_ids,
        legend_ids_str=legend_ids_str,
        legend_candidates=legend_candidates,
        all_selected=(len(selected_ids) == len(all_sources)),
        show_others=show_others,
        other_count=other_count,
        log_count=log_count,
        categories=categories,
        active_cat=active_cat,
        active_cat_label=active_cat_label,
        logs_url=logs_url,
        loaded_workspace=state.get("loaded_from"),
        jump_raw=jump_raw,
        jump_found=jump_found,
        jump_total=jump_info["total"],
        jump_n=jump_info["n"],
        locate_active=locate_active,
        locate_found=locate_found,
        locate_src_id=locate_src_id,
        locate_selected=locate_selected,
        level=level_raw,
        level_stats=level_stats,
        level_order=LEVEL_ORDER,
        bookmark_count=bookmark_count,
        pinned_ids=pinned_ids,
        pinned_names=pinned_names,
        pager_base=pager_base,
        sep_base=sep_base,
        export_base=export_base,
        panels=panels,
        active_src=active_src,
        separate_sources=selected,
        rendered=rendered,
        merged_page=merged_page,
        color_map=color_map,
        name_map=name_map,
        format_canonical=format_canonical,
    )


@app.route("/export")
def export():
    """Download the current view's lines (merged or a single file), honouring
    the active source selection, timestamp range, and text query. The full
    filtered result is exported regardless of pagination."""
    sid = _get_session_id()
    state = _current(sid)
    if not state or not state.get("sources"):
        flash("Upload some logs first.", "info")
        return redirect(url_for("index"))

    sel = _resolve_selection(state, request.args, flash_errors=False)
    mode = sel["mode"]
    start, end, q_raw = sel["start"], sel["end"], sel["q_raw"]
    qmode = sel["qmode"]
    level_raw = request.args.get("level", "").strip().lower()
    name_map = {s.source_id: s.name for s in sel["all_sources"]}
    fmt = request.args.get("format", "txt").lower()
    if fmt not in ("txt", "csv"):
        fmt = "txt"

    if mode == "separate":
        active_src = request.args.get("active", type=int)
        if active_src is None or active_src not in sel["selected_ids"]:
            active_src = sel["selected"][0].source_id if sel["selected"] else None
        records = []
        if active_src is not None:
            recs = filter_records(state["sources"][active_src].records, start, end)
            recs = filter_by_text(recs, q_raw, qmode)
            records = filter_by_level(recs, level_raw)
        base = name_map.get(active_src, "log").rsplit("/", 1)[-1]
        stem = f"{base}"
    else:
        merged = merge_records(sel["selected"])
        merged = filter_records(merged, start, end)
        merged = filter_by_text(merged, q_raw, qmode)
        records = filter_by_level(merged, level_raw)
        stem = "merged"

    def generate():
        if fmt == "csv":
            import csv
            import io
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["timestamp", "source", "message"])
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)
            for r in records:
                ts = format_canonical(r.epoch) if r.epoch is not None else ""
                writer.writerow([ts, name_map.get(r.source_id, ""), r.text])
                yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        else:
            merged_mode = (mode != "separate")
            for r in records:
                ts = format_canonical(r.epoch) if r.epoch is not None else ""
                if merged_mode:
                    yield f"{ts}\t[{name_map.get(r.source_id, '')}]\t{r.text}\n"
                else:
                    yield f"{ts}\t{r.text}\n"

    ts_now = time.strftime("%Y%m%d-%H%M%S")
    filename = f"log-parser_{stem}_{ts_now}.{fmt}"
    mimetype = "text/csv" if fmt == "csv" else "text/plain"
    return Response(
        generate(), mimetype=mimetype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/reset")
def reset():
    sid = _get_session_id()
    prev = _SESSIONS.pop(sid, None)
    if prev and os.path.isdir(prev["dir"]):
        shutil.rmtree(prev["dir"], ignore_errors=True)
    flash("Cleared. Upload new logs.", "info")
    return redirect(url_for("index"))


# --- Saved workspaces (per-user persistent storage) -----------------------------

def _register_named_sources(sid: str, pairs: list[tuple[str, str]]) -> None:
    """Register sources from explicit (display_name, path) pairs (used on load)."""
    cfg = _parser_config()
    sources: dict[int, LogSource] = {}
    for idx, (name, path) in enumerate(pairs):
        src = LogSource(source_id=idx, name=name, path=path, color=color_for(idx))
        try:
            parse_source(src, cfg)
        except OSError:
            continue
        src.is_log = classify_is_log(src.name, src.line_count, src.parsed_count)
        src.category = file_category(src.name, src.is_log)
        sources[idx] = src
    _SESSIONS[sid]["sources"] = sources


@app.route("/workspace/save", methods=["POST"])
def workspace_save():
    username = session["username"]
    sid = _get_session_id()
    state = _current(sid)
    if not state or not state.get("sources"):
        flash("Nothing to save yet \u2014 load and analyze some logs first.", "error")
        return redirect(url_for("index"))

    name = request.form.get("name", "").strip()
    overwrite = request.form.get("overwrite") == "1"
    if not ws_slugify(name):
        flash("Enter a workspace name using letters or digits.", "error")
        return redirect(url_for("view"))

    sources = [(s.name, s.path)
               for s in sorted(state["sources"].values(), key=lambda s: s.source_id)]
    try:
        slug = WORKSPACES.save(username, name, sources, overwrite=overwrite)
    except WorkspaceError as exc:
        flash(str(exc), "error")
        return redirect(url_for("view"))
    # Notes pinned on the fresh upload live under an "up:<hash>" scope; migrate
    # them into this workspace's scope so they travel with it when it is
    # reloaded (and stay visible in the current session). Compute the old scope
    # BEFORE marking the session as a saved workspace below.
    new_scope = "ws:" + name
    old_scope = _bookmark_scope(state)
    try:
        BOOKMARKS.rescope(username, old_scope, new_scope)
        NOTEPAD.rescope(username, old_scope, new_scope)
    except Exception:  # noqa: BLE001
        app.logger.warning("Note migration on workspace save failed for %s", username)
    state["loaded_from"] = name
    state["ws_owner"] = username
    state["ws_scope"] = new_scope
    state["ws_name"] = name
    flash(f"Saved workspace '{slug}'.", "info")
    return redirect(url_for("index"))


@app.route("/workspace/<slug>/load")
def workspace_load(slug):
    username = session["username"]
    sid = _get_session_id()
    try:
        meta = WORKSPACES.get(username, slug)
        if meta is None:
            flash("Workspace not found.", "error")
            return redirect(url_for("index"))
        workdir = _reset_workdir(sid)
        dest = os.path.join(workdir, "loaded")
        pairs = WORKSPACES.materialize(username, slug, dest)
    except WorkspaceError as exc:
        flash(f"Could not load workspace: {exc}", "error")
        return redirect(url_for("index"))
    _register_named_sources(sid, pairs)
    # Mark this session as viewing an already-saved workspace so the view hides
    # the "Save workspace" control, and pin the notes scope/owner to this
    # workspace so its notes travel with it (and are shared with recipients).
    name = meta.get("name") or slug
    st = _SESSIONS[sid]
    st["loaded_from"] = name
    st["ws_owner"] = username
    st["ws_scope"] = "ws:" + name
    st["ws_name"] = name
    logs, others = _split_counts(sid)
    msg = f"Loaded workspace '{slug}' \u2014 {logs} log file(s)"
    msg += f" (+{others} non-log)." if others else "."
    flash(msg, "info")
    return redirect(url_for("view"))


@app.route("/workspace/<slug>/delete", methods=["POST"])
def workspace_delete(slug):
    username = session["username"]
    try:
        WORKSPACES.delete(username, slug)
        flash(f"Deleted workspace '{slug}'.", "info")
    except WorkspaceError as exc:
        flash(f"Could not delete workspace: {exc}", "error")
    return redirect(url_for("index"))


@app.route("/workspace/<slug>/rename", methods=["POST"])
def workspace_rename(slug):
    """Rename one of the caller's own saved workspaces."""
    username = session["username"]
    meta = WORKSPACES.get(username, slug)
    if meta is None:
        flash("Workspace not found.", "error")
        return redirect(url_for("index"))
    new_name = request.form.get("name", "").strip()
    if not ws_slugify(new_name):
        flash("Enter a workspace name using letters or digits.", "error")
        return redirect(url_for("index"))
    old_name = meta.get("name") or slug
    try:
        new_slug = WORKSPACES.rename(username, slug, new_name)
    except WorkspaceError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))
    # Notes and the notepad are keyed by the workspace's display name
    # ("ws:<name>"), so move them across so they follow the rename.
    old_scope, new_scope = "ws:" + old_name, "ws:" + new_name
    if old_scope != new_scope:
        try:
            BOOKMARKS.rescope(username, old_scope, new_scope)
            NOTEPAD.rescope(username, old_scope, new_scope)
        except Exception:  # noqa: BLE001
            app.logger.warning("Note rescope on workspace rename failed for %s", username)
    # Keep a currently-loaded session pointing at the renamed workspace.
    st = _SESSIONS.get(_get_session_id())
    if st and st.get("ws_owner") == username and st.get("ws_name") == old_name:
        st["loaded_from"] = new_name
        st["ws_scope"] = new_scope
        st["ws_name"] = new_name
    flash(f"Renamed workspace to '{new_slug}'.", "info")
    return redirect(url_for("index"))


@app.route("/workspace/<slug>/share", methods=["POST"])
def workspace_share(slug):
    """Share one of the caller's own workspaces with other named users."""
    username = session["username"]
    if WORKSPACES.get(username, slug) is None:
        flash("Workspace not found.", "error")
        return redirect(url_for("index"))
    raw = request.form.get("usernames", "")
    targets = [t for t in re.split(r"[,\s]+", raw) if t]
    valid, unknown = [], []
    for t in targets:
        if t == username:
            continue  # sharing with yourself is a no-op
        try:
            exists = USERS.exists(t)
        except Exception:  # noqa: BLE001
            exists = False
        (valid if exists else unknown).append(t)
    if valid:
        try:
            WORKSPACES.share(username, slug, valid)
        except WorkspaceError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))
    parts = []
    if valid:
        parts.append(f"Shared '{slug}' with {', '.join(valid)}.")
    if unknown:
        parts.append(f"Skipped unknown user(s): {', '.join(unknown)}.")
    if not parts:
        parts.append("Enter at least one existing username to share with.")
    flash(" ".join(parts), "info" if valid else "error")
    return redirect(url_for("index"))


@app.route("/workspace/<slug>/unshare", methods=["POST"])
def workspace_unshare(slug):
    """Revoke one user's access to the caller's own workspace."""
    username = session["username"]
    target = request.form.get("username", "").strip()
    try:
        WORKSPACES.unshare(username, slug, target)
        flash(f"Stopped sharing '{slug}' with {target}.", "info")
    except WorkspaceError as exc:
        flash(f"Could not update sharing: {exc}", "error")
    return redirect(url_for("index"))


@app.route("/workspace/shared/<owner>/<slug>/load")
def workspace_load_shared(owner, slug):
    """Load a workspace another user has shared with the caller (read access)."""
    username = session["username"]
    sid = _get_session_id()
    try:
        meta = WORKSPACES.get(owner, slug)
    except WorkspaceError as exc:
        flash(f"Could not open shared workspace: {exc}", "error")
        return redirect(url_for("index"))
    if meta is None:
        flash("Shared workspace not found.", "error")
        return redirect(url_for("index"))
    # Authorization: only users on the workspace's share list may load it.
    if username not in (meta.get("shared_with") or []):
        flash("That workspace is not shared with you.", "error")
        return redirect(url_for("index"))
    try:
        workdir = _reset_workdir(sid)
        dest = os.path.join(workdir, "loaded")
        pairs = WORKSPACES.materialize(owner, slug, dest)
    except WorkspaceError as exc:
        flash(f"Could not load shared workspace: {exc}", "error")
        return redirect(url_for("index"))
    _register_named_sources(sid, pairs)
    name = meta.get("name") or slug
    st = _SESSIONS[sid]
    st["loaded_from"] = f"{name} (shared by {owner})"
    # Notes for a shared workspace live in the OWNER's store under the owner's
    # stable scope, so the recipient sees (and can add to) the owner's notes.
    st["ws_owner"] = owner
    st["ws_scope"] = "ws:" + name
    st["ws_name"] = name
    flash(f"Loaded shared workspace '{name}' from {owner} — {len(pairs)} source(s).", "info")
    return redirect(url_for("view"))


# ---------------------------------------------------------------------------
# Investigation bookmarks (pinned log lines + notes)
# ---------------------------------------------------------------------------
@app.route("/bookmarks")
def bookmarks_list():
    """Return the loaded folder's bookmarks for the current user as JSON."""
    state = _current(_get_session_id())
    scope = _bookmark_scope(state)
    return jsonify(bookmarks=BOOKMARKS.list(_notes_owner(state), scope))


@app.route("/bookmark/add", methods=["POST"])
def bookmark_add():
    """Pin a log line with an optional note. Upserts on (source, seq)."""
    state = _current(_get_session_id())
    owner = _notes_owner(state)
    scope = _bookmark_scope(state)
    try:
        seq = int(request.form.get("seq", "-1"))
    except (TypeError, ValueError):
        seq = -1
    epoch_raw = request.form.get("epoch", "").strip()
    try:
        epoch = float(epoch_raw) if epoch_raw else None
    except ValueError:
        epoch = None
    srcid_raw = request.form.get("srcid", "").strip()
    try:
        srcid = int(srcid_raw) if srcid_raw != "" else None
    except ValueError:
        srcid = None
    # Optional range bookmark: a list of member lines [{source, srcid, seq}, ...]
    # that are all treated as one note and highlighted together on "go to line".
    members = None
    members_raw = request.form.get("members", "").strip()
    if members_raw:
        try:
            members = []
            for m in json.loads(members_raw):
                try:
                    entry = {"source": str(m.get("source", "")),
                             "seq": int(m.get("seq"))}
                    if m.get("srcid") is not None:
                        entry["srcid"] = int(m.get("srcid"))
                    members.append(entry)
                except (TypeError, ValueError):
                    continue
            if len(members) < 2:
                members = None
        except (ValueError, TypeError):
            members = None
    bm = {
        "source": request.form.get("source", "").strip(),
        "srcid": srcid,
        "seq": seq,
        "ts": request.form.get("ts", "").strip(),
        "epoch": epoch,
        "text": request.form.get("text", "").strip(),
        "note": request.form.get("note", "").strip(),
        "color": request.form.get("color", "").strip(),
        "context": ((state.get("ws_name") or state.get("loaded_from")) if state else "") or "",
        "scope": scope,
        "members": members,
    }
    rec = BOOKMARKS.add(owner, bm)
    return jsonify(ok=True, bookmark=rec,
                   count=len(BOOKMARKS.list(owner, scope)))


@app.route("/bookmark/update", methods=["POST"])
def bookmark_update():
    """Edit the note on an existing bookmark."""
    state = _current(_get_session_id())
    bid = request.form.get("id", "").strip()
    note = request.form.get("note", "").strip()
    rec = BOOKMARKS.update(_notes_owner(state), bid, note)
    if rec is None:
        return jsonify(ok=False, error="not found"), 404
    return jsonify(ok=True, bookmark=rec)


@app.route("/bookmark/delete", methods=["POST"])
def bookmark_delete():
    """Remove a bookmark by id, or by (source, seq) when unpinning a line."""
    state = _current(_get_session_id())
    owner = _notes_owner(state)
    scope = _bookmark_scope(state)
    bid = request.form.get("id", "").strip()
    if bid:
        BOOKMARKS.delete(owner, bid)
    else:
        src = request.form.get("source", "").strip()
        try:
            seq = int(request.form.get("seq", "-1"))
        except (TypeError, ValueError):
            seq = -1
        srcid_raw = request.form.get("srcid", "").strip()
        try:
            srcid = int(srcid_raw) if srcid_raw != "" else None
        except ValueError:
            srcid = None
        BOOKMARKS.delete_by_line(owner, src, seq, scope, srcid)
    return jsonify(ok=True, count=len(BOOKMARKS.list(owner, scope)))


@app.route("/notepad")
def notepad_get():
    """Return the freeform notepad text for the currently loaded workspace."""
    state = _current(_get_session_id())
    scope = _bookmark_scope(state)
    pad = NOTEPAD.get(_notes_owner(state), scope)
    return jsonify(ok=True, has_scope=bool(scope),
                   text=pad.get("text", ""), updated_at=pad.get("updated_at", ""))


@app.route("/notepad", methods=["POST"])
def notepad_save():
    """Persist the freeform notepad text for the currently loaded workspace."""
    state = _current(_get_session_id())
    scope = _bookmark_scope(state)
    if not scope:
        return jsonify(ok=False, error="No logs loaded."), 400
    pad = NOTEPAD.set(_notes_owner(state), scope, request.form.get("text", ""))
    return jsonify(ok=True, text=pad.get("text", ""),
                   updated_at=pad.get("updated_at", ""))


@app.route("/bookmarks/export")
def bookmarks_export():
    """Download all bookmarks as Markdown, plain text, or CSV."""
    state = _current(_get_session_id())
    username = _notes_owner(state)
    fmt = request.args.get("format", "md").strip().lower()
    scope = _bookmark_scope(state)
    items = BOOKMARKS.list(username, scope)
    # Oldest-first reads better in an exported report.
    items = list(reversed(items))
    stamp = time.strftime("%Y%m%d-%H%M%S")

    if fmt == "csv":
        import csv
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["created_at", "context", "source", "timestamp",
                         "line", "note", "text"])
        for b in items:
            writer.writerow([
                b.get("created_at", ""), b.get("context", ""),
                b.get("source", ""), b.get("ts", ""), b.get("seq", ""),
                b.get("note", ""), b.get("text", ""),
            ])
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition":
                     f"attachment; filename=bookmarks-{stamp}.csv"},
        )

    if fmt == "txt":
        out = [
            f"Log investigation notes \u2014 {username}",
            f"{len(items)} bookmark(s), exported {stamp}",
            "=" * 60,
            "",
        ]
        for i, b in enumerate(items, 1):
            head = b.get("ts") or "(no timestamp)"
            out.append(f"[{i}] {head}  \u00b7  {b.get('source', '?')}")
            if b.get("context"):
                out.append(f"    workspace: {b['context']}")
            note = b.get("note", "")
            if note:
                out.append("    note:")
                for ln in (note.splitlines() or [""]):
                    out.append(f"      {ln}")
            out.append(f"    line: {b.get('text', '')}")
            out.append("")
        return Response(
            "\n".join(out),
            mimetype="text/plain",
            headers={"Content-Disposition":
                     f"attachment; filename=bookmarks-{stamp}.txt"},
        )

    lines = [f"# Log investigation notes \u2014 {username}", ""]
    lines.append(f"_{len(items)} bookmark(s), exported {stamp}_")
    lines.append("")
    for b in items:
        head = b.get("ts") or "(no timestamp)"
        src = b.get("source", "?")
        lines.append(f"## {head} · `{src}`")
        if b.get("context"):
            lines.append(f"*Workspace:* {b['context']}")
        if b.get("note"):
            lines.append("")
            for _ln in b["note"].splitlines():
                lines.append(f"> {_ln}")
        lines.append("")
        lines.append("```")
        lines.append(b.get("text", ""))
        lines.append("```")
        lines.append("")
    body = "\n".join(lines)
    return Response(
        body,
        mimetype="text/markdown",
        headers={"Content-Disposition":
                 f"attachment; filename=bookmarks-{stamp}.md"},
    )


@app.errorhandler(413)
def too_large(_err):
    flash("Upload too large — exceeds the configured size limit.", "error")
    return redirect(url_for("index")), 413


if __name__ == "__main__":
    _sweep_stale_dirs()
    print(f"\n  Log Parser running → http://localhost:{PORT}\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
