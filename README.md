# Log Parser

A standalone Flask web app for correlating RDKB device logs that use
different timestamp formats. Upload an archive or multiple log files, then
view them separately or **merged** into one chronological, color-coded,
paginated timeline — with **timestamp-range filtering** and per-source toggles.

## Features

- Upload a `.tar`, `.tar.gz`/`.tgz`, or `.zip` archive **or** select multiple
  individual log files. Archives are extracted safely server-side.
- **Server-side path**: instead of (or in addition to) uploading, enter a path
  to a folder or file already on the machine. A folder loads all log files
  inside it (recursively); a file/archive is handled like an upload.
- **Nested archives**: if a `.zip` contains multiple `.tar.gz`/`.tgz` log
  bundles (e.g. one per time window), the app lists them and lets you pick
  which bundle(s) to analyze. Selecting several prefixes each source with its
  bundle time so they stay distinguishable.
- Detects the human-readable timestamp formats seen in RDKB logs and
  normalizes them to a single sortable timeline (UTC):
  - ISO 8601 — `2026-05-05T11:14:00.619Z`
  - ISO date, space/dot/all-colon — `2026-05-05 11:15:18`, `2026.05.05 11:27:31`, `1970-01-01:00:01:22:946410`
  - Bracketed ISO — `[2026-05-05 11:27:32]`
  - RDK compact — `260505-11:14:07.729256` (also after a `[OneWifi] ` tag)
  - Year-first — `1970 Jan 01 00:00:25`
  - Bracketed date / ctime (TZ optional) — `[Thu Jan  1 00:00:39 UTC 1970]`, `Tue May  5 11:14:12 2026`
  - Classic syslog — `Jan  1 00:01:03` (year assumed)
  - Compact — `20260505 111501.905999`, telemetry `2026-May-05_11-14-30`
  - Timestamps that appear after a leading `[tag] ` prefix (second column) are
    detected; two-digit boot years (`700101`) map to 1970 so they sort first.
- **Separate** view (each log in its own panel) or **Merge** view
  (chronological, stable-ordered, column-aligned).
- Per-source **color coding**, filename **badges**, and a color **legend**.
- **Timestamp-range filter** (start/end, canonical `YYYY-MM-DD HH:MM:SS`),
  a **message text filter** (case-insensitive, with match highlighting),
  and per-source show/hide toggles.
- **Source presets (templates)**: a one-click **WiFi Analysis** preset selects
  only `wifiDMCLI.txt`, `wifiHal.txt`, `wifiMgr.txt`, `wifiMon.txt`,
  `wifiWebConfig.txt`, `wifiCtrl.txt`, and `messages.txt` (matched by basename,
  so it works across bundles); an **All sources** button resets it.
- **Optional pagination** for large output (OFF by default; enable if laggy).
- **Export** the current view (merged or a single file) as `.txt` or `.csv`,
  honouring the active source selection and filters.
- **Sign-in required**: access is limited to a known set of users, and each
  user gets a **home page** listing their **saved workspaces**. After parsing,
  save the current set of logs under a name, then reload it on a later visit
  (per-user storage is capped, default 500 MB).

## Run

```bash
cd log-parser
python3 -m venv .venv && . .venv/bin/activate   # optional
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5100

## Sign in & saved workspaces

The app requires a login. Allowed users come from a **local** `users.json`
(an array of `{username, pass_hash}`, where `pass_hash` is a SHA-256 hex
digest). The app reads only this local file at runtime.

Create `users.json` once by importing from the shared credential store:

```bash
python import_users.py                       # reads ../iimt-block/data/db.json
python import_users.py /path/to/db.json       # or point at an explicit file
```

`users.json` is gitignored — never commit it. Re-run the importer whenever the
shared store changes.

Once signed in:

- The **home page** lists your saved workspaces (name, date, source count,
  size) with **Load** / **Delete**, a storage-usage bar, and the upload form.
- After uploading and parsing, use **Save workspace** on the view page to name
  and persist the current sources. **Load** reopens them later; **Delete**
  frees the space. Each user's storage is private and capped (default 500 MB).

## Run with Docker (e.g. on a Windows Server)

The app is packaged as a container so it runs the same on Windows Server,
Linux, or macOS — only Docker is required (Docker Desktop / Docker Engine).

```bash
cd log-parser
docker compose up -d --build
```

Then open `http://<server-host>:5100`.

Loading logs, two ways:

1. **Upload** an archive or files straight from your browser — works out of
   the box.
2. **Server path**: drop device logs into the `logs/` folder next to
   `docker-compose.yml`. They appear inside the container at `/data/logs`;
   type `/data/logs` into the app's “server path” box to load them. (On
   Windows the container can't see host paths like `C:\logs` directly — use
   this mounted folder, or edit the volume in `docker-compose.yml`.)

Before deploying, edit `docker-compose.yml` and set `LOG_PARSER_SECRET` to a
long random string so sessions survive restarts.

Useful commands:

```bash
docker compose logs -f        # follow logs
docker compose down           # stop and remove the container
docker compose up -d --build  # rebuild after code changes
```

> The container runs a single Gunicorn worker with multiple threads. This is
> intentional: each user's loaded logs are held in memory per process, so a
> single worker keeps every request for a session on the same state. Scale by
> giving the container more CPU/RAM rather than adding workers.

## Updating an existing deployment (keeps all saved data)

Your data is **decoupled from the code**, so pulling a new version never
removes anything you've saved:

- **Saved workspaces** live in the Docker named volume `lp-workspaces`
  (mounted at `/data/workspaces`). Rebuilding the image does **not** touch it.
- **`users.json`** and the **`logs/`** folder are bind-mounted from the host
  (and both are gitignored), so a code update can't overwrite them.

Update **in place, in the same folder** (so the volume name stays the same),
then rebuild:

```bash
cd log-parser        # the SAME folder as before
git pull
docker compose up -d --build
```

Every saved workspace, user, and log carries over.

> **Never run `docker compose down -v`.** The `-v` deletes the `lp-workspaces`
> volume and with it every saved workspace. Plain `docker compose down`
> (without `-v`) is safe, as is `up -d --build`.

**Back up first (optional, recommended):**

```bash
docker volume ls                                    # find the exact volume name
docker run --rm -v <name>_lp-workspaces:/data -v "$PWD:/backup" \
  alpine tar czf /backup/workspaces-backup.tar.gz -C /data .
```

**Fresh install on a brand-new machine (no data yet):** create an empty users
file before the first `docker compose up`, otherwise Docker creates a *folder*
where the `users.json` file is expected:

```bash
echo '{ "users": [] }' > users.json
docker compose up -d --build
```

Then sign in as an admin (a name listed in `LOG_PARSER_ADMINS`) and add users
from the Admin page.

## Configuration (environment variables)

| Variable | Default | Meaning |
|----------|---------|---------|
| `LOG_PARSER_PORT` | `5100` | HTTP port |
| `LOG_PARSER_MAX_UPLOAD` | `268435456` (256 MB) | Max upload size in bytes |
| `LOG_PARSER_PAGINATE` | `0` (off) | Set to `1` to enable pagination |
| `LOG_PARSER_PAGE_SIZE` | `500` | Default lines per page (when pagination is on) |
| `LOG_PARSER_ASSUMED_YEAR` | current year | Year used for yearless syslog lines |
| `LOG_PARSER_ALLOWED_ROOT` | _(unset)_ | If set, server-side path reads are restricted to within this directory |
| `LOG_PARSER_SECRET` | random | Flask session secret — set a stable value so logins survive restarts |
| `LOG_PARSER_USERS_DB` | `./users.json` | Path to the local allowed-users file (username + SHA-256 hash) |
| `LOG_PARSER_ADMINS` | `admin` | Comma-separated usernames granted admin rights (auto-created; set their password on first sign-in) |
| `LOG_PARSER_DATA_ROOT` | `./data` | Root directory for per-user saved workspaces |
| `LOG_PARSER_USER_QUOTA` | `524288000` (500 MB) | Per-user saved-workspace storage quota in bytes |
| `LOG_PARSER_COOKIE_SECURE` | `0` | Set to `1` to mark the session cookie Secure (serve over HTTPS) |

## Limitations / out of scope

- Kernel `dmesg` uptime timestamps (`[   12.345678]`) are **not** parsed —
  use the human-readable kernel logs in `messages.txt` / `journal_logs.txt`.
- Message text filtering is a case-insensitive substring match (not regex).
- Access requires a login; users are managed externally and imported into a
  local `users.json`. Password hashes are unsalted SHA-256 (matching the shared
  store), so keep the port on a trusted network and prefer HTTPS.
- Uploaded logs are held in an ephemeral per-session temp directory and are
  replaced on the next upload. To keep a parse, **save it as a workspace** —
  saved workspaces persist per user under `LOG_PARSER_DATA_ROOT`.
- Pre-time-sync / implausible timestamps (e.g. `-300101-...`) and bare numeric
  rotation markers are treated as having no timestamp (they inherit the
  previous line's time within their source).
