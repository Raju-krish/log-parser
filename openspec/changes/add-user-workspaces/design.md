## Context

The Log Parser is a standalone Flask app (see `app.py`) that today has no concept of users. A browser session id (`sid`) stored in the Flask session cookie maps to an in-memory entry `_SESSIONS[sid] = {"dir": <tempdir>, "sources": {...}}`. Uploaded archives/files are extracted into an ephemeral `tempfile.mkdtemp()` working directory under the system temp folder, parsed into in-memory `LogSource` records, and wiped whenever a new upload arrives or after a 6-hour sweep. Nothing is persisted and nothing is access-controlled.

Two needs drive this change: (1) restrict use to a known set of engineers, and (2) let those engineers keep parsed log sets so earlier investigations can be reopened. The team maintains a shared credential store at `iimt-block/data/db.json` whose `users` array holds `{username, pass_hash, slack_user_id}`, where `pass_hash` is a 64-char hex **SHA-256** digest of the password. Rather than depend on that shared file at runtime, this change imports a **local copy** of the allowed users (username + `pass_hash` only) into the project's own `users.json` and treats it as the single runtime source of truth for who may log in. It also adds a persistent, per-user storage tier alongside the existing ephemeral working directory.

## Goals / Non-Goals

**Goals:**
- Allow only users present in the local `users.json` copy to use the tool; verify passwords against the stored SHA-256 hashes without weakening or exposing them.
- Require an authenticated session for every existing route.
- Give each user a home page listing their saved work, and the ability to save the current parse under a chosen name, reload it, and delete it.
- Keep each user's stored logs private to that user and capped at 500 MB.
- Reuse the existing ingestion/parse/merge/view pipeline unchanged; a loaded workspace feeds the same `LogSource` registry.

**Non-Goals:**
- No self-registration, password change, or admin UI — users are managed in the shared `db.json` and imported into the local `users.json` copy.
- No change to the existing hashing scheme and no writes to the shared `db.json` (the tool reads only its local copy).
- No sharing of workspaces between users and no encryption of stored logs at rest.
- No multi-tenant scaling concerns beyond a single local host (this remains a local team tool).
- No change to timestamp normalization, merge, filtering, or export behavior.

## Decisions

### Decision: Maintain a local copy of the allowed users
Import the allowed users (username + `pass_hash` only) from the shared `iimt-block/data/db.json` into the project's own `users.json` (a small one-off importer / documented step). At runtime the app loads only this local file — path configurable via `LOG_PARSER_USERS_DB`, defaulting to `./users.json` — into an in-memory `{username: pass_hash}` map, with a lazy reload when the file's mtime changes. **Why:** the user asked not to depend on the shared file directly; a local copy decouples the tool from the shared store's availability, location, and unrelated fields, and keeps the credential surface minimal (only what login needs). `users.json` is gitignored so hashes are not committed. **Alternatives:** reading the shared `db.json` live at runtime (rejected — creates a runtime coupling the user explicitly wants avoided); a full database (over-engineered for ~14 users). **Trade-off:** the local copy can drift from the shared store; re-running the importer refreshes it.

### Decision: Verify SHA-256 with constant-time comparison
On login, compute `hashlib.sha256(password.encode("utf-8")).hexdigest()` and compare it to the stored `pass_hash` (both lowercased) using `hmac.compare_digest`. **Why:** the stored hashes are unsalted SHA-256, so we must match that scheme exactly; constant-time comparison avoids timing leaks. **Trade-off:** unsalted SHA-256 is weak against offline cracking, but we cannot rehash without plaintext and must not modify the shared store. Mitigations live in the throttling and cookie decisions below. **Alternative:** upgrading to bcrypt/scrypt — rejected because it would break every other tool that reads the same `db.json`.

### Decision: Session-cookie auth with a central login-required guard
Store `username` in Flask's signed session cookie after a successful login. A `before_request` guard (with an allowlist of the `login` endpoint and static assets) redirects unauthenticated requests to `/login`, preserving the originally requested URL for a post-login redirect. Add `/login` (GET form, POST verify) and `/logout` (clears the session). **Why:** minimal, standard Flask pattern; gates routing centrally rather than per-view. **Alternative:** a decorator on each route — more error-prone (easy to forget one).

### Decision: Stable secret key + hardened cookie
Require a stable `LOG_PARSER_SECRET` (env) so sessions survive restarts; today the secret is random per process, which would log everyone out on restart. Set `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="Lax"`, and a configurable `SESSION_COOKIE_SECURE` (on when served over HTTPS). **Why:** protects the session token and mitigates cross-site use given the weak password hashes.

### Decision: Throttle failed logins
Track failed attempts per username + client IP in memory; after a threshold (e.g. 5) within a window, reject further attempts for a short lockout (e.g. 5 minutes). **Why:** unsalted SHA-256 makes online guessing the main practical risk; simple throttling raises the cost without external dependencies. **Alternative:** account lockout persisted to disk — unnecessary for a local tool.

### Decision: Persist raw sources + manifest, re-parse on load
Storage layout: `LOG_PARSER_DATA_ROOT/<user-slug>/<workspace-slug>/` containing `sources/` (the raw log files copied from the working dir) and `manifest.json` (display name, created-at, ordered source list with original relative names, per-source sizes, total size). Loading copies the stored `sources/` into a fresh working directory and runs the existing `parse_source` over them. **Why:** storing raw text is robust and future-proof — parser improvements apply to old saves — and it reuses the existing registration path (`_register_source_groups`). **Alternative:** pickling parsed `LogSource` records — brittle across code changes and larger on disk.

### Decision: Home page shows saved workspaces and the upload option together
Repurpose `/` to render, for the logged-in user, both (a) their saved workspaces (name, date, source count, size) with Load/Delete plus a quota bar, and (b) the existing upload form (archive / multi-file / server-side path). The upload POST handler is unchanged and also remains reachable at `/upload` for a focused full-page upload. **Why:** the user asked that after login they see their workspaces *and* still have the existing upload option on the same page, so both reopening prior work and starting a fresh parse are one click away. **Alternative:** upload on a separate route only — rejected because it hides the primary action behind an extra click. Empty state: when the user has no saved workspaces, the page leads with the upload form.

### Decision: Save is an explicit action from the viewer
On `view.html`, add a "Save workspace" form (a name field + submit) that POSTs to `/workspace/save`. The handler slugifies the name, checks the quota, copies the current session's raw sources into the user's storage, and writes `manifest.json`. Name collisions prompt the user to choose a new name or confirm overwrite. **Why:** the user wants to name the directory after parsing; an explicit save avoids persisting throwaway parses. **Alternative:** auto-save every upload — wastes quota on discardable work.

### Decision: Enforce the 500 MB quota at save time
`LOG_PARSER_USER_QUOTA` (default `500 * 1024 * 1024`). Before writing, sum the on-disk size of the user's existing workspaces plus the incoming size; if the total exceeds the quota, refuse the save with a message showing usage and the limit. The home page shows a usage bar. **Why:** bounds disk use per user and gives clear feedback. **Alternative:** a global cap — doesn't isolate users from each other.

### Decision: Sanitize workspace names against traversal
Slugify names to `[A-Za-z0-9._-]` (reject empty results), then verify the resolved absolute path stays within the user's storage root before any write, load, or delete — the same defense the ingestion code already uses against zip-slip. User identity for all storage operations comes from the session, never from a request parameter, so one user can never address another's directory. **Why:** untrusted names and multi-user storage are the main new attack surface.

## Risks / Trade-offs

- **Unsalted SHA-256 password hashes** → offline-crackable if the credential copy (`users.json`) or the shared `db.json` leaks. Mitigation: `users.json` is gitignored, login throttling, HttpOnly/SameSite cookie, stable secret, and a recommendation to serve over HTTPS / keep the port on a trusted network. We cannot change the scheme without breaking the shared store.
- **Local users.json missing/malformed, or drift from the shared store** → if the local copy is absent or invalid, no one can log in; if the shared store changes, the copy goes stale. Mitigation: fail closed with a clear server-log error and validate the `users` array shape on load; document re-running the importer to refresh the copy; make the path configurable.
- **Disk exhaustion from many saves** → mitigated by the per-user 500 MB quota and quota accounting before each save; deletion frees space immediately.
- **Path traversal via workspace name** → mitigated by slugging + resolved-path containment checks and session-derived user identity.
- **CSRF on state-changing POSTs (save/delete/logout)** → SameSite=Lax cookie is the baseline mitigation; a per-session CSRF token can be added if the tool is ever exposed beyond a trusted network.
- **Session loss on restart** → mitigated by requiring a stable `LOG_PARSER_SECRET`.
- **Concurrent saves by the same user in two tabs** → last-writer-wins on a same-named workspace; the slug-uniqueness check plus overwrite confirmation keeps this predictable.

## Migration Plan

- One-time import: run the importer to copy the allowed users (username + `pass_hash`) from the shared `db.json` into the local `users.json`, which is kept out of version control.
- Purely additive to deploy: set `LOG_PARSER_SECRET`, optionally `LOG_PARSER_USERS_DB` (defaults to `./users.json`), `LOG_PARSER_DATA_ROOT`, and optionally `LOG_PARSER_USER_QUOTA`, then restart. The first request now redirects to `/login`.
- No data migration — existing ephemeral behavior is unchanged; persistence is opt-in via Save.
- Rollback: revert the code and unset the new env vars; saved workspace directories can be left in place (ignored by the old build) or deleted.

## Open Questions

- Default `LOG_PARSER_DATA_ROOT` location on the target host (Raspberry Pi / NUC) and its backup story.
- On name collision, prefer overwrite-with-confirm or auto-versioned names (`name-2`)? Proposed: overwrite-with-confirm.
- Should the quota count extracted on-disk size (proposed) or original upload size?
- Should a workspace also persist the last-used filter/view state, or only the raw sources (proposed: sources only for now)?
- How should the local `users.json` be refreshed when the shared `db.json` changes — a manual importer re-run (proposed) or a scheduled sync?
