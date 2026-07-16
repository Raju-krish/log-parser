## Why

The Log Parser is currently an anonymous, single-session tool: anyone who can reach the port can use it, and every parsed upload is discarded when the session ends or a new upload replaces it. The team needs access limited to known engineers and needs their parsed log sets to persist so earlier debugging work can be reopened instead of re-uploaded and re-parsed.

## What Changes

- Require **login** before any part of the tool is usable. Credentials are validated against a **local copy of the allowed users** (`users.json`, an array of `{username, pass_hash}`) that is imported once from the shared `iimt-block/data/db.json`; the tool never reads the shared file at runtime. Only those users may sign in. **BREAKING**: all existing routes now require an authenticated session.
- Add a **home page** shown after login that lists the signed-in user's previously saved work (name, date, number of sources, size) with actions to load or delete each, **and keeps the existing upload option** on the same page so a user can start a new parse.
- After a user uploads and parses logs, let them **save the result as a named workspace** (a "directory name"); the raw sources are persisted under that user's private storage so they can be reopened later.
- Add **Load** to reopen a saved workspace directly into the existing separate/merge viewer, and **Delete** to remove one.
- Enforce a **per-user storage quota of 500 MB**; saving is refused when it would exceed the limit, and current usage is shown on the home page.
- Add **logout** and session hardening; passwords are verified against the stored SHA-256 hashes without ever exposing them.

## Capabilities

### New Capabilities
- `user-authentication`: Gate the whole tool behind a login that validates username + password against a local copy of the allowed-users list (`users.json`, SHA-256 hashes) imported from the shared `db.json`, maintains an authenticated session for every route, supports logout, and throttles repeated failed attempts.
- `saved-workspaces`: Persist a parsed upload as a named, per-user workspace; list a user's saved workspaces on a home page; load one back into the viewer; delete one; and enforce a per-user storage quota.

### Modified Capabilities
<!-- None. The tool's original behavior was never written to openspec/specs/, so there is no existing spec to modify. Ingestion, timestamp normalization, merge, filtering, and export behavior are unchanged; they are simply now reached through an authenticated session and can be sourced from a saved workspace. -->

## Impact

- New Python module for the user store + password verification; new auth routes (`/login`, `/logout`) and a login-required guard applied to all existing routes (`/`, `/upload`, `/select`, `/view`, `/export`, `/reset`).
- `/` (index) is repurposed into the per-user **home page** that shows both the user's saved workspaces and the existing upload form (upload also remains reachable at `/upload`).
- New persistent storage tree (`LOG_PARSER_DATA_ROOT/<user>/<workspace>/`) with a per-workspace `manifest.json`; new save/load/delete routes; quota accounting.
- New/updated templates: `login.html`, `home.html`, a save control on `view.html`, and a logout link in `base.html`.
- New configuration: local users-file path (`users.json`), data root, per-user quota (default 500 MB), a stable session secret, and session-cookie hardening flags.
- Adds a local `users.json` (copied from the shared `db.json`, gitignored) as the runtime credential source; the shared `db.json` is read **only once** to seed it and is never modified. No change to the existing SHA-256 hashing scheme. Security note: unsalted SHA-256 is weak, so login throttling and cookie hardening are added, and workspace names are sanitized against path traversal.
