## 1. Configuration & user store

- [x] 1.1 Add config: `LOG_PARSER_USERS_DB` (path to the local `users.json`, default `./users.json`), `LOG_PARSER_DATA_ROOT`, `LOG_PARSER_USER_QUOTA` (default 500 MB), stable `LOG_PARSER_SECRET`, and session-cookie hardening flags
- [x] 1.2 Provide a one-off importer/script that copies the allowed users (username + `pass_hash`) from the shared `db.json` into the local `users.json`; gitignore `users.json`
- [x] 1.3 Implement a user-store loader that reads the `users` array from the local `users.json` into an in-memory `{username: pass_hash}` map, validates its shape, and reloads on file mtime change
- [x] 1.4 Implement `verify_password(username, password)` using SHA-256 hex digest + `hmac.compare_digest`; never log or expose hashes

## 2. Authentication & session gating

- [x] 2.1 Add `/login` GET (form) and POST (verify) routes; store `username` in the session on success
- [x] 2.2 Add `/logout` route that clears the session
- [x] 2.3 Add a `before_request` guard requiring a session for all routes except login and static, redirecting to `/login` with a post-login `next` target
- [x] 2.4 Add in-memory failed-login throttling (threshold + lockout window) keyed by username + client IP
- [x] 2.5 Set a stable secret key and `SESSION_COOKIE_HTTPONLY` / `SAMESITE` / configurable `SECURE`

## 3. Per-user persistent storage

- [x] 3.1 Define storage layout `DATA_ROOT/<user-slug>/<workspace-slug>/` with `sources/` and `manifest.json`
- [x] 3.2 Implement name slugification (`[A-Za-z0-9._-]`, reject empty) and a resolved-path containment check within the user's root
- [x] 3.3 Implement helpers to list a user's workspaces (reading manifests), compute per-workspace and total usage, and resolve a workspace by slug scoped to the session user

## 4. Save workflow

- [x] 4.1 Add a "Save workspace" form (name field) to `view.html` posting to `/workspace/save`
- [x] 4.2 Implement `/workspace/save`: validate the name, check the quota, copy current session raw sources into the user's storage, write `manifest.json`
- [x] 4.3 Handle name collisions (prompt for a new name or confirm overwrite) and the empty-selection / no-sources cases with clear messages

## 5. Home page (prior work + upload)

- [x] 5.1 Repurpose `/` into a per-user home page template (`home.html`) listing saved workspaces with name, date, source count, and size
- [x] 5.2 Include the existing upload form (archive / multi-file / server-side path) on the home page; keep the POST upload handler and a focused `/upload` GET route too
- [x] 5.3 Add a quota usage indicator (used vs. limit) and an empty state (leading with upload) for users with no saved work

## 6. Load & delete

- [x] 6.1 Implement `/workspace/<slug>/load`: copy stored sources into a fresh working dir, register them via the existing source pipeline, redirect to `/view`
- [x] 6.2 Implement `/workspace/<slug>/delete`: remove the workspace dir (scoped to the session user) and update usage
- [x] 6.3 Ensure load/delete reject slugs that resolve outside the user's storage root or belong to another user

## 7. UI integration

- [x] 7.1 Add a logout link and the signed-in username to `base.html`
- [x] 7.2 Create `login.html` with the login form and error messaging
- [x] 7.3 Link home ⇄ upload ⇄ view so a user can move between saved work and a new parse

## 8. Security & robustness

- [x] 8.1 Confirm all state-changing routes derive the user from the session, never from request params
- [x] 8.2 Verify traversal-crafted workspace names cannot escape the user's storage root
- [x] 8.3 Fail closed with a clear server-side error when db.json is missing or malformed

## 9. Manual verification

- [x] 9.1 Log in as a valid user from the local `users.json`; confirm an unknown user and a wrong password are both rejected
- [x] 9.2 Confirm unauthenticated access to `/`, `/upload`, `/view`, `/export` redirects to login and returns to the target after login
- [x] 9.3 Upload + parse, save as a named workspace, log out, log back in, and load it; confirm sources view/merge correctly
- [x] 9.4 Confirm a second user cannot see or load the first user's workspaces
- [x] 9.5 Confirm the 500 MB quota blocks an over-limit save and that usage shows on the home page
- [x] 9.6 Delete a workspace and confirm it disappears and frees usage
- [x] 9.7 Confirm a workspace name with `../` cannot write outside the user's storage root
