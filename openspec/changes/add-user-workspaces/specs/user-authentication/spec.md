## ADDED Requirements

### Requirement: Restrict access to known users
The system SHALL authenticate users against a local credential file (`users.json`, an array of `{username, pass_hash}` imported from the shared `db.json`) and SHALL allow only usernames present in that local copy to sign in. The system SHALL NOT read the shared `db.json` at runtime.

#### Scenario: Known user signs in with correct password
- **WHEN** a user submits a username that exists in the store together with the matching password
- **THEN** the system establishes an authenticated session and redirects the user to their home page

#### Scenario: Unknown username is rejected
- **WHEN** a user submits a username that is not present in the credential store
- **THEN** the system refuses the login and shows a generic invalid-credentials message without revealing whether the username exists

#### Scenario: Wrong password is rejected
- **WHEN** a user submits a valid username with an incorrect password
- **THEN** the system refuses the login and does not establish a session

### Requirement: Verify passwords against stored SHA-256 hashes
The system SHALL verify a submitted password by computing its SHA-256 hex digest and comparing it, using a constant-time comparison, against the stored `pass_hash`. The system SHALL NOT modify, rehash, or expose stored password hashes.

#### Scenario: Password matching the stored hash is accepted
- **WHEN** the SHA-256 hex digest of the submitted password equals the stored `pass_hash` for that username
- **THEN** the system treats the credentials as valid

#### Scenario: Hashes are never exposed
- **WHEN** any page or error response is rendered
- **THEN** no password hash from the credential store appears in the response

### Requirement: Require authentication for all tool routes
The system SHALL require an authenticated session for every route except the login route and static assets, and SHALL redirect unauthenticated requests to the login page, preserving the originally requested location for redirect after a successful login.

#### Scenario: Unauthenticated request is redirected to login
- **WHEN** an unauthenticated user requests the home page, an upload, a view, or an export
- **THEN** the system redirects them to the login page instead of serving the resource

#### Scenario: Redirect back after login
- **WHEN** an unauthenticated user is redirected to login from a specific page and then signs in successfully
- **THEN** the system sends them to the originally requested page

### Requirement: Log out
The system SHALL provide a logout action that clears the authenticated session so that subsequent requests require signing in again.

#### Scenario: User logs out
- **WHEN** an authenticated user triggers logout
- **THEN** the system clears the session and any further access to tool routes redirects to login

### Requirement: Throttle repeated failed logins
The system SHALL limit repeated failed login attempts for a given username and client, temporarily refusing further attempts after a configurable threshold within a time window.

#### Scenario: Repeated failures are temporarily locked out
- **WHEN** the number of consecutive failed login attempts for a username/client exceeds the configured threshold within the window
- **THEN** the system refuses further attempts for that username/client until the lockout period elapses

#### Scenario: Successful login resets the counter
- **WHEN** a user logs in successfully before reaching the threshold
- **THEN** the failed-attempt counter for that username/client is reset
