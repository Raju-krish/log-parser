## ADDED Requirements

### Requirement: Save a parsed upload as a named workspace
The system SHALL allow an authenticated user, after uploading and parsing logs, to save the current set of sources as a workspace identified by a user-provided name, persisting the raw source files and a manifest under that user's private storage.

#### Scenario: User saves the current parse
- **WHEN** a user with parsed sources enters a valid workspace name and confirms the save
- **THEN** the system stores the current sources under that name in the user's storage and confirms the save

#### Scenario: Empty or invalid name is rejected
- **WHEN** a user attempts to save with an empty name or a name that reduces to no safe characters
- **THEN** the system refuses the save and prompts for a valid name

#### Scenario: Name collides with an existing workspace
- **WHEN** a user saves using a name that already exists in their storage
- **THEN** the system does not silently overwrite and instead prompts the user to choose a different name or confirm replacement

#### Scenario: Saving with no parsed sources
- **WHEN** a user triggers save without any parsed sources in the current session
- **THEN** the system refuses the save with a message that there is nothing to save

### Requirement: Keep each user's workspaces private
The system SHALL store and list workspaces per user, derive the acting user's identity from the authenticated session, and SHALL NOT allow any user to list, load, or delete another user's workspaces.

#### Scenario: A user only sees their own workspaces
- **WHEN** a user views their home page
- **THEN** the system lists only workspaces stored under that user's identity

#### Scenario: Cross-user access is prevented
- **WHEN** a user requests to load or delete a workspace that belongs to another user
- **THEN** the system refuses the request and does not reveal the other user's data

### Requirement: List saved workspaces on the home page
The system SHALL present, after login, a home page listing the signed-in user's saved workspaces with at least the workspace name, creation date, number of sources, and size, plus actions to load or delete each. The home page SHALL also provide the upload option (archive, multiple files, or server-side path) so the user can start a new parse without leaving the page.

#### Scenario: Returning user sees prior work
- **WHEN** a user who has saved workspaces logs in
- **THEN** the home page lists each saved workspace with its name, date, source count, and size

#### Scenario: Upload option available on the home page
- **WHEN** a logged-in user is on the home page
- **THEN** the home page presents the upload option so they can start a new parse in addition to their saved workspaces

#### Scenario: New user sees an empty state
- **WHEN** a user with no saved workspaces logs in
- **THEN** the home page shows an empty state that leads with the upload option to parse logs

### Requirement: Load a saved workspace
The system SHALL allow a user to load one of their saved workspaces, restoring its sources into the viewer so they can be viewed separately or merged exactly as after a fresh upload.

#### Scenario: User loads a saved workspace
- **WHEN** a user selects Load on one of their workspaces
- **THEN** the system registers that workspace's sources for the session and shows them in the viewer

### Requirement: Delete a saved workspace
The system SHALL allow a user to delete one of their saved workspaces, removing its stored files and reclaiming the space it used.

#### Scenario: User deletes a workspace
- **WHEN** a user confirms deletion of one of their workspaces
- **THEN** the system removes it from storage, it no longer appears on the home page, and the freed space is reflected in the user's usage

### Requirement: Enforce a per-user storage quota
The system SHALL enforce a configurable per-user storage quota (default 500 MB) by refusing a save that would cause the user's total stored size to exceed the quota, and SHALL show the user's current usage relative to the quota.

#### Scenario: Save within quota succeeds
- **WHEN** a save would keep the user's total stored size at or below the quota
- **THEN** the system stores the workspace

#### Scenario: Save exceeding quota is refused
- **WHEN** a save would push the user's total stored size above the quota
- **THEN** the system refuses the save and reports the current usage and the limit, storing nothing

#### Scenario: Usage is visible
- **WHEN** a user views their home page
- **THEN** the system shows how much of the quota is currently used

### Requirement: Store workspaces at safe, contained paths
The system SHALL sanitize workspace names into safe directory names and SHALL verify that the resolved storage path stays within the acting user's storage root before creating, loading, or deleting any workspace.

#### Scenario: Traversal in a workspace name is contained
- **WHEN** a user supplies a workspace name containing path-traversal characters such as `../`
- **THEN** the system sanitizes the name so the resolved path remains inside the user's storage root and never writes outside it
