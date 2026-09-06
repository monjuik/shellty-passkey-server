# Architecture

For developers and maintainers: the boundaries and invariants to preserve when
changing the server. Request formats belong in the [API contract](api.md);
configuration and cookie lifecycle are covered by [administration](administration.md).

## Structure and access

`passkeys` owns ceremony behavior, the WebAuthn adapter and persistence operations.
`app` composes the server, validates HTTP input and serves administration pages.
`assets` embeds versioned SQL, templates and styles into the binary. Repository
interfaces express atomic ceremony operations so transaction boundaries remain
explicit rather than being assembled by HTTP handlers.

Integration requests require native mTLS with application-specific certificate
authorization. Administration uses a separate signed cookie and read-only queries;
that cookie cannot authorize integration requests. Keeping these paths separate
prevents browser access from inheriting an application's credential-management
permissions. All nodes share the same immutable configuration and database.

## Data integrity

Credentials and user handles are scoped to applications. The database also enforces
uniqueness of `(rp_id, webauthn_id)` across applications sharing an RP, preventing
duplicate ownership of the same authenticator credential. Changing a configured
RP ID requires an explicit migration; existing credentials are not reassigned.

Finish locks its ceremony row to serialize competing uses of one token. A
transaction-scoped advisory lock on application and subject serializes credential
creation, updates and deletion across nodes, including different ceremonies for
the same user. Preserve both locks: they protect different races.

Credential changes, terminal ceremony state and the corresponding history event
commit together. Infrastructure failures roll back the transaction; expected
verification failures terminate the ceremony. This prevents a partially applied
result from surviving a retry. Expiry is evaluated on finish, without a background
expiry worker.

## WebAuthn and stored state

Credentials retain the complete library record alongside fields needed for queries.
Ceremony state is also stored intact, avoiding lossy reconstruction as library
behavior evolves. Application JSON uses `encoding/json/v2`; the WebAuthn adapter
uses `encoding/json.DefaultOptionsV1()` to preserve existing byte encoding and
field-omission semantics. Library or codec changes must preserve stored-state
compatibility and the adapter's compatibility tests.

The signature counter comes from the authenticator; it is not a server-maintained
login count. A `0 -> 0` transition is valid. A library clone warning rejects the
assertion. Registration rejects explicit `credProps.rk=false`, while absence means
unknown and is accepted. This browser-reported extension is not independent
cryptographic proof of discoverability. Backup flags are retained as metadata,
not used as trust signals.

## History and diagnostics

History records successful starts, terminal finish results and successful deletes.
Malformed requests, authorization failures, replays and infrastructure failures do
not add ceremony events. It describes committed ceremony outcomes, not every HTTP
request. Deleting a credential preserves its history.

Successful finishes and deletes link to a credential; starts and failed finishes
do not. Investigating failed attempts therefore requires application-and-subject
history rather than only the events attached to one key.

History excludes bearer tokens, raw credential responses and challenges. Request
error logs use fixed messages or stable codes, excluding panic values and arbitrary
dependency errors that might expose request data or secrets.
