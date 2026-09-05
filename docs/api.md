# Integration API

The application's backend calls Passkey Server over native HTTPS with its client certificate.
It must authenticate the application user and authorize registration/deletion itself.
The browser talks to that backend; it must not receive the backend's private key.
Passkey Server does not issue application sessions or make account-recovery decisions.

All JSON POSTs require `Content-Type: application/json`. Bodies are limited to
96 KiB, the embedded credential response to 64 KiB, subject and displayName to
256 UTF-8 bytes. Subjects are nonempty and cannot contain U+0000 (PostgreSQL text).
Field names are case-sensitive (for example, `application` is accepted but
`Application` is rejected). Unknown JSON fields, duplicate keys, multiple JSON values, invalid UTF-8 and
nesting deeper than 32 levels are rejected. Application codes match
`[A-Za-z0-9._-]{1,64}`. Product configuration is limited to 1 MiB.

## Start registration

`POST /v1/registrations/start`

```json
{"application":"shop","subject":"customer-87231","displayName":"Customer 87231"}
```

`displayName` is optional and defaults to subject. It is used for both the
WebAuthn user name and display name, not for identity verification.

Success: `200`, with an opaque token, WebAuthn options and server expiry:

```json
{"token":"<opaque base64url token>","options":{"publicKey":{"challenge":"...","rp":{"id":"localhost","name":"Example Shop"},"user":{"id":"...","name":"Customer 87231","displayName":"Customer 87231"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}]}},"expiresAt":"2026-09-05T12:05:00Z"}
```

The example omits other generated WebAuthn fields. Forward the whole `options`
value to the browser. Use `PublicKeyCredential.parseCreationOptionsFromJSON()`
on `options.publicKey` where available, or an equivalent base64url conversion,
then call `navigator.credentials.create()`. Return the credential's JSON form
(`credential.toJSON()` where available) to the backend.

## Finish registration

`POST /v1/registrations/finish`

```json
{"token":"<registration token>","credential":{"id":"...","rawId":"...","type":"public-key","response":{"clientDataJSON":"...","attestationObject":"..."},"clientExtensionResults":{"credProps":{"rk":true}}}}
```

Success: `200`:

```json
{"application":"shop","subject":"customer-87231","credential":"019c0000-0000-7000-8000-000000000001"}
```

The returned credential identifier is a Passkey Server UUIDv7, not the authenticator's ID.
Registration requests a discoverable credential and UV, `credProps.rk=false` are not allowed. Clients must forward extension results.

## Authenticate

`POST /v1/authentications/start`

```json
{"application":"shop","subject":"customer-87231"}
```

Returns `200` with the same envelope as registration: `token`, `options` (including
WebAuthn `publicKey` request options), and `expiresAt`. No registered credentials
returns `authentication_failed`. Authentication always requires a known subject.

The browser converts `options.publicKey` with
`PublicKeyCredential.parseRequestOptionsFromJSON()` or equivalent, then calls
`navigator.credentials.get()`. Send its JSON response to:

`POST /v1/authentications/finish`

```json
{"token":"<authentication token>","credential":{"id":"...","rawId":"...","type":"public-key","response":{"clientDataJSON":"...","authenticatorData":"...","signature":"...","userHandle":"..."},"clientExtensionResults":{}}}
```

Success: `200` with `application`, `subject`, `credential`, as above.
The backend decides whether to create its own login session.

## Credential lifecycle

`GET /v1/credentials?application=shop&subject=customer-87231`

Returns `200`, `{"credentials":[...]}`. Each record contains `id`, `application`,
`subject`, `algorithm`, `signCount`, `transports`, `backupEligible`, `backupState`,
`createdAt`, and optional `usedAt`. Public keys, authenticator IDs and opaque
WebAuthn storage are not exposed. Empty results are `[]`. Results are ordered by
Passkey Server UUID. Query parameters must each occur exactly once, with no extra fields.

`DELETE /v1/credentials/{credential}?application=shop&subject=customer-87231`

Returns `204`. An unknown or differently scoped credential returns `404`.
Deletion is permanent; history remains. A subsequent finish cannot authenticate
using that deleted credential. An authentication already committed before deletion
remains a completed authentication.

## Token lifecycle and errors

Tokens contain 32 CSPRNG bytes encoded as unpadded base64url. Only SHA-256 hashes
of their encoded values are stored. Ceremonies expire after five minutes.
Registration and authentication tokens are not interchangeable. On finish, Passkey Server
resolves application/subject from the stored ceremony and verifies that the caller
is authorized for that application, including when the request reaches another node.

A valid finish attempt ends in `succeeded`, `failed` or `expired`. A completed
ceremony returns `conflict` on subsequent finishes. An invalid assertion consumes
the ceremony; start a new one. Invalid request envelopes, access failures and
infrastructure failures do not consume it. Infrastructure failures roll back the
credential, ceremony and history together. A lost success response may therefore
be followed by `conflict` on retry; this API does not promise idempotent result retrieval.

Errors have the shape `{"error":"machine_code"}`:

| HTTP | Codes |
| --- | --- |
| 400 | `invalid_request`, `registration_invalid`, `authentication_failed` |
| 403 | `forbidden` (missing certificate or unauthorized fingerprint) |
| 404 | `application_not_found`, `registration_not_found`, `authentication_not_found`, `credential_not_found` |
| 409 | `conflict` (used ceremony or duplicate credential within an RP) |
| 410 | `registration_expired`, `authentication_expired` |
| 500 | `internal_error` |

Invalid client certificates fail at the TLS handshake before an HTTP response.
Unknown routes/methods use the standard HTTP mux 404/405 responses.

`GET /health` returns `200 {"status":"ok"}`. 

`GET /ready` checks database/schema access and returns `200 {"status":"ready"}` or `503 {"status":"not_ready"}`.

All responses disable caching.
