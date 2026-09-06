# Administration

The optional administration UI is read-only and served by the same HTTPS binary
at `/admin/`. It needs no client certificate. The integration API at `/v1/*`
continues to require an authorized mTLS certificate; an admin cookie cannot
replace it.

## Enable and sign in

Configure the existing `admin` section:

```json
{
  "admin": {
    "enabled": true,
    "username": "admin",
    "passwordHash": "<bcrypt hash of your password>"
  }
}
```

Keep the `applications` section in your configuration. Generate a bcrypt hash
with a password-hashing tool, for example `htpasswd -nBC 12 admin` (Apache tools).
It prompts for the password; copy only the hash after `admin:` into
`passwordHash`. Passwords must be at most 72 UTF-8 bytes; the login form does
not silently truncate longer passwords.

Restart the server and open `https://<server>:8443/admin/` using a trusted server
certificate. Sign in with the configured username and password. Login and logout
forms require a matching HTTPS Origin; proxy certificate headers are not used.
The per-node login limiter allows an initial five attempts and refills one attempt
every 12 seconds, up to five. Excess attempts return 429 with `Retry-After`.

When `admin.enabled=false`, all `/admin/*` routes, including login and styles,
return 404. There is no default password.

## Pages

- **Configuration** shows applications in the loaded configuration. The admin hash is never shown.
- **Credentials** lists the newest keys first. Application and exact Subject are
  optional filters. Select a Subject to view the corresponding credential and its linked events.
- **Credential** shows metadata and a paginated history for that key. The link
  **History for this subject** shows events for its application and subject,
  including failed attempts and operation starts without a credential ID.
- **History** shows the newest events first, with optional Application, exact
  Subject, From and To filters. Dates use UTC and include the entire selected days.
  Both dates can be omitted. `credential=<UUID>` is supported as a contextual
  query filter, with no separate input field. Events do not have detail pages.

Lists show **20 records** per page with Previous / Next. Filters are stored in
URLs and applying them starts at the first page. Cursor pagination uses UUID order
for credentials and timestamp plus UUID for history. Lists are live views, not
snapshots: newly inserted events appear when returning to the first page.

Application inputs suggest configured codes and also accept codes removed from
the configuration, so older records remain searchable. Deleted credentials retain
their history, but no longer have a details page. Their Subjects appear as plain text in
History. Successful finishes record a credential ID; failed attempts and starts
currently do not. Subject history is the place to investigate those failures.

All timestamps are displayed in UTC. All pages disable caching and load embedded
Pico CSS 2.1.1 and local styles. No CDN, JavaScript or frontend build is required.

## Cookie lifetime and revocation

A successful login sets a Secure, HttpOnly, SameSite=Lax cookie scoped to `/admin`
for **30 days from login**, without automatic renewal. The server verifies its
expiry and HMAC-SHA256 signature on each protected request. The signature binds
the service, format version, configured admin username and expiry. The configured
bcrypt hash is the signing secret: treat the hash as a credential, since knowing
it allows someone to mint an admin cookie.

No session records are stored in PostgreSQL or memory. A cookie survives restarts
and works across nodes with the same username and hash. Keep node clocks in sync.

**Sign out** removes the browser cookie. A previously copied cookie remains valid
until expiry. To revoke all cookies, change the configured hash or username and
restart **every node**. Rehashing the same password with a fresh bcrypt salt also
changes the signing secret. There is no per-session revocation or session list.
