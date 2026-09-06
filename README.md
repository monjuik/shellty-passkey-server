# Shellty Passkey Server

A minimal self-hosted passkey server for existing applications.

[Website](https://monjuik.github.io/shellty-passkey-server/) ·
[Documentation](docs/) ·
[Releases](https://github.com/monjuik/shellty-passkey-server/releases) ·
[Commercial support](https://monjuik.github.io/shellty-passkey-server/#support)

One binary. One JSON configuration file. One PostgreSQL database.
Built in Go. No IAM platform and no vendor cloud.

Your application keeps its users, sessions and login decisions; Shellty handles
passkey registration and authentication.

Registration, authentication, credential management, PostgreSQL history,
native HTTPS/mTLS, embedded migrations and health/readiness.

## Quick start

You'll need Go 1.27, PostgreSQL and TLS certificates. Start with
[local development](docs/local-development.md) for database and certificate setup.
The database role needs DDL permissions for startup migrations.

Copy [config.example.json](config.example.json) to `config.json` and set your
application's RP ID, origins and client certificate fingerprint. Then, from the
repository root:

```sh
go run ./cmd/web \
  --listen :8443 \
  --config config.json \
  --database-dsn 'postgres://passkey_server:password@localhost/passkey_server?sslmode=require' \
  --tls-cert server.pem \
  --tls-key server.key \
  --client-ca client-ca.pem
```

All three TLS flags are required. Adjust the database DSN and certificate paths
to match your setup.

To build the binary:

```sh
go build -trimpath -o passkey-server ./cmd/web
```

Run `./passkey-server` with the same flags.

## API

```text
POST   /v1/registrations/start
POST   /v1/registrations/finish
POST   /v1/authentications/start
POST   /v1/authentications/finish
GET    /v1/credentials
DELETE /v1/credentials/{credential}
GET    /health
GET    /ready
```

See the [API contract](docs/api.md) for request formats, token lifecycle and errors.

## Security model

Your backend calls Shellty over mTLS and remains responsible for user authorization
and application sessions. The browser talks to your backend.

Every `/v1/*` route requires a CA-verified client certificate whose leaf fingerprint
is authorized for the requested application. `/health`, `/ready` and the optional
administration UI use HTTPS without client certificates; admin pages require a
separate login. TLS terminates in Passkey Server; HTTP proxy certificate headers
are not trusted.

Applications are immutable while the process runs. Every node must use the same
configuration and database. The RP is the browser application's domain, not the
Passkey Server host.

## Administration UI

A small optional read-only administration UI is included for configuration,
credentials and history. See [administration](docs/administration.md) to enable it
and learn how login cookies work.

## Browser demo

Want to try it end to end? `cmd/demo` is a separate local HTTPS application for
registering a passkey and testing authentication. It calls Shellty over mTLS and
needs no database of its own or frontend build step.

See [browser demo setup](docs/local-development.md#browser-demo) for the command,
certificate trust and manual test steps.

## Tests

```sh
go test ./...
TEST_DATABASE_DSN='postgres://passkey_server:password@localhost/passkey_server_test?sslmode=disable' go test -race ./...
go vet ./...
```

Integration tests create a fresh temporary schema per test and drop only that
schema on completion. The database role needs schema creation permissions.

Without `TEST_DATABASE_DSN`, PostgreSQL tests explicitly skip; unit, HTTP, native
TLS and WebAuthn adapter tests still run. An Ed25519 authenticator fixture creates
registrations and signs real assertions. No physical passkey needed.

## Documentation

- [API](docs/api.md)
- [Local development](docs/local-development.md)
- [Administration](docs/administration.md)
- [Architecture](docs/architecture.md)
- [Dependencies](docs/dependencies.md)
- [Releasing](docs/releases.md)

## Commercial support

Need help integrating Shellty into an existing backend, IAM or private environment?

[Commercial support →](https://github.com/monjuik/shellty-passkey-server/discussions)

## License

[Apache License 2.0](LICENSE).
