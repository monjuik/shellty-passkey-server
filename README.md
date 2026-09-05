# Shellty Passkey Server

A minimal self-hosted passkey server for existing applications.

One binary. One JSON configuration file. One PostgreSQL database.
Built in Go. No IAM platform and no vendor cloud.

## First iteration

The core implements registration, authentication, credential listing/deletion,
PostgreSQL history, native HTTPS/mTLS, embedded migrations, and health/readiness.
The read-only administration UI and admin sessions belong to the next iteration;
startup currently requires `admin.enabled=false`. This is not the complete 0.9 release.

Requires Go 1.27 and PostgreSQL. Build the single binary:

```sh
go build -trimpath -o passkey-server ./cmd/web
```

Copy `config.example.json` to your deployment configuration and replace the
application RP/origins and client certificate fingerprint. Applications are
immutable while the process runs; every node must use the same configuration
and database. The RP is the browser application's domain, not the Passkey Server host.

```sh
./passkey-server \
  --listen :8443 \
  --config config.json \
  --database-dsn 'postgres://passkey_server:password@localhost/passkey_server?sslmode=require' \
  --tls-cert server.pem \
  --tls-key server.key \
  --client-ca client-ca.pem
```

All three TLS flags are required. The database role needs DDL permissions for
startup migrations. `/health` and `/ready` use HTTPS without client certificates;
all `/v1/*` routes require a CA-verified client certificate whose leaf fingerprint
is authorized for the requested application. TLS terminates in Passkey Server; HTTP proxy
certificate headers are not trusted.

See [API contract](docs/api.md), [local setup](docs/local-development.md), and
[dependency review](docs/dependencies.md).

## Browser demo

`cmd/demo` is a separate local HTTPS application with buttons to register a passkey
and verify authentication. It accesses Passkey Server using mTLS, with no database
or frontend build chain. See [browser demo setup](docs/local-development.md#browser-demo)
for the command, certificate trust and manual test steps.

## Tests

```sh
go test ./...
TEST_DATABASE_DSN='postgres://passkey_server:password@localhost/passkey_server_test?sslmode=disable' go test -race ./...
go vet ./...
```

Integration tests use a fresh temporary schema per test and drop only that schema
on completion. The supplied database role needs schema creation permissions.
Without `TEST_DATABASE_DSN`, PostgreSQL tests explicitly skip; unit, HTTP, native
TLS and WebAuthn adapter tests still run. Tests use an Ed25519 authenticator fixture
that creates a registration and signs real assertions; no physical passkey is needed.
