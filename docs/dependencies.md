# Dependency review

Reviewed pinned module manifests, runtime import paths and upstream license files
on 2026-09-05. `go.mod` / `go.sum` fix the selected versions. This review identifies
purpose and licensing; it is not a source-level security audit of dependencies.

## Direct runtime dependencies

| Module                            | Version | License      | Reason                                                                                                 |
| --------------------------------- | ------- | ------------ | ------------------------------------------------------------------------------------------------------ |
| `github.com/go-webauthn/webauthn` | v0.18.0 | BSD-3-Clause | WebAuthn options, session state, credential parsing and verification behind the Passkey Server adapter |
| `github.com/jackc/pgx/v5`         | v5.10.0 | MIT          | PostgreSQL driver, native types, transactions and connection pool; no ORM                              |
| `golang.org/x/crypto`             | v0.56.0 | BSD-3-Clause | bcrypt administrator password verification and hash validation; also used transitively by WebAuthn     |

## Transitive runtime modules

| Module                                | Version                            | License                       | Imported capability                                                              |
| ------------------------------------- | ---------------------------------- | ----------------------------- | -------------------------------------------------------------------------------- |
| `github.com/fxamacker/cbor/v2`        | v2.9.3                             | MIT                           | WebAuthn CBOR encoding/decoding                                                  |
| `github.com/x448/float16`             | v0.8.4                             | MIT                           | CBOR numeric representation                                                      |
| `github.com/go-viper/mapstructure/v2` | v2.5.0                             | MIT                           | WebAuthn attestation field conversion                                            |
| `github.com/go-webauthn/x`            | v0.3.0                             | BSD-3-Clause                  | WebAuthn shared helpers                                                          |
| `github.com/golang-jwt/jwt/v5`        | v5.3.1                             | MIT                           | WebAuthn's supported attestation/metadata formats; Passkey Server issues no JWTs |
| `github.com/google/go-tpm`            | v0.9.8                             | Apache-2.0                    | Library TPM attestation decoding; no local TPM required                          |
| `github.com/google/uuid`              | v1.6.0                             | BSD-3-Clause                  | Library AAGUID handling; Passkey Server IDs use standard-library `uuid`          |
| `github.com/tinylib/msgp`             | v1.6.4                             | MIT, with Go-derived portions | Library serialization support; Passkey Server stores JSON-encoded opaque records |
| `github.com/philhofer/fwd`            | v1.2.0                             | MIT                           | MessagePack buffered I/O support                                                 |
| `github.com/jackc/pgpassfile`         | v1.0.0                             | MIT                           | pgx connection configuration                                                     |
| `github.com/jackc/pgservicefile`      | v0.0.0-20240606120523-5a60cdf6a761 | MIT                           | pgx service-file configuration                                                   |
| `github.com/jackc/puddle/v2`          | v2.2.2                             | MIT                           | pgx pool resources                                                               |
| `golang.org/x/sync`                   | v0.22.0                            | BSD-3-Clause                  | Pool synchronization                                                             |
| `golang.org/x/sys`                    | v0.47.0                            | BSD-3-Clause                  | Platform support in dependencies                                                 |
| `golang.org/x/text`                   | v0.41.0                            | BSD-3-Clause                  | PostgreSQL authentication text handling                                          |

The module graph also contains upstream testing/tool dependencies (including
`testify`, `go.uber.org/mock`, TPM simulator tools and YAML). Passkey Server does not import
mock/assertion frameworks or YAML and they are not part of the server's runtime
imports. No routing, DI, ORM, migration, JavaScript frontend or configuration framework was
introduced. No MDS provider or outbound vendor client is configured.

The [release workflow](releases.md) inventories runtime modules with
`go list -deps -json ./cmd/web` and bundles their license/notice files, plus the Go
and Pico licenses. Review dependency changes before shipping. Vulnerability scans
and SBOM publication remain separate release tasks, not automated by this workflow.

## Embedded administration styles

Pico CSS **2.1.1** (MIT) is vendored in `assets/static/pico-2.1.1.min.css`
from `https://cdn.jsdelivr.net/npm/@picocss/pico@2.1.1/css/pico.min.css`.
Its upstream license is included as `assets/static/PICO-LICENSE.md`.
The administration UI loads all styles from the server, without CDN requests
or a frontend build step.
