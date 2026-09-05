# Local HTTPS/mTLS setup

Use a disposable PostgreSQL database and a local CA. The example config expects
an application at `https://localhost:3000`; Passkey Server itself listens on port 8443.
The browser must trust the certificate used by the application as well.

Generate development certificates in a private working directory (OpenSSL):

```sh
mkdir -m 700 dev-certs
cd dev-certs
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout ca.key -out ca.pem -subj '/CN=Passkey Server Development CA'
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj '/CN=localhost'
cat > server.ext <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
EXT
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 7 -extfile server.ext
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj '/CN=Example Backend'
cat > client.ext <<'EXT'
extendedKeyUsage=clientAuth
basicConstraints=CA:FALSE
keyUsage=digitalSignature
EXT
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.pem -days 7 -extfile client.ext
chmod 600 *.key
openssl x509 -in client.pem -outform DER | openssl dgst -sha256
cd ..
```

Replace the all-zero fingerprint in a copy of `config.example.json` with
`sha256:` followed by the lowercase digest from the last command (no colons).
The same development CA is used for server trust and client trust here; deployments
may use different CAs.

With PostgreSQL running and the target database created:

```sh
go build -trimpath -o passkey-server ./cmd/web
./passkey-server --listen :8443 --config config.json \
  --database-dsn 'postgres://localhost/passkey_server?sslmode=disable' \
  --tls-cert dev-certs/server.pem --tls-key dev-certs/server.key \
  --client-ca dev-certs/ca.pem
```

From another terminal:

```sh
curl --cacert dev-certs/ca.pem https://localhost:8443/ready
curl --cacert dev-certs/ca.pem --cert dev-certs/client.pem --key dev-certs/client.key \
  -H 'Content-Type: application/json' \
  -d '{"application":"shop","subject":"alice","displayName":"Alice"}' \
  https://localhost:8443/v1/registrations/start
```

## Browser demo

The repository includes a separate minimal HTTPS application in `cmd/demo`.
It calls Passkey Server through its public mTLS API and does not access the database.
Start Passkey Server as above, then run this command in another terminal:

```sh
go run ./cmd/demo \
  --listen 127.0.0.1:3000 \
  --passkey-server https://localhost:8443 \
  --application shop \
  --tls-cert dev-certs/server.pem \
  --tls-key dev-certs/server.key \
  --client-cert dev-certs/client.pem \
  --client-key dev-certs/client.key \
  --server-ca dev-certs/ca.pem
```

For this local setup the demo can reuse the development server certificate because
both servers use the `localhost` hostname. The backend client certificate fingerprint
must match the application's `clients` entry in Passkey Server configuration.
`--server-ca` verifies Passkey Server; `--client-cert` and `--client-key` authenticate
the demo backend to it. These files are never served to the browser.

Trust the development CA in the browser/operating system before testing. On macOS,
import `dev-certs/ca.pem` into Keychain Access and explicitly trust it for SSL; never
import or share `ca.key`. Remove that local trust when the development CA is no longer
needed. Clicking through a browser certificate warning is not a substitute for a
trusted HTTPS context for WebAuthn.

Open **https://localhost:3000/** (use `localhost`, not `127.0.0.1`). The application
configuration must have `rpId: "localhost"` and `origins: ["https://localhost:3000"]`,
as in `config.example.json`. The demo binds only to loopback and accepts only its
canonical localhost Host and same-origin JSON POSTs. If you change its port, update
the configured origin accordingly.

1. Leave subject as `alice` and click **Добавить passkey**. Complete the system dialog.
2. Click **Проверить вход** for the same subject. The page should show a successful
   result with application, subject and credential identifier.
3. Start another action and cancel the system dialog. The page should show a message
   and allow retrying.
4. Enter a fresh subject with no credentials and click **Проверить вход**. It should
   show an authentication failure.

This is a local test harness: any entered subject can be used for registration.
Successful authentication is displayed but does not create a login session. There
is no database, frontend build chain or additional dependency for the demo.
Stop either process with Ctrl+C. The demo has four fixed API routes, bounded bodies,
upstream timeouts, certificate verification and no upstream redirect following.
See [the API contract](api.md) for the exchanged WebAuthn values.

`go test -race ./cmd/demo` checks forwarding, validation, TLS trust, mTLS and redirect
handling. Real browser/authenticator behavior is covered by the manual flow above;
the core also has an automated software-authenticator fixture.


## PostgreSQL

```bash
createuser --login --pwprompt passkey
createdb --owner=passkey passkey
```

DSN: postgres://passkey:<password>@localhost:5432/passkey
