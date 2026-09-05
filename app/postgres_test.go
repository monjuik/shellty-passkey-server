package app_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/monjuik/shellty-passkey-server/app"
	"github.com/monjuik/shellty-passkey-server/internal/testauth"
	"github.com/monjuik/shellty-passkey-server/passkeys"
)

func testDatabase(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "passkey_server_test_" + strings.ReplaceAll(uuid.NewV7().String(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer admin.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	pools := make([]*pgxpool.Pool, 2)
	for i := range pools {
		config, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.ConnConfig.RuntimeParams["search_path"] = schema
		config.MaxConns = 4
		pools[i], err = pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pools[i].Close)
	}
	var wg sync.WaitGroup
	for _, pool := range pools {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := app.Migrate(ctx, pool); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if t.Failed() {
		t.FailNow()
	}
	return pools[0], pools[1]
}
func TestPostgresCeremonies(t *testing.T) {
	first, second := testDatabase(t)
	ctx := context.Background()
	applications := []passkeys.Application{{Code: "shop", Name: "Shop", RPID: "shop.example.com", Origins: []string{"https://shop.example.com"}, Clients: []string{"client-a"}}, {Code: "other", Name: "Other", RPID: "shop.example.com", Origins: []string{"https://shop.example.com"}, Clients: []string{"client-b"}}}
	adapter, err := passkeys.NewWebAuthn(applications)
	if err != nil {
		t.Fatal(err)
	}
	a := passkeys.NewService(applications, passkeys.NewPostgres(first), adapter)
	adapter, err = passkeys.NewWebAuthn(applications)
	if err != nil {
		t.Fatal(err)
	}
	b := passkeys.NewService(applications, passkeys.NewPostgres(second), adapter)
	start := func(k passkeys.Kind) passkeys.StartResult {
		t.Helper()
		result, err := a.Start(ctx, k, "shop", "alice", "Alice", "client-a")
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	authenticator := testauth.New(t)
	registration := start(passkeys.Registration)
	response := authenticator.Register(t, registration.Options, "shop.example.com", "https://shop.example.com")
	if _, err = b.Finish(ctx, passkeys.Registration, registration.Token, response, "client-b"); !errors.Is(err, passkeys.Forbidden) {
		t.Fatalf("unauthorized finish: %v", err)
	}
	var tokenHash []byte
	if err = first.QueryRow(ctx, "SELECT token_hash FROM registration").Scan(&tokenHash); err != nil || len(tokenHash) != 32 || string(tokenHash) == registration.Token {
		t.Fatal("token storage", err)
	}
	finish, err := b.Finish(ctx, passkeys.Registration, registration.Token, response, "client-a")
	if err != nil {
		t.Fatal("register", err)
	}
	if _, err = a.Finish(ctx, passkeys.Registration, registration.Token, response, "client-a"); !errors.Is(err, passkeys.Conflict) {
		t.Fatal("registration replay", err)
	}
	credentials, err := a.Credentials(ctx, "shop", "alice", "client-a")
	if err != nil || len(credentials) != 1 || credentials[0].ID != finish.Credential {
		t.Fatal("credential persistence", err)
	}
	if _, err = a.Credentials(ctx, "shop", "alice", "client-b"); !errors.Is(err, passkeys.Forbidden) {
		t.Fatal("cross-app credential access", err)
	}
	if err = a.Delete(ctx, "shop", "bob", finish.Credential, "client-a"); !errors.Is(err, passkeys.CredentialNotFound) {
		t.Fatal("cross-subject delete", err)
	}
	// Identical authenticator IDs cannot be reassigned within the same RP.
	duplicate, err := a.Start(ctx, passkeys.Registration, "other", "bob", "Bob", "client-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Finish(ctx, passkeys.Registration, duplicate.Token, authenticator.Register(t, duplicate.Options, "shop.example.com", "https://shop.example.com"), "client-b"); !errors.Is(err, passkeys.Conflict) {
		t.Fatal("duplicate RP credential", err)
	}
	login := start(passkeys.Authentication)
	assertion := authenticator.Authenticate(t, login.Options, "shop.example.com", "https://shop.example.com", passkeys.UserHandle("shop", "alice"), 1, true)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := b.Finish(ctx, passkeys.Authentication, login.Token, assertion, "client-a")
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, passkeys.Conflict) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent successes: %d", successes.Load())
	}
	// Independent ceremonies share the latest credential counter across nodes.
	login1, login2 := start(passkeys.Authentication), start(passkeys.Authentication)
	assertion1 := authenticator.Authenticate(t, login1.Options, "shop.example.com", "https://shop.example.com", passkeys.UserHandle("shop", "alice"), 2, true)
	assertion2 := authenticator.Authenticate(t, login2.Options, "shop.example.com", "https://shop.example.com", passkeys.UserHandle("shop", "alice"), 2, true)
	successes.Store(0)
	for _, entry := range []struct {
		start    passkeys.StartResult
		response jsontext.Value
		service  *passkeys.Service
	}{{login1, assertion1, a}, {login2, assertion2, b}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := entry.service.Finish(ctx, passkeys.Authentication, entry.start.Token, entry.response, "client-a")
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, passkeys.Authentication.Invalid()) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("lost counter update")
	}
	expired := start(passkeys.Authentication)
	hash, _ := passkeys.TokenHash(expired.Token)
	if _, err = first.Exec(ctx, "UPDATE authentication SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE token_hash=$1", hash); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Finish(ctx, passkeys.Authentication, expired.Token, assertion, "client-a"); !errors.Is(err, passkeys.Authentication.Expired()) {
		t.Fatal("expired", err)
	}
	failed := start(passkeys.Authentication)
	invalid := authenticator.Authenticate(t, failed.Options, "shop.example.com", "https://evil.example.com", passkeys.UserHandle("shop", "alice"), 3, true)
	if _, err = b.Finish(ctx, passkeys.Authentication, failed.Token, invalid, "client-a"); !errors.Is(err, passkeys.Authentication.Invalid()) {
		t.Fatal("invalid origin", err)
	}
	if _, err = b.Finish(ctx, passkeys.Authentication, failed.Token, invalid, "client-a"); !errors.Is(err, passkeys.Conflict) {
		t.Fatal("failed ceremony reused", err)
	}
	// Infrastructure failure rolls back the ceremony and its history.
	retry := start(passkeys.Authentication)
	hash, _ = passkeys.TokenHash(retry.Token)
	sentinel := errors.New("storage unavailable")
	_, err = passkeys.NewPostgres(first).Finish(ctx, passkeys.Authentication, hash, func(passkeys.Ceremony) error { return nil }, func(passkeys.Ceremony, []passkeys.Credential) (passkeys.Credential, error) {
		return passkeys.Credential{}, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	assertion = authenticator.Authenticate(t, retry.Options, "shop.example.com", "https://shop.example.com", passkeys.UserHandle("shop", "alice"), 3, true)
	if _, err = b.Finish(ctx, passkeys.Authentication, retry.Token, assertion, "client-a"); err != nil {
		t.Fatal("rollback retry", err)
	}
	pending := start(passkeys.Authentication)
	if err = b.Delete(ctx, "shop", "alice", finish.Credential, "client-a"); err != nil {
		t.Fatal(err)
	}
	assertion = authenticator.Authenticate(t, pending.Options, "shop.example.com", "https://shop.example.com", passkeys.UserHandle("shop", "alice"), 4, true)
	if _, err = a.Finish(ctx, passkeys.Authentication, pending.Token, assertion, "client-a"); !errors.Is(err, passkeys.Authentication.Invalid()) {
		t.Fatal("deleted credential used", err)
	}
	credentials, err = a.Credentials(ctx, "shop", "alice", "client-a")
	if err != nil || len(credentials) != 0 {
		t.Fatal("delete persistence", err)
	}
	var count int
	if err = first.QueryRow(ctx, "SELECT count(*) FROM history WHERE kind='authentication.finish' AND result='succeeded'").Scan(&count); err != nil || count != 3 {
		t.Fatalf("history successes %d: %v", count, err)
	}
	if err = first.QueryRow(ctx, "SELECT count(*) FROM history WHERE result='expired' AND error='authentication_expired'").Scan(&count); err != nil || count != 1 {
		t.Fatal("expiry history", count, err)
	}
}
func TestMigrationValidation(t *testing.T) {
	pool, _ := testDatabase(t)
	ctx := context.Background()
	if err := app.Migrate(ctx, pool); err != nil {
		t.Fatal("repeat migration", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO migration(version,checksum) VALUES(2,'future')"); err != nil {
		t.Fatal(err)
	}
	if err := app.Migrate(ctx, pool); err == nil {
		t.Fatal("newer schema accepted")
	}
	if err := app.CheckSchema(ctx, pool); err == nil {
		t.Fatal("newer schema ready")
	}
	if _, err := pool.Exec(ctx, "DELETE FROM migration WHERE version=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE migration SET checksum='changed' WHERE version=1"); err != nil {
		t.Fatal(err)
	}
	if err := app.Migrate(ctx, pool); err == nil {
		t.Fatal("modified migration accepted")
	}
}

// Verify the public JSON envelopes against real application services and storage.
// Native TLS certificate validation is covered separately by TestNativeMTLS.
func TestHTTPPostgresFlow(t *testing.T) {
	pool, other := testDatabase(t)
	cert := &x509.Certificate{Raw: []byte("verified test certificate")}
	fingerprint := fmt.Sprintf("sha256:%x", sha256.Sum256(cert.Raw))
	applications := []passkeys.Application{{Code: "shop", Name: "Shop", RPID: "shop.example.com", Origins: []string{"https://shop.example.com"}, Clients: []string{fingerprint}}}
	adapter, err := passkeys.NewWebAuthn(applications)
	if err != nil {
		t.Fatal(err)
	}
	first := app.Handler(passkeys.NewService(applications, passkeys.NewPostgres(pool), adapter), func(ctx context.Context) error { return app.CheckSchema(ctx, pool) }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	adapter, err = passkeys.NewWebAuthn(applications)
	if err != nil {
		t.Fatal(err)
	}
	second := app.Handler(passkeys.NewService(applications, passkeys.NewPostgres(other), adapter), func(ctx context.Context) error { return app.CheckSchema(ctx, other) }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	call := func(node int, method, path string, body any, status int, target any) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, strings.NewReader(string(data)))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		recorder := httptest.NewRecorder()
		handler := first
		if node == 2 {
			handler = second
		}
		handler.ServeHTTP(recorder, req)
		if recorder.Code != status {
			t.Fatalf("%s: %d %s", path, recorder.Code, recorder.Body.String())
		}
		if target != nil {
			if err = json.Unmarshal(recorder.Body.Bytes(), target); err != nil {
				t.Fatal(err)
			}
		}
	}
	var registration passkeys.StartResult
	call(1, "POST", "/v1/registrations/start", map[string]string{"application": "shop", "subject": "alice"}, 200, &registration)
	authenticator := testauth.New(t)
	response := authenticator.Register(t, registration.Options, "shop.example.com", "https://shop.example.com")
	var registered passkeys.FinishResult
	call(2, "POST", "/v1/registrations/finish", map[string]any{"token": registration.Token, "credential": response}, 200, &registered)
	var login passkeys.StartResult
	call(1, "POST", "/v1/authentications/start", map[string]string{"application": "shop", "subject": "alice"}, 200, &login)
	assertion := authenticator.Authenticate(t, login.Options, "shop.example.com", "https://shop.example.com", passkeys.UserHandle("shop", "alice"), 0, true)
	var authenticated passkeys.FinishResult
	call(2, "POST", "/v1/authentications/finish", map[string]any{"token": login.Token, "credential": assertion}, 200, &authenticated)
	if authenticated != registered {
		t.Fatal("finish contract differs")
	}
	var listed struct {
		Credentials []passkeys.Credential `json:"credentials"`
	}
	call(1, "GET", "/v1/credentials?application=shop&subject=alice", nil, 200, &listed)
	if len(listed.Credentials) != 1 || listed.Credentials[0].ID != registered.Credential || listed.Credentials[0].UsedAt == nil {
		t.Fatal("list contract")
	}
	call(2, "DELETE", "/v1/credentials/"+registered.Credential+"?application=shop&subject=alice", nil, 204, nil)
	call(1, "GET", "/v1/credentials?application=shop&subject=alice", nil, 200, &listed)
	if len(listed.Credentials) != 0 {
		t.Fatal("credential still listed")
	}
}
