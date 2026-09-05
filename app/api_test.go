package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monjuik/shellty-passkey-server/passkeys"
)

type fakePasskeys struct {
	calls       int
	fingerprint string
	err         error
	panic       bool
}

func (f *fakePasskeys) Start(_ context.Context, _ passkeys.Kind, _, _, _, fingerprint string) (passkeys.StartResult, error) {
	f.calls++
	f.fingerprint = fingerprint
	if f.panic {
		panic("secret panic")
	}
	return passkeys.StartResult{Token: "test-token", Options: jsontext.Value(`{"publicKey":{}}`)}, f.err
}
func (f *fakePasskeys) Finish(context.Context, passkeys.Kind, string, jsontext.Value, string) (passkeys.FinishResult, error) {
	return passkeys.FinishResult{}, f.err
}
func (f *fakePasskeys) Credentials(context.Context, string, string, string) ([]passkeys.Credential, error) {
	return []passkeys.Credential{}, f.err
}
func (f *fakePasskeys) Delete(context.Context, string, string, string, string) error { return f.err }
func verifiedRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	cert := &x509.Certificate{Raw: []byte("test certificate")}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	return r
}
func TestHTTPContract(t *testing.T) {
	service := &fakePasskeys{}
	var logs bytes.Buffer
	dbErr := error(nil)
	handler := Handler(service, func(context.Context) error { return dbErr }, slog.New(slog.NewJSONHandler(&logs, nil)))
	for _, tc := range []struct {
		name, method, path, body string
		status                   int
	}{
		{"start", "POST", "/v1/registrations/start", `{"application":"shop","subject":"alice"}`, 200},
		{"wrong field case", "POST", "/v1/registrations/start", `{"Application":"shop","subject":"alice"}`, 400},
		{"unknown field", "POST", "/v1/registrations/start", `{"application":"shop","subject":"alice","extra":1}`, 400},
		{"duplicate field", "POST", "/v1/registrations/start", `{"application":"shop","subject":"alice","subject":"bob"}`, 400},
		{"trailing JSON", "POST", "/v1/registrations/start", `{} {}`, 400},
		{"null", "POST", "/v1/registrations/start", `null`, 400},
		{"large body", "POST", "/v1/registrations/start", `{"subject":"` + strings.Repeat("x", maxRequestBytes) + `"}`, 400},
		{"list", "GET", "/v1/credentials?application=shop&subject=alice", "", 200},
		{"duplicate scope", "GET", "/v1/credentials?application=shop&application=other&subject=alice", "", 400},
		{"malformed query", "GET", "/v1/credentials?application=shop&subject=alice&bad=%xx", "", 400},
		{"missing scope", "GET", "/v1/credentials?application=shop", "", 400},
		{"delete", "DELETE", "/v1/credentials/test?application=shop&subject=alice", "", 204},
		{"health", "GET", "/health", "", 200},
		{"ready", "GET", "/ready", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, verifiedRequest(tc.method, tc.path, tc.body))
			if recorder.Code != tc.status {
				t.Fatalf("got %d: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
	if service.calls != 1 || service.fingerprint == "" {
		t.Fatal("invalid request reached service or fingerprint missing")
	}
	for _, state := range []*tls.ConnectionState{nil, {PeerCertificates: []*x509.Certificate{{Raw: []byte("unverified")}}}} {
		req := verifiedRequest("POST", "/v1/registrations/start", `{}`)
		req.TLS = state
		req.Header.Set("X-Client-Cert", "forged")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatal("unverified request allowed")
		}
	}
	service.err = errors.New("SQL password=secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, verifiedRequest("POST", "/v1/registrations/start", `{}`))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "secret") || strings.Contains(logs.String(), "secret") {
		t.Fatal("internal error disclosure")
	}
	service.panic = true
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, verifiedRequest("POST", "/v1/registrations/start", `{}`))
	if rec.Code != 500 || strings.Contains(logs.String(), "secret") {
		t.Fatal("panic handling")
	}
	dbErr = errors.New("offline")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/ready", nil))
	if rec.Code != 503 {
		t.Fatal("readiness ignored DB error")
	}
}
func TestErrorMapping(t *testing.T) {
	for err, want := range map[error]int{
		passkeys.InvalidRequest:            400,
		passkeys.Forbidden:                 403,
		passkeys.ApplicationNotFound:       404,
		passkeys.CredentialNotFound:        404,
		passkeys.Registration.NotFound():   404,
		passkeys.Authentication.NotFound(): 404,
		passkeys.Registration.Expired():    410,
		passkeys.Authentication.Expired():  410,
		passkeys.Registration.Invalid():    400,
		passkeys.Authentication.Invalid():  400,
		passkeys.Conflict:                  409,
		errors.New("secret"):               500,
		passkeys.Error("secret"):           500,
	} {
		got, code := errorStatus(fmt.Errorf("wrapped: %w", err))
		if got != want || (want == 500 && code != "internal_error") {
			t.Fatalf("%v -> %d %s", err, got, code)
		}
	}
}
func TestRunRejectsIncompleteConfiguration(t *testing.T) {
	if err := Run(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("missing flags accepted")
	}
}
