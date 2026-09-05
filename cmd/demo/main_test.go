package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProxy(t *testing.T) {
	var upstreamPath string
	var upstreamBody map[string]jsontext.Value
	status, body := 200, `{"token":"opaque","options":{"publicKey":{}}}`
	calls := 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		upstreamPath = r.URL.Path
		data, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(data, &upstreamBody); err != nil {
			t.Error(err)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing JSON content type")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()
	d := &demo{upstream.Client(), upstream.URL, "shop", "https://localhost:3000", "localhost:3000"}
	handler := d.handler()
	call := func(path, input, origin, host, contentType string, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", "https://localhost:3000"+path, strings.NewReader(input))
		req.Host = host
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", contentType)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		return rec
	}
	for _, kind := range []string{"registrations", "authentications"} {
		call("/api/"+kind+"/start", `{"subject":"alice"}`, d.origin, d.host, "application/json", 200)
		if upstreamPath != "/v1/"+kind+"/start" || string(upstreamBody["application"]) != `"shop"` ||
			string(upstreamBody["subject"]) != `"alice"` {
			t.Fatal("start forwarding")
		}
		input := `{"token":"` + strings.Repeat("a", 43) + `","credential":{"id":"credential-id",` +
			`"clientExtensionResults":{"credProps":{"rk":true}}}}`
		call("/api/"+kind+"/finish", input, d.origin, d.host, "application/json", 200)
		if upstreamPath != "/v1/"+kind+"/finish" || string(upstreamBody["token"]) != `"`+strings.Repeat("a", 43)+`"` ||
			!strings.Contains(string(upstreamBody["credential"]), `"rk":true`) {
			t.Fatal("finish forwarding")
		}
	}
	before := calls
	for _, input := range []string{
		`null`, `{}`, `{} {}`, `{"Subject":"alice"}`, `{"subject":"alice","application":"other"}`,
		`{"subject":"alice","subject":"bob"}`, `{"subject":"` + strings.Repeat("x", 257) + `"}`,
		`{"subject":"` + strings.Repeat("x", requestLimit) + `"}`,
	} {
		call("/api/registrations/start", input, d.origin, d.host, "application/json", 400)
	}
	call("/api/registrations/finish", `{"token":"bad","credential":{}}`, d.origin, d.host, "application/json", 400)
	call("/api/registrations/start", `{"subject":"alice"}`, "", d.host, "application/json", 403)
	call("/api/registrations/start", `{"subject":"alice"}`, "https://evil.test", d.host, "application/json", 403)
	call("/api/registrations/start", `{"subject":"alice"}`, d.origin, "evil.test", "application/json", 403)
	call("/api/registrations/start", `{"subject":"alice"}`, d.origin, d.host, "text/plain", 400)
	call("/api/unknown", `{}`, d.origin, d.host, "application/json", 404)
	if calls != before {
		t.Fatal("invalid request reached upstream")
	}
	status, body = 403, `{"error":"forbidden"}`
	rec := call("/api/registrations/start", `{"subject":"alice"}`, d.origin, d.host, "application/json", 403)
	if !strings.Contains(rec.Body.String(), "forbidden") {
		t.Fatal("lost error code")
	}
	for _, invalid := range []string{`not JSON`, strings.Repeat("x", responseLimit+1)} {
		status, body = 200, invalid
		call("/api/registrations/start", `{"subject":"alice"}`, d.origin, d.host, "application/json", 502)
	}
	status, body = 500, `{"error":"secret database details"}`
	rec = call("/api/registrations/start", `{"subject":"alice"}`, d.origin, d.host, "application/json", 502)
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("upstream details leaked")
	}
	upstream.Close()
	call("/api/registrations/start", `{"subject":"alice"}`, d.origin, d.host, "application/json", 502)
}

func TestPageAndListenValidation(t *testing.T) {
	d := &demo{host: "localhost:3000", origin: "https://localhost:3000"}
	rec := httptest.NewRecorder()
	d.handler().ServeHTTP(rec, httptest.NewRequest("GET", "https://localhost:3000/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "navigator.credentials.create") ||
		rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("embedded page")
	}
	if err := run(context.Background(), []string{"--listen", "0.0.0.0:3000"}); err == nil {
		t.Fatal("non-loopback listener allowed")
	}
}

func TestMTLSClient(t *testing.T) {
	// A self-signed development client certificate supplies test trust
	// and a client identity. Production configuration can use separate CAs.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(cert)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 {
			t.Error("client certificate not verified")
		}
		w.Header().Set("Location", "https://localhost:1/should-not-follow")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	upstream.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	upstream.StartTLS()
	defer upstream.Close()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	caPath := filepath.Join(dir, "ca.pem")
	files := map[string][]byte{
		certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPath:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		caPath:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}),
	}
	for path, data := range files {
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	client, err := newClient(certPath, keyPath, caPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 307 {
		t.Fatal("redirect followed")
	}
	untrusted, err := newClient(certPath, keyPath, certPath)
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.CloseIdleConnections()
	if response, err = untrusted.Get(upstream.URL); err == nil {
		_ = response.Body.Close()
		t.Fatal("untrusted server accepted")
	}
}
