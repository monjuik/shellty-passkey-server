package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func issueCertificate(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool, usage x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Passkey Server test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
		template.ExtKeyUsage = nil
	}
	if parent == nil {
		parent = template
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
func TestNativeMTLS(t *testing.T) {
	ca, caKey, caPEM, _ := issueCertificate(t, nil, nil, true, 0)
	_, _, serverPEM, serverKey := issueCertificate(t, ca, caKey, false, x509.ExtKeyUsageServerAuth)
	_, _, clientPEM, clientKey := issueCertificate(t, ca, caKey, false, x509.ExtKeyUsageClientAuth)
	foreignCA, foreignKey, _, _ := issueCertificate(t, nil, nil, true, 0)
	_, _, foreignPEM, foreignClientKey := issueCertificate(t, foreignCA, foreignKey, false, x509.ExtKeyUsageClientAuth)
	dir := t.TempDir()
	files := []string{"server.pem", "server.key", "ca.pem"}
	for i, b := range [][]byte{serverPEM, serverKey, caPEM} {
		if err := os.WriteFile(filepath.Join(dir, files[i]), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	config, err := TLSConfig(filepath.Join(dir, files[0]), filepath.Join(dir, files[1]), filepath.Join(dir, files[2]))
	if err != nil {
		t.Fatal(err)
	}
	service := &fakePasskeys{}
	server := httptest.NewUnstartedServer(Handler(service, func(context.Context) error { return nil }, slog.New(slog.NewTextHandler(io.Discard, nil))))
	server.TLS = config
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := func(certPEM, keyPEM []byte) *http.Client {
		t.Helper()
		cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		if certPEM != nil {
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
		}
		transport := &http.Transport{TLSClientConfig: cfg}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 3 * time.Second}
	}
	without := client(nil, nil)
	resp, err := without.Get(server.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("health requires certificate")
	}
	resp, err = without.Post(server.URL+"/v1/registrations/start", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("integration accepted missing certificate")
	}
	trusted := client(clientPEM, clientKey)
	resp, err = trusted.Post(server.URL+"/v1/registrations/start", "application/json", strings.NewReader(`{"application":"shop","subject":"alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || service.fingerprint == "" {
		t.Fatal("trusted certificate rejected")
	}
	if resp, err = client(foreignPEM, foreignClientKey).Post(server.URL+"/v1/registrations/start", "application/json", strings.NewReader(`{}`)); err == nil {
		_ = resp.Body.Close()
		t.Fatal("untrusted client CA accepted")
	}
}
