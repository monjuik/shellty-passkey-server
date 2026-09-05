// Command demo runs a local browser client for Shellty Passkey Server.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

//go:embed index.html
var page []byte

const requestLimit = 96 << 10
const responseLimit = 1 << 20

var applicationCode = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var errorCode = regexp.MustCompile(`^[a-z_]{1,64}$`)

type demo struct {
	client      *http.Client
	upstream    string
	application string
	origin      string
	host        string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		slog.Error("demo stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("passkey-demo", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:3000", "loopback HTTPS listen address")
	upstream := flags.String("passkey-server", "https://localhost:8443", "Passkey Server HTTPS URL")
	application := flags.String("application", "shop", "configured application code")
	cert := flags.String("tls-cert", "", "demo HTTPS certificate")
	key := flags.String("tls-key", "", "demo HTTPS private key")
	clientCert := flags.String("client-cert", "", "backend mTLS certificate")
	clientKey := flags.String("client-key", "", "backend mTLS private key")
	serverCA := flags.String("server-ca", "", "CA PEM for verifying Passkey Server")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !applicationCode.MatchString(*application) {
		return fmt.Errorf("invalid arguments or application code")
	}
	host, port, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("listen must specify a loopback host and port")
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("demo must listen on a loopback address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("invalid listen port")
	}
	upstreamURL, err := url.Parse(*upstream)
	if err != nil || upstreamURL.Scheme != "https" || upstreamURL.Host == "" ||
		upstreamURL.User != nil || (upstreamURL.Path != "" && upstreamURL.Path != "/") ||
		upstreamURL.RawQuery != "" || upstreamURL.ForceQuery || upstreamURL.Fragment != "" {
		return fmt.Errorf("passkey-server must be an HTTPS origin without credentials, query or fragment")
	}
	serverCert, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		return fmt.Errorf("load demo HTTPS certificate: %w", err)
	}
	client, err := newClient(*clientCert, *clientKey, *serverCA)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	publicHost := net.JoinHostPort("localhost", strconv.Itoa(portNumber))
	if portNumber == 443 {
		publicHost = "localhost"
	}
	d := &demo{client, strings.TrimSuffix(*upstream, "/"), *application, "https://" + publicHost, publicHost}
	server := &http.Server{
		Addr: *listen, Handler: d.handler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	slog.Info("demo ready", "url", d.origin, "application", d.application)
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		return nil
	}
}

func newClient(certFile, keyFile, caFile string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load mTLS certificate: %w", err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read upstream CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("upstream CA contains no certificates")
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert},
		}},
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func (d *demo) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	})
	for _, ceremony := range []string{"registrations", "authentications"} {
		for _, step := range []string{"start", "finish"} {
			path := "/" + ceremony + "/" + step
			mux.HandleFunc("POST /api"+path, d.forward("/v1"+path, step == "start"))
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "+
				"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
		)
		if r.Host != d.host {
			writeError(w, http.StatusForbidden, "invalid_host")
			return
		}
		if r.Method == http.MethodPost && r.Header.Get("Origin") != d.origin {
			writeError(w, http.StatusForbidden, "invalid_origin")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (d *demo) forward(path string, start bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || contentType != "application/json" || r.URL.RawQuery != "" {
			writeError(w, 400, "invalid_request")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, requestLimit))
		trimmed := bytes.TrimSpace(body)
		if err != nil || len(trimmed) == 0 || trimmed[0] != '{' {
			writeError(w, 400, "invalid_request")
			return
		}
		var payload any
		if start {
			var input struct {
				Subject string `json:"subject"`
			}
			if err = json.Unmarshal(body, &input, json.RejectUnknownMembers(true)); err != nil ||
				input.Subject == "" || len(input.Subject) > 256 || !utf8.ValidString(input.Subject) ||
				strings.ContainsRune(input.Subject, 0) {
				writeError(w, 400, "invalid_request")
				return
			}
			payload = struct {
				Application string `json:"application"`
				Subject     string `json:"subject"`
			}{d.application, input.Subject}
		} else {
			var input struct {
				Token      string         `json:"token"`
				Credential jsontext.Value `json:"credential"`
			}
			if err = json.Unmarshal(body, &input, json.RejectUnknownMembers(true)); err != nil ||
				len(input.Token) != 43 || len(input.Credential) == 0 || len(input.Credential) > 64<<10 ||
				bytes.TrimSpace(input.Credential)[0] != '{' {
				writeError(w, 400, "invalid_request")
				return
			}
			payload = input
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			writeError(w, 400, "invalid_request")
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, d.upstream+path, bytes.NewReader(encoded))
		if err != nil {
			writeError(w, 502, "upstream_unavailable")
			return
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := d.client.Do(request)
		if err != nil {
			writeError(w, 502, "upstream_unavailable")
			return
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
		if err != nil || len(data) > responseLimit || !jsontext.Value(data).IsValid() {
			writeError(w, 502, "invalid_upstream_response")
			return
		}
		if response.StatusCode != http.StatusOK {
			var failure struct {
				Error string `json:"error"`
			}
			if response.StatusCode >= 400 && response.StatusCode < 500 &&
				json.Unmarshal(data, &failure) == nil && errorCode.MatchString(failure.Error) {
				writeError(w, response.StatusCode, failure.Error)
				return
			}
			writeError(w, 502, "upstream_failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	data, _ := json.Marshal(map[string]string{"error": code})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
