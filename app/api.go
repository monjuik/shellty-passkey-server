package app

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/monjuik/shellty-passkey-server/passkeys"
)

const maxRequestBytes = 96 << 10

type Passkeys interface {
	passkeys.Commands
	passkeys.Queries
}

type API struct {
	service Passkeys
	ready   func(context.Context) error
	logger  *slog.Logger
}

func Handler(service Passkeys, ready func(context.Context) error, logger *slog.Logger, admin ...http.Handler) http.Handler {
	api := &API{service, ready, logger}
	mux := http.NewServeMux()
	if len(admin) > 0 && admin[0] != nil {
		mux.Handle("/admin/", admin[0])
	}
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		api.writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), databaseTimeout)
		defer cancel()
		if err := ready(ctx); err != nil {
			logger.Error("database readiness check failed", "error", err)
			api.writeJSON(w, 503, map[string]string{"status": "not_ready"})
			return
		}
		api.writeJSON(w, 200, map[string]string{"status": "ready"})
	})
	integration := http.NewServeMux()
	integration.HandleFunc("POST /v1/registrations/start", api.start(passkeys.Registration))
	integration.HandleFunc("POST /v1/registrations/finish", api.finish(passkeys.Registration))
	integration.HandleFunc("POST /v1/authentications/start", api.start(passkeys.Authentication))
	integration.HandleFunc("POST /v1/authentications/finish", api.finish(passkeys.Authentication))
	integration.HandleFunc("GET /v1/credentials", api.credentials)
	integration.HandleFunc("DELETE /v1/credentials/{credential}", api.deleteCredential)
	mux.Handle("/v1/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fingerprint(r) == "" {
			api.fail(w, passkeys.Forbidden)
			return
		}
		integration.ServeHTTP(w, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		defer func() {
			if recover() != nil {
				logger.Error("HTTP handler panic")
				api.writeJSON(w, 500, map[string]string{"error": "internal_error"})
			}
		}()
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func fingerprint(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(r.TLS.PeerCertificates[0].Raw))
}
func decode(w http.ResponseWriter, r *http.Request, target any) error {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return passkeys.InvalidRequest
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil || !utf8.Valid(body) {
		return passkeys.InvalidRequest
	}
	if err = strictJSON(body, target); err != nil {
		return passkeys.InvalidRequest
	}
	return nil
}
func (a *API) start(k passkeys.Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Application string `json:"application"`
			Subject     string `json:"subject"`
			DisplayName string `json:"displayName"`
		}
		if err := decode(w, r, &request); err != nil {
			a.fail(w, err)
			return
		}
		if k == passkeys.Authentication && request.DisplayName != "" {
			a.fail(w, passkeys.InvalidRequest)
			return
		}
		result, err := a.service.Start(
			r.Context(), k, request.Application, request.Subject, request.DisplayName, fingerprint(r),
		)
		if err != nil {
			a.fail(w, err)
			return
		}
		a.writeJSON(w, 200, result)
	}
}
func (a *API) finish(k passkeys.Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Token      string         `json:"token"`
			Credential jsontext.Value `json:"credential"`
		}
		if err := decode(w, r, &request); err != nil {
			a.fail(w, err)
			return
		}
		result, err := a.service.Finish(r.Context(), k, request.Token, request.Credential, fingerprint(r))
		if err != nil {
			a.fail(w, err)
			return
		}
		a.writeJSON(w, 200, result)
	}
}
func scope(r *http.Request) (string, string, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) != 2 || len(q["application"]) != 1 || len(q["subject"]) != 1 {
		err = passkeys.InvalidRequest
	}
	return q.Get("application"), q.Get("subject"), err
}
func (a *API) credentials(w http.ResponseWriter, r *http.Request) {
	application, subject, err := scope(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	result, err := a.service.Credentials(r.Context(), application, subject, fingerprint(r))
	if err != nil {
		a.fail(w, err)
		return
	}
	a.writeJSON(w, 200, map[string]any{"credentials": result})
}
func (a *API) deleteCredential(w http.ResponseWriter, r *http.Request) {
	application, subject, err := scope(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	if err = a.service.Delete(r.Context(), application, subject, r.PathValue("credential"), fingerprint(r)); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func errorStatus(err error) (int, string) {
	var code passkeys.Error
	if !errors.As(err, &code) {
		return 500, "internal_error"
	}
	switch code {
	case passkeys.InvalidRequest:
		return 400, string(code)
	case passkeys.Forbidden:
		return 403, string(code)
	case passkeys.ApplicationNotFound, passkeys.CredentialNotFound,
		passkeys.Registration.NotFound(), passkeys.Authentication.NotFound():
		return 404, string(code)
	case passkeys.Registration.Expired(), passkeys.Authentication.Expired():
		return 410, string(code)
	case passkeys.Registration.Invalid(), passkeys.Authentication.Invalid():
		return 400, string(code)
	case passkeys.Conflict:
		return 409, string(code)
	default:
		return 500, "internal_error"
	}
}
func (a *API) fail(w http.ResponseWriter, err error) {
	status, code := errorStatus(err)
	if status == 500 {
		a.logger.Error("request failed", "code", code, "error", err)
	}
	a.writeJSON(w, status, map[string]string{"error": code})
}
func (a *API) writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		a.logger.Error("JSON response encoding failed", "code", "internal_error")
		status = http.StatusInternalServerError
		data = []byte(`{"error":"internal_error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}
