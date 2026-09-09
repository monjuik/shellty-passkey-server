package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/monjuik/shellty-passkey-server/assets"
	"github.com/monjuik/shellty-passkey-server/passkeys"
	"golang.org/x/crypto/bcrypt"
)

const adminCookieName = "shellty_admin"
const adminCookieAge = 30 * 24 * time.Hour

type adminUI struct {
	config    *Config
	store     adminStore
	templates *template.Template
	logger    *slog.Logger
	now       func() time.Time
	mu        sync.Mutex
	tokens    float64
	refill    time.Time
}
type adminPageData struct {
	Title, Active, Error, Previous, Next string
	Filter                               adminFilter
	Applications                         []passkeys.Application
	Credentials                          []adminCredential
	Credential                           *adminCredential
	History                              []adminEvent
	Compact                              bool
}

func newAdmin(config *Config, store adminStore, logger *slog.Logger) (http.Handler, error) {
	if !config.Admin.Enabled {
		return nil, nil
	}
	funcs := template.FuncMap{
		"date": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
		"optionalDate": func(t *time.Time) string {
			if t == nil {
				return "Never"
			}
			return t.UTC().Format("2006-01-02 15:04:05 UTC")
		},
		"join": strings.Join,
		"credentialURL": func(id string) string {
			return "/admin/credentials/" + id
		},
		"subjectHistory": func(application, subject string) string {
			return "/admin/history?" + url.Values{"application": {application}, "subject": {subject}}.Encode()
		},
		"applicationURL": func(code string) string { return "/admin/credentials?" + url.Values{"application": {code}}.Encode() },
	}
	templates, err := template.New("admin").Funcs(funcs).ParseFS(assets.Admin, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse admin templates: %w", err)
	}
	a := &adminUI{config: config, store: store, templates: templates, logger: logger, now: time.Now, tokens: 5, refill: time.Now()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/configuration", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /admin/login", a.loginForm)
	mux.HandleFunc("POST /admin/login", a.login)
	mux.HandleFunc("POST /admin/logout", a.logout)
	mux.HandleFunc("GET /admin/static/{file}", a.static)
	mux.HandleFunc("GET /admin/configuration", a.protect(a.configuration))
	mux.HandleFunc("GET /admin/credentials", a.protect(a.credentials))
	mux.HandleFunc("GET /admin/credentials/{id}", a.protect(a.credential))
	mux.HandleFunc("GET /admin/history", a.protect(a.history))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		// Same-origin forms must retain their Origin for the POST check below.
		w.Header().Set("Referrer-Policy", "same-origin")
		if r.Method == http.MethodPost && !adminSameOrigin(r) {
			http.Error(w, "Invalid request origin", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	}), nil
}
func adminSameOrigin(r *http.Request) bool {
	if r.TLS == nil || len(r.Header.Values("Origin")) != 1 {
		return false
	}
	origin, err := url.Parse(r.Header.Get("Origin"))
	return err == nil && origin.Scheme == "https" && strings.EqualFold(origin.Host, r.Host) &&
		origin.User == nil && origin.Path == "" && origin.RawQuery == "" && !origin.ForceQuery && origin.Fragment == ""
}
func (a *adminUI) signature(expires string) []byte {
	mac := hmac.New(sha256.New, []byte(a.config.Admin.PasswordHash))
	// Length-prefix the configured identity so delimiters in usernames are unambiguous.
	fmt.Fprintf(mac, "shellty-passkey-server:admin:v1:%d:%s:%s", len(a.config.Admin.Username), a.config.Admin.Username, expires)
	return mac.Sum(nil)
}
func (a *adminUI) cookieValue(now time.Time) string {
	expires := strconv.FormatInt(now.Add(adminCookieAge).Unix(), 10)
	return "v1." + expires + "." + hex.EncodeToString(a.signature(expires))
}
func (a *adminUI) validCookie(value string) bool {
	if len(value) > 128 {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != "v1" || len(parts[2]) != 64 {
		return false
	}
	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || strconv.FormatInt(expires, 10) != parts[1] || expires <= a.now().Unix() {
		return false
	}
	actual, err := hex.DecodeString(parts[2])
	return err == nil && hmac.Equal(actual, a.signature(parts[1]))
}
func (a *adminUI) authorized(r *http.Request) bool {
	cookies := r.CookiesNamed(adminCookieName)
	return len(cookies) == 1 && a.validCookie(cookies[0].Value)
}
func (a *adminUI) protect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authorized(r) {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}
func (a *adminUI) allowLogin() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	elapsed := now.Sub(a.refill).Seconds()
	if elapsed > 0 {
		a.tokens = min(5, a.tokens+elapsed/12)
		a.refill = now
	}
	if a.tokens < 1 {
		return false
	}
	a.tokens--
	return true
}
func (a *adminUI) render(w http.ResponseWriter, status int, name string, data adminPageData) {
	var b bytes.Buffer
	if err := a.templates.ExecuteTemplate(&b, name, data); err != nil {
		a.logger.Error("admin template failed")
		http.Error(w, "Unable to display this page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}
func (a *adminUI) loginForm(w http.ResponseWriter, r *http.Request) {
	if a.authorized(r) {
		http.Redirect(w, r, "/admin/configuration", http.StatusSeeOther)
		return
	}
	a.render(w, 200, "login", adminPageData{Title: "Sign in"})
}
func (a *adminUI) login(w http.ResponseWriter, r *http.Request) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		http.Error(w, "Invalid login form", 400)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err = r.ParseForm(); err != nil || len(r.PostForm) != 2 || len(r.PostForm["username"]) != 1 || len(r.PostForm["password"]) != 1 {
		http.Error(w, "Invalid login form", 400)
		return
	}
	if !a.allowLogin() {
		w.Header().Set("Retry-After", "12")
		a.render(w, 429, "login", adminPageData{Title: "Sign in", Error: "Too many sign-in attempts. Please try again shortly."})
		return
	}
	password := r.PostForm.Get("password")
	// Always run bcrypt, including unknown usernames; never silently truncate long passwords.
	err = bcrypt.CompareHashAndPassword([]byte(a.config.Admin.PasswordHash), []byte(password))
	if err != nil || len(password) > 72 || r.PostForm.Get("username") != a.config.Admin.Username {
		a.render(w, 401, "login", adminPageData{Title: "Sign in", Error: "Invalid username or password."})
		return
	}
	now := a.now()
	http.SetCookie(w, &http.Cookie{Name: adminCookieName, Value: a.cookieValue(now), Path: "/admin", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(adminCookieAge.Seconds()), Expires: now.Add(adminCookieAge)})
	http.Redirect(w, r, "/admin/configuration", http.StatusSeeOther)
}
func (a *adminUI) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: adminCookieName, Value: "", Path: "/admin", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}
func (a *adminUI) static(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if name != "pico-2.1.1.min.css" && name != "admin.css" {
		http.NotFound(w, r)
		return
	}
	b, err := assets.Admin.ReadFile("static/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(b)
}
func (a *adminUI) configuration(w http.ResponseWriter, r *http.Request) {
	a.render(w, 200, "configuration", adminPageData{Title: "Configuration", Active: "configuration", Applications: a.config.Applications})
}
func (a *adminUI) failure(w http.ResponseWriter, err error) {
	a.logger.Error("admin query failed", "error", err)
	a.render(w, 500, "error", adminPageData{Title: "Unable to load data", Error: "Data is temporarily unavailable. Please try again."})
}
func (a *adminUI) filter(w http.ResponseWriter, r *http.Request, history bool) (adminFilter, bool) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err == nil {
		var f adminFilter
		f, err = parseAdminFilter(q, history)
		if err == nil {
			return f, true
		}
	}
	a.render(w, 400, "error", adminPageData{Title: "Invalid filters", Error: "Check the filters, date range and page link, then try again."})
	return adminFilter{}, false
}
func pageURL(r *http.Request, cursor string) string {
	q := r.URL.Query()
	q.Set("cursor", cursor)
	return r.URL.Path + "?" + q.Encode()
}
func (a *adminUI) credentials(w http.ResponseWriter, r *http.Request) {
	f, ok := a.filter(w, r, false)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), databaseTimeout)
	defer cancel()
	rows, err := a.store.Credentials(ctx, f)
	if err != nil {
		a.failure(w, err)
		return
	}
	rows, prev, next := adminPage(rows, f.Cursor)
	data := adminPageData{Title: "Credentials", Active: "credentials", Filter: f, Credentials: rows, Applications: a.config.Applications}
	if len(rows) > 0 {
		if prev {
			data.Previous = pageURL(r, cursorValue(rows[0].ID, time.Time{}, true))
		}
		if next {
			data.Next = pageURL(r, cursorValue(rows[len(rows)-1].ID, time.Time{}, false))
		}
	}
	a.render(w, 200, "credentials", data)
}
func (a *adminUI) credential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validUUID(id) {
		http.NotFound(w, r)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "Invalid page link", 400)
		return
	}
	for k := range q {
		if k != "cursor" {
			http.Error(w, "Invalid page link", 400)
			return
		}
	}
	f, err := parseAdminFilter(q, true)
	if err != nil {
		http.Error(w, "Invalid page link", 400)
		return
	}
	f.Credential = id
	ctx, cancel := context.WithTimeout(r.Context(), databaseTimeout)
	defer cancel()
	c, err := a.store.Credential(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		a.render(w, 404, "error", adminPageData{Title: "Credential not found", Error: "This credential does not exist or has been deleted. Its recorded events remain in History."})
		return
	}
	if err != nil {
		a.failure(w, err)
		return
	}
	rows, err := a.store.History(ctx, f)
	if err != nil {
		a.failure(w, err)
		return
	}
	data := adminPageData{Title: "Credential", Active: "credentials", Credential: &c, Compact: true}
	a.historyPage(r, &data, rows, f.Cursor)
	a.render(w, 200, "credential", data)
}
func (a *adminUI) historyPage(r *http.Request, data *adminPageData, rows []adminEvent, cursor adminCursor) {
	rows, prev, next := adminPage(rows, cursor)
	data.History = rows
	if len(rows) > 0 {
		if prev {
			data.Previous = pageURL(r, cursorValue(rows[0].ID, rows[0].Time, true))
		}
		if next {
			e := rows[len(rows)-1]
			data.Next = pageURL(r, cursorValue(e.ID, e.Time, false))
		}
	}
}
func (a *adminUI) history(w http.ResponseWriter, r *http.Request) {
	f, ok := a.filter(w, r, true)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), databaseTimeout)
	defer cancel()
	rows, err := a.store.History(ctx, f)
	if err != nil {
		a.failure(w, err)
		return
	}
	data := adminPageData{Title: "History", Active: "history", Filter: f, Applications: a.config.Applications}
	a.historyPage(r, &data, rows, f.Cursor)
	a.render(w, 200, "history", data)
}
