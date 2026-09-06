package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/monjuik/shellty-passkey-server/passkeys"
	"golang.org/x/crypto/bcrypt"
)

type fakeAdminStore struct {
	credentials []adminCredential
	events      []adminEvent
	filter      adminFilter
	err         error
}

func (s *fakeAdminStore) Credentials(_ context.Context, f adminFilter) ([]adminCredential, error) {
	s.filter = f
	return s.credentials, s.err
}
func (s *fakeAdminStore) Credential(_ context.Context, id string) (adminCredential, error) {
	if s.err != nil {
		return adminCredential{}, s.err
	}
	for _, c := range s.credentials {
		if c.ID == id {
			return c, nil
		}
	}
	return adminCredential{}, pgx.ErrNoRows
}
func (s *fakeAdminStore) History(_ context.Context, f adminFilter) ([]adminEvent, error) {
	s.filter = f
	return s.events, s.err
}
func adminTestConfig(t *testing.T) *Config {
	t.Helper()
	c, err := LoadConfig(strings.NewReader(validConfig()))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("correct password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	c.Admin.Enabled = true
	c.Admin.Username = "admin"
	c.Admin.PasswordHash = string(hash)
	return c
}
func adminTestHandler(t *testing.T, c *Config, s adminStore) http.Handler {
	t.Helper()
	h, err := newAdmin(c, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func adminRequest(h http.Handler, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://admin.example"+path, strings.NewReader(body))
	if method == "POST" {
		r.Header.Set("Origin", "https://admin.example")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func testAdminCookie(c *Config) *http.Cookie {
	a := &adminUI{config: c}
	return &http.Cookie{Name: adminCookieName, Value: a.cookieValue(time.Now())}
}
func TestAdminLoginAndIsolation(t *testing.T) {
	c := adminTestConfig(t)
	store := &fakeAdminStore{}
	h := adminTestHandler(t, c, store)
	for _, path := range []string{"/admin/configuration", "/admin/credentials", "/admin/history", "/admin/credentials/019c0000-0000-7000-8000-000000000001"} {
		w := adminRequest(h, "GET", path, "", nil)
		if w.Code != 303 || w.Header().Get("Location") != "/admin/login" {
			t.Fatalf("unprotected %s: %d", path, w.Code)
		}
	}
	w := adminRequest(h, "POST", "/admin/login", "username=admin&password=wrong", nil)
	if w.Code != 401 || len(w.Result().Cookies()) != 0 {
		t.Fatal("wrong password accepted")
	}
	w = adminRequest(h, "POST", "/admin/login", "username=admin&password=correct+password", nil)
	if w.Code != 303 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/admin" || cookie.Domain != "" || cookie.MaxAge != 2592000 {
		t.Fatalf("cookie attributes: %+v", cookie)
	}
	second := adminTestHandler(t, c, store)
	w = adminRequest(second, "GET", "/admin/configuration", "", cookie)
	if w.Code != 200 {
		t.Fatal("cookie rejected by new node")
	}
	if strings.Contains(w.Body.String(), c.Admin.PasswordHash) {
		t.Fatal("hash rendered")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cache enabled")
	}
	if w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("same-origin form submissions must preserve Origin")
	}
	integration := Handler(&fakePasskeys{}, func(context.Context) error { return nil }, slog.Default(), second)
	if got := adminRequest(integration, "GET", "/v1/credentials?application=shop&subject=alice", "", cookie).Code; got != 403 {
		t.Fatalf("cookie bypassed mTLS: %d", got)
	}
	w = adminRequest(h, "POST", "/admin/logout", "", cookie)
	if w.Code != 303 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout did not clear cookie")
	}
	if adminRequest(h, "GET", "/admin/configuration", "", cookie).Code != 200 {
		t.Fatal("stateless cookie unexpectedly revoked")
	}
	c.Admin.Enabled = false
	disabled, err := newAdmin(c, store, slog.Default())
	if err != nil || disabled != nil {
		t.Fatal("disabled admin registered")
	}
	integration = Handler(&fakePasskeys{}, func(context.Context) error { return nil }, slog.Default(), disabled)
	if adminRequest(integration, "GET", "/admin/login", "", nil).Code != 404 {
		t.Fatal("disabled login exposed")
	}
}
func TestAdminCookieValidation(t *testing.T) {
	c := adminTestConfig(t)
	now := time.Unix(1800000000, 0)
	a := &adminUI{config: c, now: func() time.Time { return now }}
	good := a.cookieValue(now)
	if !a.validCookie(good) {
		t.Fatal("valid cookie rejected")
	}
	for _, bad := range []string{"", good + "x", strings.Replace(good, "v1.", "v2.", 1), good[:len(good)-2] + "zz", strings.Repeat("x", 10000), a.cookieValue(now.Add(-adminCookieAge))} {
		if a.validCookie(bad) {
			t.Fatal("bad cookie accepted")
		}
	}
	parts := strings.Split(good, ".")
	parts[1] = "1900000000"
	if a.validCookie(strings.Join(parts, ".")) {
		t.Fatal("expiry tampering accepted")
	}
	c.Admin.Username = "other"
	if a.validCookie(good) {
		t.Fatal("changed username accepted")
	}
	c.Admin.Username = "admin"
	c.Admin.PasswordHash += "changed"
	if a.validCookie(good) {
		t.Fatal("changed hash accepted")
	}
}
func TestAdminOriginAndRateLimit(t *testing.T) {
	c := adminTestConfig(t)
	h := adminTestHandler(t, c, &fakeAdminStore{})
	for _, origin := range []string{"", "null", "https://evil.example", "http://admin.example", "https://admin.example/path"} {
		r := httptest.NewRequest("POST", "https://admin.example/admin/login", strings.NewReader("username=admin&password=correct+password"))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("origin %q: %d", origin, w.Code)
		}
	}
	for i := 0; i < 5; i++ {
		if adminRequest(h, "POST", "/admin/login", "username=admin&password=wrong", nil).Code != 401 {
			t.Fatal("early rate limit")
		}
	}
	w := adminRequest(h, "POST", "/admin/login", "username=admin&password=correct+password", nil)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("missing rate limit")
	}
	now := time.Unix(1800000000, 0)
	a := &adminUI{now: func() time.Time { return now }, refill: now}
	if a.allowLogin() {
		t.Fatal("empty bucket allowed")
	}
	now = now.Add(12 * time.Second)
	if !a.allowLogin() || a.allowLogin() {
		t.Fatal("incorrect refill")
	}
	fresh := adminTestHandler(t, c, &fakeAdminStore{})
	for _, body := range []string{"username=admin&username=admin&password=x", "username=admin&password=" + strings.Repeat("x", 4096), "username=%ZZ&password=x"} {
		if adminRequest(fresh, "POST", "/admin/login", body, nil).Code != 400 {
			t.Fatal("malformed form accepted")
		}
	}
}
func TestAdminPages(t *testing.T) {
	c := adminTestConfig(t)
	id := "019c0000-0000-7000-8000-000000000001"
	store := &fakeAdminStore{credentials: []adminCredential{{Credential: passkeys.Credential{ID: id, Application: "removed", Subject: "<script>alert('x')</script>", CreatedAt: time.Now()}}}, events: []adminEvent{{ID: id, Application: "removed", Subject: "alice", Credential: id, Kind: "authentication.finish", Result: "succeeded", Time: time.Now(), CredentialExists: true}}}
	h := adminTestHandler(t, c, store)
	cookie := testAdminCookie(c)
	for _, path := range []string{"/admin/credentials", "/admin/credentials/" + id, "/admin/history", "/admin/configuration"} {
		w := adminRequest(h, "GET", path, "", cookie)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "<script>") {
			t.Fatal("unescaped HTML")
		}
	}
	w := adminRequest(h, "GET", "/admin/credentials/"+id, "", cookie)
	if !strings.Contains(w.Body.String(), "History for this subject") || !strings.Contains(w.Body.String(), "authentication.finish") || strings.Contains(w.Body.String(), "Back to results") {
		t.Fatal("missing detail navigation/history")
	}
	if store.filter.Credential != id {
		t.Fatal("detail history not scoped to credential")
	}
	store.events[0].CredentialExists = false
	w = adminRequest(h, "GET", "/admin/history", "", cookie)
	if strings.Contains(w.Body.String(), "(deleted)") || strings.Contains(w.Body.String(), "/admin/credentials/"+id) {
		t.Fatal("deleted credential linked")
	}
	w = adminRequest(h, "GET", "/admin/credentials/019c0000-0000-7000-8000-000000000002", "", cookie)
	if w.Code != 404 {
		t.Fatal("unknown credential")
	}
	store.err = fmt.Errorf("secret database password")
	w = adminRequest(h, "GET", "/admin/history", "", cookie)
	if w.Code != 500 || strings.Contains(w.Body.String(), "secret database password") {
		t.Fatal("database failure leaked")
	}
}
func TestAdminFiltersAndPagination(t *testing.T) {
	for _, q := range []string{"subject=a&subject=b", "extra=x", "subject=%00", "from=2026-02-30", "from=2026-09-07&to=2026-09-06", "credential=invalid", "cursor=broken"} {
		values, _ := url.ParseQuery(q)
		if _, err := parseAdminFilter(values, true); err == nil {
			t.Fatalf("accepted %s", q)
		}
	}
	values, _ := url.ParseQuery("application=removed&subject=alice&from=2026-09-06&to=2026-09-06")
	if _, err := parseAdminFilter(values, true); err != nil {
		t.Fatal(err)
	}
	if _, err := parseAdminFilter(values, false); err == nil {
		t.Fatal("credential date accepted")
	}
	id := "019c0000-0000-7000-8000-000000000001"
	now := time.Now().UTC().Truncate(time.Microsecond)
	raw := cursorValue(id, now, true)
	f, err := parseAdminFilter(url.Values{"cursor": {raw}}, true)
	if err != nil || f.Cursor.ID != id || !f.Cursor.Previous || !f.Cursor.Time.Equal(now) {
		t.Fatal("cursor round trip", err)
	}
	invalid := base64.RawURLEncoding.EncodeToString([]byte("next|invalid|" + id))
	if _, err = parseAdminFilter(url.Values{"cursor": {invalid}}, true); err == nil {
		t.Fatal("invalid cursor timestamp")
	}
	rows := make([]int, 21)
	for i := range rows {
		rows[i] = i
	}
	page, prev, next := adminPage(rows, adminCursor{})
	if len(page) != 20 || prev || !next {
		t.Fatal("first page")
	}
	page, prev, next = adminPage(rows, adminCursor{ID: id, Previous: true})
	if len(page) != 20 || page[0] != 19 || !prev || !next {
		t.Fatal("previous page")
	}

}

func TestAdminSubjectLinks(t *testing.T) {
	c := adminTestConfig(t)
	first := "019c0000-0000-7000-8000-000000000001"
	second := "019c0000-0000-7000-8000-000000000002"
	store := &fakeAdminStore{}
	for _, id := range []string{first, second} {
		store.credentials = append(store.credentials, adminCredential{Credential: passkeys.Credential{ID: id, Subject: "alice"}})
	}
	h := adminTestHandler(t, c, store)
	cookie := testAdminCookie(c)
	body := adminRequest(h, "GET", "/admin/credentials", "", cookie).Body.String()
	for _, id := range []string{first, second} {
		if !strings.Contains(body, `<a href="/admin/credentials/`+id+`">alice</a>`) {
			t.Fatal("subject must link to its individual credential")
		}
	}
	if strings.Contains(body, "Credential ID") || strings.Contains(body, "return=") {
		t.Fatal("obsolete credential table navigation")
	}
	for _, event := range []adminEvent{
		{Subject: "alice", Credential: first, CredentialExists: true},
		{Subject: "alice", Credential: first},
		{Subject: "alice"},
	} {
		store.events = []adminEvent{event}
		body = adminRequest(h, "GET", "/admin/history", "", cookie).Body.String()
		linked := strings.Contains(body, `<a href="/admin/credentials/`+first+`">alice</a>`)
		if linked != event.CredentialExists || strings.Contains(body, "(deleted)") || strings.Contains(body, "<th>Credential</th>") || strings.Contains(body, "?application=") {
			t.Fatal("incorrect history subject navigation")
		}
	}
	store.credentials = nil
	store.events = nil
	for path, colspan := range map[string]string{"/admin/credentials": "4", "/admin/history": "6"} {
		body = adminRequest(h, "GET", path, "", cookie).Body.String()
		if !strings.Contains(body, `colspan="`+colspan+`"`) {
			t.Fatal("incorrect empty table width")
		}
	}
}
