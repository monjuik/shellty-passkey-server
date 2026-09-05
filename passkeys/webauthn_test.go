package passkeys

import (
	"bytes"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/monjuik/shellty-passkey-server/internal/testauth"
)

func testApplication() Application {
	return Application{Code: "shop", Name: "Shop", RPID: "shop.example.com", Origins: []string{"https://shop.example.com"}, Clients: []string{"test-client"}}
}
func TestTokensAndHandle(t *testing.T) {
	token := NewToken()
	hash, err := TokenHash(token)
	if err != nil || len(hash) != 32 || bytes.Equal(hash, []byte(token)) {
		t.Fatal("invalid token hash", err)
	}
	other, _ := TokenHash(NewToken())
	if bytes.Equal(hash, other) {
		t.Fatal("reused token")
	}
	for _, bad := range []string{"", token + "=", token[:42], "!" + token[1:]} {
		if _, err = TokenHash(bad); err == nil {
			t.Fatal("accepted malformed token")
		}
	}
	// A fixed vector protects the persistent user-handle contract.
	if got := hex.EncodeToString(UserHandle("shop", "customer-87231")); got != "48ae78a1d6ea326364e22f95a1b1600487b4889113ea99f3a5d308140ef721d7" {
		t.Fatalf("user handle: %s", got)
	}
	if bytes.Equal(UserHandle("a", "bc"), UserHandle("ab", "c")) {
		t.Fatal("ambiguous handle")
	}
}
func TestCeremonyState(t *testing.T) {
	now := time.Now()
	c := Ceremony{State: "pending", ExpiresAt: now.Add(time.Second)}
	if c.Check(Registration, now) != nil {
		t.Fatal("pending rejected")
	}
	if !errors.Is(c.Check(Registration, c.ExpiresAt), Registration.Expired()) {
		t.Fatal("expiry boundary")
	}
	c.State = "failed"
	if !errors.Is(c.Check(Registration, now), Conflict) {
		t.Fatal("failed ceremony reusable")
	}
}
func TestWebAuthnRoundTrip(t *testing.T) {
	a := testApplication()
	adapter, err := NewWebAuthn([]Application{a})
	if err != nil {
		t.Fatal(err)
	}
	options, state, err := adapter.Begin(Registration, a, "subject", "Customer", nil)
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		PublicKey struct {
			Attestation            string `json:"attestation"`
			AuthenticatorSelection struct {
				ResidentKey      string `json:"residentKey"`
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
			PubKeyCredParams []struct {
				Alg int `json:"alg"`
			} `json:"pubKeyCredParams"`
		} `json:"publicKey"`
	}
	if err = json.Unmarshal(options, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.PublicKey.Attestation != "none" || policy.PublicKey.AuthenticatorSelection.ResidentKey != "required" || policy.PublicKey.AuthenticatorSelection.UserVerification != "required" || len(policy.PublicKey.PubKeyCredParams) != 3 {
		t.Fatalf("unexpected policy: %s", options)
	}
	auth := testauth.New(t)
	c := Ceremony{Application: a.Code, Subject: "subject", RPID: a.RPID, WebAuthn: state}
	response := auth.Register(t, options, a.RPID, a.Origins[0])
	credential, err := adapter.Verify(Registration, a, c, nil, response)
	if err != nil {
		t.Fatal("register", err)
	}
	if credential.Algorithm != -8 || !credential.BackupEligible || !credential.BackupState || !bytes.Equal(credential.WebAuthnID, auth.ID) {
		t.Fatal("credential mapping")
	}

	for _, tc := range []struct {
		name       string
		extensions string
		reject     bool
	}{
		{"absent credProps", `{}`, false},
		{"absent rk", `{"credProps":{}}`, false},
		{"discoverable", `{"credProps":{"rk":true}}`, false},
		{"not discoverable", `{"credProps":{"rk":false}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var payload map[string]jsontext.Value
			if err := json.Unmarshal(response, &payload); err != nil {
				t.Fatal(err)
			}
			payload["clientExtensionResults"] = jsontext.Value(tc.extensions)

			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}

			got, err := adapter.Verify(Registration, a, c, nil, encoded)
			if tc.reject {
				if !errors.Is(err, Registration.Invalid()) {
					t.Fatalf("expected registration_invalid, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}

			// The subsequent login also exercises Safari-style registration.
			if tc.name == "absent credProps" {
				credential = got
			}
		})
	}

	// Reconstruct the adapter as on another node; only persisted state is shared.
	adapter, err = NewWebAuthn([]Application{a})
	if err != nil {
		t.Fatal(err)
	}
	options, state, err = adapter.Begin(Authentication, a, "subject", "Customer", []Credential{credential})
	if err != nil {
		t.Fatal(err)
	}
	c.WebAuthn = state
	response = auth.Authenticate(t, options, a.RPID, a.Origins[0], UserHandle(a.Code, "subject"), 1, true)
	updated, err := adapter.Verify(Authentication, a, c, []Credential{credential}, response)
	if err != nil {
		t.Fatal("authenticate", err)
	}
	if updated.ID != credential.ID || updated.SignCount != 1 {
		t.Fatal("authentication mapping")
	}
	for name, response := range map[string]jsontext.Value{
		"no UV":            auth.Authenticate(t, options, a.RPID, a.Origins[0], UserHandle(a.Code, "subject"), 2, false),
		"wrong origin":     auth.Authenticate(t, options, a.RPID, "https://evil.example.com", UserHandle(a.Code, "subject"), 2, true),
		"wrong RP":         auth.Authenticate(t, options, "evil.example.com", a.Origins[0], UserHandle(a.Code, "subject"), 2, true),
		"wrong subject":    auth.Authenticate(t, options, a.RPID, a.Origins[0], UserHandle(a.Code, "other"), 2, true),
		"counter rollback": auth.Authenticate(t, options, a.RPID, a.Origins[0], UserHandle(a.Code, "subject"), 1, true),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := adapter.Verify(Authentication, a, c, []Credential{updated}, response); !errors.Is(err, Authentication.Invalid()) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
