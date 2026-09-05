package passkeys

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/monjuik/shellty-passkey-server/internal/testauth"
)

// legacyJSON checks the old decoder can read new output without changing its
// JSON meaning. Its result also supplies old-encoded records to the new reader.
func legacyJSON(t *testing.T, data []byte, target any) []byte {
	t.Helper()
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
	old, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	var got, want any
	if err = json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(old, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy JSON mismatch:\n%s\n%s", data, old)
	}
	return old
}

func TestWebAuthnJSONCompatibility(t *testing.T) {
	a := testApplication()
	adapter, err := NewWebAuthn([]Application{a})
	if err != nil {
		t.Fatal(err)
	}
	options, state, err := adapter.Begin(Registration, a, "alice", "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	legacyJSON(t, options, new(protocol.CredentialCreation))
	oldState := legacyJSON(t, state, new(wa.SessionData))
	ceremony := Ceremony{Application: a.Code, Subject: "alice", RPID: a.RPID, WebAuthn: oldState}
	authenticator := testauth.New(t)
	response := authenticator.Register(t, options, a.RPID, a.Origins[0])
	credential, err := adapter.Verify(Registration, a, ceremony, nil, response)
	if err != nil {
		t.Fatal(err)
	}
	credential.WebAuthn = legacyJSON(t, credential.WebAuthn, new(wa.Credential))
	// Exercise byte slices, extensions, backup flags, omitted values and counter
	// updates through records encoded by the original codec.
	options, state, err = adapter.Begin(Authentication, a, "alice", "Alice", []Credential{credential})
	if err != nil {
		t.Fatal(err)
	}
	legacyJSON(t, options, new(protocol.CredentialAssertion))
	ceremony.WebAuthn = legacyJSON(t, state, new(wa.SessionData))
	assertion := authenticator.Authenticate(t, options, a.RPID, a.Origins[0], UserHandle(a.Code, "alice"), 1, true)
	updated, err := adapter.Verify(Authentication, a, ceremony, []Credential{credential}, assertion)
	if err != nil {
		t.Fatal(err)
	}
	legacyJSON(t, updated.WebAuthn, new(wa.Credential))
	if updated.ID != credential.ID || updated.SignCount != 1 {
		t.Fatal("credential state changed")
	}
}
