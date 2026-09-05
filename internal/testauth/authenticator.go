// Package testauth supplies a small Ed25519 authenticator fixture for Passkey Server tests.
package testauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

type Authenticator struct {
	ID      []byte
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func New(t testing.TB) *Authenticator {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	rand.Read(id)
	return &Authenticator{id, key, pub}
}
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func encode(t testing.TB, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func cbor(t testing.TB, v any) []byte {
	t.Helper()
	data, err := webauthncbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func challenge(t testing.TB, options jsontext.Value) string {
	t.Helper()
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		t.Fatal(err)
	}
	if o.PublicKey.Challenge == "" {
		t.Fatal("missing challenge")
	}
	return o.PublicKey.Challenge
}
func (a *Authenticator) Register(t testing.TB, options jsontext.Value, rp, origin string) jsontext.Value {
	t.Helper()
	hash := sha256.Sum256([]byte(rp))
	data := append([]byte(nil), hash[:]...)
	data = append(data, 0x5d, 0, 0, 0, 0)
	data = append(data, make([]byte, 16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(a.ID)))
	data = append(data, a.ID...)
	key := cbor(t, map[int]any{1: 1, 3: -8, -1: 6, -2: []byte(a.public)})
	data = append(data, key...)
	attestation := cbor(t, map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
	client := encode(t, map[string]any{
		"type": "webauthn.create", "challenge": challenge(t, options),
		"origin": origin, "crossOrigin": false,
	})
	return encode(t, map[string]any{
		"id": b64(a.ID), "rawId": b64(a.ID), "type": "public-key",
		"clientExtensionResults": map[string]any{"credProps": map[string]any{"rk": true}},
		"response": map[string]any{
			"clientDataJSON": b64(client), "attestationObject": b64(attestation),
			"transports": []string{"internal"},
		},
	})
}
func (a *Authenticator) Authenticate(
	t testing.TB, options jsontext.Value, rp, origin string, handle []byte, counter uint32, uv bool,
) jsontext.Value {
	t.Helper()
	hash := sha256.Sum256([]byte(rp))
	data := append([]byte(nil), hash[:]...)
	flags := byte(0x19)
	if uv {
		flags |= 4
	}
	data = append(data, flags)
	data = binary.BigEndian.AppendUint32(data, counter)
	client := encode(t, map[string]any{
		"type": "webauthn.get", "challenge": challenge(t, options),
		"origin": origin, "crossOrigin": false,
	})
	clientHash := sha256.Sum256(client)
	signed := append(append([]byte(nil), data...), clientHash[:]...)
	signature := ed25519.Sign(a.private, signed)
	return encode(t, map[string]any{
		"id": b64(a.ID), "rawId": b64(a.ID), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64(client), "authenticatorData": b64(data),
			"signature": b64(signature), "userHandle": b64(handle),
		},
	})
}
