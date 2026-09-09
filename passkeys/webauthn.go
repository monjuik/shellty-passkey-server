package passkeys

import (
	"bytes"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"uuid"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthn JSON uses v1 compatibility options to preserve wire and stored records.
// WebAuthnAdapter owns all library types and persists complete library records.
type WebAuthnAdapter struct{ rps map[string]*wa.WebAuthn }

func NewWebAuthn(applications []Application) (*WebAuthnAdapter, error) {
	adapter := &WebAuthnAdapter{rps: map[string]*wa.WebAuthn{}}
	for _, a := range applications {
		required := true
		rp, err := wa.New(
			&wa.Config{
				RPID:                  a.RPID,
				RPDisplayName:         a.Name,
				RPOrigins:             append([]string(nil), a.Origins...),
				AttestationPreference: protocol.PreferNoAttestation,
				AuthenticatorSelection: protocol.AuthenticatorSelection{
					ResidentKey:        protocol.ResidentKeyRequirementRequired,
					RequireResidentKey: &required,
					UserVerification:   protocol.VerificationRequired,
				},
				Timeouts: wa.TimeoutsConfig{
					Registration: wa.TimeoutConfig{Enforce: true, Timeout: CeremonyTTL},
					Login:        wa.TimeoutConfig{Enforce: true, Timeout: CeremonyTTL},
				},
			},
		)
		if err != nil {
			return nil, fmt.Errorf("application %s WebAuthn config: %w", a.Code, err)
		}
		adapter.rps[a.Code] = rp
	}
	return adapter, nil
}

type webauthnUser struct {
	handle      []byte
	name        string
	credentials []wa.Credential
}

func (u webauthnUser) WebAuthnID() []byte                   { return u.handle }
func (u webauthnUser) WebAuthnName() string                 { return u.name }
func (u webauthnUser) WebAuthnDisplayName() string          { return u.name }
func (u webauthnUser) WebAuthnCredentials() []wa.Credential { return u.credentials }
func makeWebAuthnUser(a Application, subject, name string, credentials []Credential) (webauthnUser, error) {
	u := webauthnUser{handle: UserHandle(a.Code, subject), name: name}
	for _, c := range credentials {
		if c.RPID != a.RPID {
			continue
		}
		var value wa.Credential
		if err := json.Unmarshal(c.WebAuthn, &value, jsonv1.DefaultOptionsV1()); err != nil {
			return u, fmt.Errorf("decode stored credential: %w", err)
		}
		u.credentials = append(u.credentials, value)
	}
	return u, nil
}
func (w *WebAuthnAdapter) Begin(
	k Kind, a Application, subject, name string, credentials []Credential,
) (jsontext.Value, []byte, error) {
	rp := w.rps[a.Code]
	if rp == nil {
		return nil, nil, ApplicationNotFound
	}
	u, err := makeWebAuthnUser(a, subject, name, credentials)
	if err != nil {
		return nil, nil, err
	}
	var options any
	var session *wa.SessionData
	if k == Registration {
		excludes := make([]protocol.CredentialDescriptor, 0, len(u.credentials))
		for _, c := range u.credentials {
			excludes = append(excludes, c.Descriptor())
		}
		options, session, err = rp.BeginRegistration(
			u,
			wa.WithCredentialParameters(wa.CredentialParametersRecommendedL3()),
			wa.WithExclusions(excludes),
			wa.WithExtensions(wa.WithExtensionCredProps()),
		)
	} else {
		options, session, err = rp.BeginLogin(u, wa.WithUserVerification(protocol.VerificationRequired))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("begin WebAuthn: %w", err)
	}
	encoded, err := json.Marshal(options, jsonv1.DefaultOptionsV1())
	if err != nil {
		return nil, nil, err
	}
	state, err := json.Marshal(session, jsonv1.DefaultOptionsV1())
	return encoded, state, err
}
func (w *WebAuthnAdapter) Verify(
	k Kind, a Application, c Ceremony, credentials []Credential, response jsontext.Value,
) (Credential, error) {
	rp := w.rps[a.Code]
	if rp == nil {
		return Credential{}, ApplicationNotFound
	}
	u, err := makeWebAuthnUser(a, c.Subject, c.Subject, credentials)
	if err != nil {
		return Credential{}, err
	}
	var session wa.SessionData
	if err = json.Unmarshal(c.WebAuthn, &session, jsonv1.DefaultOptionsV1()); err != nil {
		return Credential{}, fmt.Errorf("decode stored ceremony: %w", err)
	}
	var value *wa.Credential
	if k == Registration {
		parsed, e := protocol.ParseCredentialCreationResponseBytes(response)
		if e != nil {
			return Credential{}, &DiagnosticError{Code: k.Invalid(), Cause: e}
		}
		if !slices.Contains(a.Origins, parsed.Response.CollectedClientData.Origin) {
			return Credential{}, &DiagnosticError{Code: k.Invalid(), Cause: errors.New("origin mismatch")}
		}
		value, err = rp.CreateCredential(u, session, parsed)

		// An absent credProps.rk means unknown, not false.
		// Reject only an explicitly non-discoverable credential.
		if err == nil && value.Extensions.RK != nil && !*value.Extensions.RK {
			return Credential{}, &DiagnosticError{Code: k.Invalid(), Cause: errors.New("credential is not discoverable")}
		}
	} else {
		parsed, e := protocol.ParseCredentialRequestResponseBytes(response)
		if e != nil {
			return Credential{}, &DiagnosticError{Code: k.Invalid(), Cause: e}
		}
		if !slices.Contains(a.Origins, parsed.Response.CollectedClientData.Origin) {
			return Credential{}, &DiagnosticError{Code: k.Invalid(), Cause: errors.New("origin mismatch")}
		}
		value, err = rp.ValidateLogin(u, session, parsed)
	}
	if err != nil {
		return Credential{}, &DiagnosticError{Code: k.Invalid(), Cause: err}
	}
	// The library reports a non-increasing nonzero counter as a clone warning.
	// Treat it as a failed assertion; 0 -> 0 remains valid for synced passkeys.
	if value.Authenticator.CloneWarning {
		return Credential{}, &DiagnosticError{Code: k.Invalid(), Cause: errors.New("authenticator clone warning")}
	}
	mapped, err := mapCredential(value)
	if err != nil {
		return Credential{}, &DiagnosticError{Code: k.Invalid(), Cause: err}
	}
	mapped.Application = c.Application
	mapped.Subject = c.Subject
	mapped.RPID = c.RPID
	if k == Registration {
		mapped.ID = uuid.NewV7().String()
	} else {
		for _, old := range credentials {
			if bytes.Equal(old.WebAuthnID, mapped.WebAuthnID) && old.RPID == c.RPID {
				mapped.ID = old.ID
				mapped.CreatedAt = old.CreatedAt
				break
			}
		}
		if mapped.ID == "" {
			return Credential{}, &DiagnosticError{Code: k.Invalid(), Cause: errors.New("credential was not found for subject")}
		}
	}
	return mapped, nil
}
func mapCredential(c *wa.Credential) (Credential, error) {
	key, err := webauthncose.ParsePublicKey(c.PublicKey)
	if err != nil {
		return Credential{}, err
	}
	var alg int64
	switch k := key.(type) {
	case webauthncose.OKPPublicKeyData:
		alg = k.Algorithm
	case webauthncose.EC2PublicKeyData:
		alg = k.Algorithm
	case webauthncose.RSAPublicKeyData:
		alg = k.Algorithm
	}
	offered := false
	for _, p := range wa.CredentialParametersRecommendedL3() {
		if int64(p.Algorithm) == alg {
			offered = true
		}
	}
	if !offered {
		return Credential{}, Registration.Invalid()
	}
	data, err := json.Marshal(c, jsonv1.DefaultOptionsV1())
	if err != nil {
		return Credential{}, err
	}
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return Credential{
		WebAuthnID:     c.ID,
		PublicKey:      c.PublicKey,
		Algorithm:      alg,
		SignCount:      c.Authenticator.SignCount,
		Transports:     transports,
		AAGUID:         c.Authenticator.AAGUID,
		BackupEligible: c.Flags.BackupEligible,
		BackupState:    c.Flags.BackupState,
		WebAuthn:       data,
	}, nil
}
