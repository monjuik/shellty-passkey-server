package passkeys

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"time"
	"unicode/utf8"
	"uuid"
)

// Commands and Queries describe the capability API without transport types.
type Commands interface {
	Start(context.Context, Kind, string, string, string, string) (StartResult, error)
	Finish(context.Context, Kind, string, jsontext.Value, string) (FinishResult, error)
	Delete(context.Context, string, string, string, string) error
}
type Queries interface {
	Credentials(context.Context, string, string, string) ([]Credential, error)
}

// Repository completes each ceremony and its credential/history changes atomically.
// Authorization must run before inspecting state or consuming the ceremony.
type Repository interface {
	Credentials(context.Context, string, string) ([]Credential, error)
	Start(context.Context, Kind, Ceremony) error
	Finish(
		context.Context, Kind, []byte,
		func(Ceremony) error, func(Ceremony, []Credential) (Credential, error),
	) (Credential, error)
	Delete(context.Context, string, string, string) error
}
type WebAuthn interface {
	Begin(Kind, Application, string, string, []Credential) (jsontext.Value, []byte, error)
	Verify(Kind, Application, Ceremony, []Credential, jsontext.Value) (Credential, error)
}
type Service struct {
	applications map[string]Application
	repository   Repository
	webauthn     WebAuthn
}

func NewService(applications []Application, repository Repository, webauthn WebAuthn) *Service {
	apps := make(map[string]Application, len(applications))
	for _, a := range applications {
		a.Clients = append([]string(nil), a.Clients...)
		a.Origins = append([]string(nil), a.Origins...)
		apps[a.Code] = a
	}
	return &Service{apps, repository, webauthn}
}
func (s *Service) authorize(code, fingerprint string) (Application, error) {
	a, ok := s.applications[code]
	if !ok {
		return a, ApplicationNotFound
	}
	return a, a.Authorize(fingerprint)
}
func (s *Service) Start(
	ctx context.Context, k Kind, application, subject, displayName, fingerprint string,
) (StartResult, error) {
	if !k.Valid() || !ValidApplicationCode(application) || !ValidSubject(subject) ||
		len(displayName) > 256 || !utf8.ValidString(displayName) {
		return StartResult{}, InvalidRequest
	}
	a, err := s.authorize(application, fingerprint)
	if err != nil {
		return StartResult{}, err
	}
	credentials, err := s.repository.Credentials(ctx, application, subject)
	if err != nil {
		return StartResult{}, err
	}
	if k == Authentication && len(credentials) == 0 {
		return StartResult{}, k.Invalid()
	}
	if displayName == "" {
		displayName = subject
	}
	options, state, err := s.webauthn.Begin(k, a, subject, displayName, credentials)
	if err != nil {
		return StartResult{}, err
	}
	token := NewToken()
	hash, _ := TokenHash(token)
	now := time.Now().UTC()
	c := Ceremony{
		ID:          uuid.NewV7().String(),
		Application: application,
		Subject:     subject,
		RPID:        a.RPID,
		TokenHash:   hash,
		WebAuthn:    state,
		State:       "pending",
		CreatedAt:   now,
		ExpiresAt:   now.Add(CeremonyTTL),
	}
	if err = s.repository.Start(ctx, k, c); err != nil {
		return StartResult{}, err
	}
	return StartResult{token, options, c.ExpiresAt}, nil
}
func (s *Service) Finish(
	ctx context.Context, k Kind, token string, response jsontext.Value, fingerprint string,
) (FinishResult, error) {
	if !k.Valid() || len(response) == 0 || len(response) > 64<<10 ||
		!response.IsValid() || bytes.TrimSpace(response)[0] != '{' {
		return FinishResult{}, InvalidRequest
	}
	hash, err := TokenHash(token)
	if err != nil {
		return FinishResult{}, err
	}
	authorize := func(c Ceremony) error {
		a, err := s.authorize(c.Application, fingerprint)
		if err != nil {
			return err
		}
		if a.RPID != c.RPID {
			return k.Invalid()
		}
		return nil
	}
	verify := func(c Ceremony, credentials []Credential) (Credential, error) {
		return s.webauthn.Verify(k, s.applications[c.Application], c, credentials, response)
	}
	credential, err := s.repository.Finish(ctx, k, hash, authorize, verify)
	if err != nil {
		return FinishResult{}, err
	}
	return FinishResult{credential.Application, credential.Subject, credential.ID}, nil
}
func (s *Service) Credentials(ctx context.Context, application, subject, fingerprint string) ([]Credential, error) {
	if !ValidApplicationCode(application) || !ValidSubject(subject) {
		return nil, InvalidRequest
	}
	if _, err := s.authorize(application, fingerprint); err != nil {
		return nil, err
	}
	return s.repository.Credentials(ctx, application, subject)
}
func (s *Service) Delete(ctx context.Context, application, subject, id, fingerprint string) error {
	if !ValidApplicationCode(application) || !ValidSubject(subject) {
		return InvalidRequest
	}
	u, err := uuid.Parse(id)
	if err != nil || u.String() != id {
		return InvalidRequest
	}
	if _, err = s.authorize(application, fingerprint); err != nil {
		return err
	}
	return s.repository.Delete(ctx, application, subject, id)
}
