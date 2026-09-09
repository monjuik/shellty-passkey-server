package passkeys

import (
	"encoding/json/jsontext"
	"time"
)

type Error string

func (e Error) Error() string { return string(e) }

// DiagnosticError preserves a safe public error code while retaining the
// internal cause for committed history events.
type DiagnosticError struct {
	Code  Error
	Cause error
}

func (e *DiagnosticError) Error() string { return string(e.Code) }
func (e *DiagnosticError) Unwrap() error { return e.Code }

const (
	InvalidRequest      Error = "invalid_request"
	Forbidden           Error = "forbidden"
	ApplicationNotFound Error = "application_not_found"
	CredentialNotFound  Error = "credential_not_found"
	Conflict            Error = "conflict"
	InternalError       Error = "internal_error"
)

type Kind string

const (
	Registration   Kind = "registration"
	Authentication Kind = "authentication"
	CeremonyTTL         = 5 * time.Minute
)

func (k Kind) Valid() bool {
	return k == Registration || k == Authentication
}
func (k Kind) NotFound() Error {
	return Error(string(k) + "_not_found")
}
func (k Kind) Expired() Error {
	return Error(string(k) + "_expired")
}
func (k Kind) Invalid() Error {
	if k == Registration {
		return "registration_invalid"
	}
	return "authentication_failed"
}

type Ceremony struct {
	ID, Application, Subject, RPID string
	TokenHash                      []byte
	WebAuthn                       []byte
	State                          string
	CreatedAt, ExpiresAt           time.Time
}

func (c Ceremony) Check(k Kind, now time.Time) error {
	if c.State != "pending" {
		return Conflict
	}
	if !now.Before(c.ExpiresAt) {
		return k.Expired()
	}
	return nil
}

type Credential struct {
	ID             string     `json:"id"`
	Application    string     `json:"application"`
	Subject        string     `json:"subject"`
	RPID           string     `json:"-"`
	WebAuthnID     []byte     `json:"-"`
	PublicKey      []byte     `json:"-"`
	Algorithm      int64      `json:"algorithm"`
	SignCount      uint32     `json:"signCount"`
	Transports     []string   `json:"transports"`
	AAGUID         []byte     `json:"-"`
	BackupEligible bool       `json:"backupEligible"`
	BackupState    bool       `json:"backupState"`
	WebAuthn       []byte     `json:"-"`
	CreatedAt      time.Time  `json:"createdAt"`
	UsedAt         *time.Time `json:"usedAt,omitempty"`
}
type StartResult struct {
	Token     string         `json:"token"`
	Options   jsontext.Value `json:"options"`
	ExpiresAt time.Time      `json:"expiresAt"`
}
type FinishResult struct {
	Application string `json:"application"`
	Subject     string `json:"subject"`
	Credential  string `json:"credential"`
}
