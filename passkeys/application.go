package passkeys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Application struct {
	Code    string   `json:"code"`
	Name    string   `json:"name"`
	RPID    string   `json:"rpId"`
	Origins []string `json:"origins"`
	Clients []string `json:"clients"`
}

var applicationCode = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func ValidApplicationCode(s string) bool {
	return applicationCode.MatchString(s)
}
func ValidSubject(s string) bool {
	return len(s) > 0 && len(s) <= 256 && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func UserHandle(application, subject string) []byte {
	h := sha256.Sum256([]byte(application + "\x00" + subject))
	return h[:]
}
func NewToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func TokenHash(token string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(b) != 32 {
		return nil, InvalidRequest
	}
	h := sha256.Sum256([]byte(token))
	return h[:], nil
}
func (a Application) Authorize(fingerprint string) error {
	for _, f := range a.Clients {
		if f == fingerprint && f != "" {
			return nil
		}
	}
	return Forbidden
}
