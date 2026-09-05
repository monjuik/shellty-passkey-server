package app

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/monjuik/shellty-passkey-server/passkeys"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Admin struct {
		Enabled      bool   `json:"enabled"`
		Username     string `json:"username"`
		PasswordHash string `json:"passwordHash"`
	} `json:"admin"`
	Applications []passkeys.Application `json:"applications"`
}

var fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func LoadConfig(r io.Reader) (*Config, error) {
	var c Config
	b, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil {
		return &c, err
	}
	if len(b) > 1<<20 || !utf8.Valid(b) {
		return &c, fmt.Errorf("config must be UTF-8 and at most 1 MiB")
	}
	if err = strictJSON(b, &c); err != nil {
		return &c, fmt.Errorf("decode config: %w", err)
	}
	if len(c.Applications) == 0 {
		return &c, fmt.Errorf("at least one application is required")
	}
	if c.Admin.Enabled {
		if c.Admin.Username == "" || len(c.Admin.Username) > 256 {
			return &c, fmt.Errorf("invalid admin username")
		}
		if _, err = bcrypt.Cost([]byte(c.Admin.PasswordHash)); err != nil {
			return &c, fmt.Errorf("invalid admin bcrypt hash")
		}
	}
	seen := map[string]bool{}
	for _, a := range c.Applications {
		if !passkeys.ValidApplicationCode(a.Code) || seen[a.Code] {
			return &c, fmt.Errorf("invalid or duplicate application code")
		}
		seen[a.Code] = true
		if a.Name == "" || len(a.Name) > 256 {
			return &c, fmt.Errorf("application %s: invalid name", a.Code)
		}
		if a.RPID == "" || len(a.RPID) > 253 || net.ParseIP(a.RPID) != nil {
			return &c, fmt.Errorf("application %s: invalid RP ID", a.Code)
		}
		for label := range strings.SplitSeq(a.RPID, ".") {
			if !domainLabel.MatchString(label) {
				return &c, fmt.Errorf("application %s: invalid RP ID", a.Code)
			}
		}
		if len(a.Origins) == 0 || len(a.Clients) == 0 {
			return &c, fmt.Errorf("application %s: origins and clients are required", a.Code)
		}
		origins := map[string]bool{}
		for _, origin := range a.Origins {
			u, e := url.Parse(origin)
			if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" ||
				u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(origin, "*#") || origins[origin] {
				return &c, fmt.Errorf("application %s: invalid or duplicate HTTPS origin", a.Code)
			}
			host := u.Hostname()
			if host != a.RPID && !strings.HasSuffix(host, "."+a.RPID) {
				return &c, fmt.Errorf("application %s: origin must belong to RP ID", a.Code)
			}
			origins[origin] = true
		}
		clients := map[string]bool{}
		for _, f := range a.Clients {
			if !fingerprintPattern.MatchString(f) || clients[f] {
				return &c, fmt.Errorf("application %s: invalid or duplicate client fingerprint", a.Code)
			}
			clients[f] = true
		}
	}
	return &c, nil
}
