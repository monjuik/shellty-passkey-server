package app

import (
	"encoding/json/v2"
	"strings"
	"testing"
)

func validConfig() string {
	return `{"admin":{"enabled":false},"applications":[{"code":"shop","name":"Shop","rpId":"shop.example.com","origins":["https://shop.example.com"],"clients":["sha256:` + strings.Repeat("a", 64) + `"]}]}`
}
func TestConfigValidation(t *testing.T) {
	if _, err := LoadConfig(strings.NewReader(validConfig())); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"wrong field case":   strings.Replace(validConfig(), `"rpId"`, `"RPID"`, 1),
		"unknown":            strings.Replace(validConfig(), `"name":"Shop"`, `"name":"Shop","extra":true`, 1),
		"duplicate key":      strings.Replace(validConfig(), `"name":"Shop"`, `"name":"Shop","name":"Other"`, 1),
		"bad code":           strings.Replace(validConfig(), `"code":"shop"`, `"code":"a/b"`, 1),
		"wildcard":           strings.Replace(validConfig(), `https://shop.example.com`, `https://*.shop.example.com`, 1),
		"insecure origin":    strings.Replace(validConfig(), `https://`, `http://`, 1),
		"wrong RP":           strings.Replace(validConfig(), `https://shop.example.com`, `https://evil.example.com`, 1),
		"origin path":        strings.Replace(validConfig(), `https://shop.example.com`, `https://shop.example.com/path`, 1),
		"bad fingerprint":    strings.Replace(validConfig(), strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"missing clients":    strings.Replace(validConfig(), `"sha256:`+strings.Repeat("a", 64)+`"`, ``, 1),
		"admin without hash": strings.Replace(validConfig(), `"enabled":false`, `"enabled":true,"username":"admin"`, 1),
		"trailing":           validConfig() + `{}`,
		"null":               "null",
		"invalid UTF8":       strings.Replace(validConfig(), "Shop", string([]byte{255}), 1),
		"too large":          strings.Repeat(" ", 1<<20) + validConfig(),
	}
	var c Config
	if err := json.Unmarshal([]byte(validConfig()), &c); err != nil {
		t.Fatal(err)
	}
	c.Applications = append(c.Applications, c.Applications[0])
	b, _ := json.Marshal(c)
	cases["duplicate application"] = string(b)
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(strings.NewReader(input)); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}
