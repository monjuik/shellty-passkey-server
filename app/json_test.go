package app

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monjuik/shellty-passkey-server/passkeys"
)

func TestStrictJSONV2(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"object", `{"value":{"extension":true}}`, true},
		{"case sensitive", `{"Value":1}`, false},
		{"unknown", `{"other":1}`, false},
		{"duplicate", `{"value":1,"value":2}`, false},
		{"nested duplicate", `{"value":{"x":1,"x":2}}`, false},
		{"invalid UTF8", "{\"value\":\"\xff\"}", false},
		{"invalid surrogate", `{"value":"\ud800"}`, false},
		{"null", `null`, false},
		{"array", `[]`, false},
		{"trailing object", `{} {}`, false},
		{"trailing scalar", `{} 1`, false},
		{"depth boundary", `{"value":` + strings.Repeat("[", 31) + `0` + strings.Repeat("]", 31) + `}`, true},
		{"empty depth boundary", `{"value":` + strings.Repeat("[", 32) + strings.Repeat("]", 32) + `}`, true},
		{"too deep scalar", `{"value":` + strings.Repeat("[", 32) + `0` + strings.Repeat("]", 32) + `}`, false},
		{"too deep container", `{"value":` + strings.Repeat("[", 33) + strings.Repeat("]", 33) + `}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var target struct {
				Value jsontext.Value `json:"value"`
			}
			err := strictJSON([]byte(tc.input), &target)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}

func TestJSONResponseV2(t *testing.T) {
	var logs bytes.Buffer
	api := &API{logger: slog.New(slog.NewTextHandler(&logs, nil))}
	rec := httptest.NewRecorder()
	api.writeJSON(rec, 200, map[string]any{"credentials": []passkeys.Credential{}})
	if rec.Code != 200 || rec.Body.String() != "{\"credentials\":[]}\n" {
		t.Fatal(rec.Body.String())
	}
	rec = httptest.NewRecorder()
	api.writeJSON(rec, 200, passkeys.Credential{ID: "test", Transports: []string{}})
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(rec.Body.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["usedAt"]; ok {
		t.Fatal("absent usedAt emitted")
	}
	if string(fields["signCount"]) != "0" || string(fields["backupState"]) != "false" {
		t.Fatal("zero-valued fields omitted")
	}
	rec = httptest.NewRecorder()
	api.writeJSON(rec, 200, passkeys.StartResult{Options: jsontext.Value(`{"publicKey":{}}`)})
	if !strings.Contains(rec.Body.String(), `"options":{"publicKey":{}}`) {
		t.Fatal("raw options changed")
	}
	rec = httptest.NewRecorder()
	api.writeJSON(rec, 201, map[string]any{"secret": make(chan int)})
	if rec.Code != 500 || rec.Body.String() != "{\"error\":\"internal_error\"}\n" {
		t.Fatalf("partial success on encoding failure: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), "secret") {
		t.Fatal("encoding error leaked input")
	}
}
