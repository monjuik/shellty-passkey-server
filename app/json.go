package app

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
)

// strictJSON accepts one object with exact field names. The v2 decoder rejects
// duplicate names and invalid UTF-8; the token pass preserves our depth limit.
func strictJSON(data []byte, target any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("expected JSON object")
	}
	decoder := jsontext.NewDecoder(bytes.NewReader(data))
	for {
		depth := decoder.StackDepth()
		token, err := decoder.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// The root value is depth zero. Empty containers at depth 32 remain valid,
		// just as with the previous recursive validator; their children do not.
		if depth > 32 && token.Kind() != '}' && token.Kind() != ']' {
			return fmt.Errorf("JSON nesting limit exceeded")
		}
	}
	return json.Unmarshal(data, target, json.RejectUnknownMembers(true))
}
