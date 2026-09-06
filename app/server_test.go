package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"--version", "--config", "missing.json"}} {
		var stdout, stderr bytes.Buffer
		if err := Run(context.Background(), args, &stdout, &stderr); err != nil {
			t.Fatal(err)
		}
		if stdout.String() != "passkey-server dev\n" || stderr.Len() != 0 {
			t.Fatalf("stdout=%q stderr=%q", &stdout, &stderr)
		}
	}
}
func TestStartupStillRequiresConfiguration(t *testing.T) {
	for _, args := range [][]string{nil, {"--version=false"}, {"--version", "extra"}} {
		var stdout, stderr bytes.Buffer
		err := Run(context.Background(), args, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "config and database-dsn") || stdout.Len() != 0 {
			t.Fatalf("unexpected startup: %v, %q", err, &stdout)
		}
	}
}
