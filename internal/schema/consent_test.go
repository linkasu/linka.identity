package schema

import (
	"strings"
	"testing"
	"time"
)

func TestConsentSchemaTwoToThreeAndFailure(t *testing.T) {
	e := &migrationExecutor{exists: true, version: 2, fail: "CREATE TABLE IF NOT EXISTS installation_consent_requests"}
	if err := Apply(t.Context(), e, time.Now()); err == nil || e.version != 2 {
		t.Fatal("failed DDL promoted schema")
	}
	e.fail, e.commands = "", nil
	if err := Apply(t.Context(), e, time.Now()); err != nil || e.version != 3 {
		t.Fatalf("2 -> 3: %v", err)
	}
	joined := strings.Join(e.commands, "\n")
	for _, table := range []string{"installation_consent_epochs", "installation_consent_requests"} {
		if !strings.Contains(joined, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatal("missing additive table")
		}
	}
	if !strings.Contains(e.commands[len(e.commands)-1], "schema_meta") {
		t.Fatal("metadata promotion is not final")
	}
}
