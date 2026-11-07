package installationbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

func TestBrokerUnknownBootstrap(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repository := newFakeRepository()
	signer, err := token.NewSigner(bytes.Repeat([]byte{1}, 32), "active", "issuer", time.Minute, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pairwiseIDs, err := pairwise.New(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	broker, err := New(repository, signer, pairwiseIDs, Config{
		Products:             map[string]Product{"linka-plays": {Audience: "metric", AdditionalPolicies: map[string]struct{}{"v2": {}}}},
		RegistrationProducts: map[string]struct{}{"linka-plays": {}}, PolicyVersion: "v1", RefreshTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker.now = func() time.Time { return now }
	input := RegisterInput{RequestID: "11111111-1111-4111-8111-111111111111", ProductID: "linka-plays", Platform: "android", Preference: "unknown", PolicyVersion: "v2", RecordedAt: now.Add(123 * time.Nanosecond)}
	registered, err := broker.Register(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if registered.Preference != "unknown" || registered.MetricsToken != nil || !pairwise.Valid(registered.InstallationKey) || registered.RefreshToken == "" || registered.PolicyVersion != "v2" {
		t.Fatal("unknown registration must provide refresh context without metrics access")
	}
	if repository.consent != (store.Consent{}) || repository.suppressions != 0 {
		t.Fatal("unknown bootstrap invented a consent or withdrawal")
	}
	preference, err := repository.GetTelemetryPreference(context.Background(), store.Subject{Kind: "installation", ID: repository.installation.ID}, input.ProductID)
	if err != nil || preference.Preference != "unknown" || !preference.RecordedAt.Equal(now) {
		t.Fatal("unknown preference or normalized timestamp was not preserved")
	}
	encoded, err := json.Marshal(registered)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	if string(response["metrics_token"]) != "null" {
		t.Fatal("unknown metrics_token must be explicitly null")
	}
	replayed, err := broker.Register(context.Background(), input)
	if err != nil || replayed.InstallationKey != registered.InstallationKey || repository.registrations != 1 || replayed.MetricsToken != nil {
		t.Fatal("unknown replay changed identity or issued metrics access")
	}
	if refreshed, err := broker.Refresh(context.Background(), registered.RefreshToken); err != domain.ErrForbidden || refreshed != (TokenResponse{}) {
		t.Fatalf("unknown refresh: %v", err)
	}
	deniedInput := input
	deniedInput.Preference = "denied"
	if broker.registrationID(input, "metric") == broker.registrationID(deniedInput, "metric") {
		t.Fatal("registration fingerprint must keep preference in its identity")
	}
	for _, preference := range []string{"unknown", "allowed"} {
		if _, err := broker.SetPreference(context.Background(), registered.RefreshToken, PreferenceInput{Preference: preference, PolicyVersion: "v2", RecordedAt: now.Add(time.Second)}); err != domain.ErrInvalid {
			t.Fatal("preference endpoint must remain denial only")
		}
	}
	for _, invalid := range []RegisterInput{
		{RequestID: input.RequestID, ProductID: input.ProductID, Platform: input.Platform, Preference: "unknown", PolicyVersion: "arbitrary", RecordedAt: now},
		{RequestID: input.RequestID, ProductID: input.ProductID, Platform: input.Platform, Preference: "unknown", PolicyVersion: "v2", RecordedAt: now.Add(-25 * time.Hour)},
		{RequestID: input.RequestID, ProductID: input.ProductID, Platform: input.Platform, Preference: "unknown", PolicyVersion: "v2", RecordedAt: now.Add(6 * time.Minute)},
	} {
		if _, err := broker.Register(context.Background(), invalid); err != domain.ErrInvalid {
			t.Fatal("unknown bypassed policy or timestamp validation")
		}
	}
	denial := PreferenceInput{Preference: "denied", PolicyVersion: "v2", RecordedAt: now.Add(time.Second)}
	for range 2 {
		if _, err := broker.SetPreference(context.Background(), registered.RefreshToken, denial); err != nil {
			t.Fatal(err)
		}
	}
	if repository.suppressions != 1 {
		t.Fatal("explicit denial must suppress exactly once")
	}
}
