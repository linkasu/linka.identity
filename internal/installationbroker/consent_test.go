package installationbroker

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

func TestVersionedConsentStrictBody(t *testing.T) {
	base := `"preference":"denied","policy_version":"base2026-07-19-v3","recorded_at":"2026-11-01T00:00:00.000Z"`
	for _, extra := range []string{
		`"request_id":null`, `"expected_version":null`, `"request_id":"11111111-1111-4111-8111-111111111111"`,
		`"expected_version":1`, `"request_id":null,"expected_version":1`,
		`"request_id":"11111111-1111-4111-8111-111111111111","expected_version":null`,
		`"request_id":"11111111-1111-4111-8111-111111111111","expected_version":1.5`,
		`"request_id":"11111111-1111-4111-8111-111111111111","expected_version":18446744073709551616`,
		`"extra":true`,
		`"request_id":"11111111-1111-4111-8111-111111111111","expected_version":1,"preference":"denied"`,
	} {
		var input PreferenceInput
		if err := json.Unmarshal([]byte(`{`+base+`,`+extra+`}`), &input); err == nil {
			t.Fatalf("accepted %s", extra)
		}
	}
	var legacy PreferenceInput
	if err := json.Unmarshal([]byte(`{`+base+`}`), &legacy); err != nil {
		t.Fatal(err)
	}
	for _, timestamp := range []string{"2026-11-01T00:00:00.0000Z", "2026-11-01T00:00:00.1234Z", "2026-11-01T00:00:00.000001Z"} {
		var input PreferenceInput
		body := `{"request_id":"11111111-1111-4111-8111-111111111111","expected_version":1,"preference":"denied","policy_version":"base2026-07-19-v3","recorded_at":"` + timestamp + `"}`
		if err := json.Unmarshal([]byte(body), &input); err == nil {
			t.Fatal("accepted non-millisecond versioned timestamp")
		}
	}
}

func TestVersionedConsentAcceptsKotlinInstantPrecision(t *testing.T) {
	for _, test := range []struct{ timestamp, normalized string }{
		{"2026-11-01T00:00:00Z", "2026-11-01T00:00:00.000Z"},
		{"2026-11-01T00:00:00.1Z", "2026-11-01T00:00:00.100Z"},
		{"2026-11-01T00:00:00.12Z", "2026-11-01T00:00:00.120Z"},
		{"2026-11-01T00:00:00.123Z", "2026-11-01T00:00:00.123Z"},
		{"2026-11-01T03:00:00.1+03:00", "2026-11-01T00:00:00.100Z"},
	} {
		t.Run(test.timestamp, func(t *testing.T) {
			var input PreferenceInput
			body := `{"request_id":"11111111-1111-4111-8111-111111111111","expected_version":1,"preference":"denied","policy_version":"base2026-07-19-v3","recorded_at":"` + test.timestamp + `"}`
			if err := json.Unmarshal([]byte(body), &input); err != nil {
				t.Fatal(err)
			}
			if input.RecordedAt.Nanosecond()%int(time.Millisecond) != 0 {
				t.Fatal("sub-millisecond precision accepted")
			}
			response, err := json.Marshal(PreferenceResponse{RecordedAt: input.RecordedAt, ManagedPreferenceFields: &ManagedPreferenceFields{Version: 1}})
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(response, &fields); err != nil {
				t.Fatal(err)
			}
			if string(fields["recorded_at"]) != `"`+test.normalized+`"` {
				t.Fatal("response did not normalize UTC milliseconds")
			}
		})
	}
}

func TestManagedConsentTokenDeliveryAndExactEpoch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	repository := newFakeRepository()
	signer, _ := token.NewSigner(bytes.Repeat([]byte{1}, 32), "active", "https://identity.test", 5*time.Minute, 15*time.Minute)
	generator, _ := pairwise.New(bytes.Repeat([]byte{2}, 32))
	broker, err := New(repository, signer, generator, Config{Products: map[string]Product{"linka-pokazhi": {Audience: "metric"}},
		RegistrationProducts: map[string]struct{}{"linka-pokazhi": {}}, PolicyVersion: "base2026-07-19-v3", RefreshTTL: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	broker.now = func() time.Time { return now }
	registered, err := broker.Register(t.Context(), RegisterInput{RequestID: "11111111-1111-4111-8111-111111111111",
		ProductID: "linka-pokazhi", Platform: "android", Preference: "unknown", PolicyVersion: "base2026-07-19-v3", RecordedAt: now})
	if err != nil || registered.MetricsToken != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	state, err := broker.GetPreference(t.Context(), registered.RefreshToken)
	if err != nil || state.Version != 1 || state.ConsentEpoch != 0 || state.DeliveryState != "completed" || state.MetricsToken != nil {
		t.Fatalf("bootstrap read: %+v %v", state, err)
	}
	request, version := "22222222-2222-4222-8222-222222222222", uint64(1)
	input := PreferenceInput{RequestID: &request, ExpectedVersion: &version, Preference: "allowed", PolicyVersion: "base2026-07-19-v3", RecordedAt: now.Add(-48 * time.Hour)}
	repository.managed = &store.InstallationConsent{Preference: "allowed", PolicyVersion: input.PolicyVersion, RecordedAt: input.RecordedAt, Version: 2, ConsentEpoch: 7, DeliveryState: "pending"}
	state, err = broker.SetPreference(t.Context(), registered.RefreshToken, input)
	if err != nil || state.MetricsToken != nil || repository.decision.ExpectedVersion != 1 {
		t.Fatalf("pending grant: %+v %v", state, err)
	}
	if _, err := broker.Refresh(t.Context(), registered.RefreshToken); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("pending token: %v", err)
	}
	repository.managed.DeliveryState = "completed"
	response, err := broker.Refresh(t.Context(), registered.RefreshToken)
	if err != nil || response.ConsentEpoch != 7 {
		t.Fatalf("delivered token: %+v %v", response, err)
	}
	claims, err := signer.VerifyForTest(response.MetricsToken.AccessToken)
	if err != nil || claims.ConsentEpoch != 7 || claims.Subject != registered.InstallationKey || claims.Product != "linka-pokazhi" || claims.Audience != "metric" || claims.SubjectType != "installation" || len(claims.Scopes) != 1 || claims.Scopes[0] != "telemetry:write" {
		t.Fatalf("incorrect epoch JWT: %+v %v", claims, err)
	}
	repository.managed.Preference = "denied"
	state, err = broker.SetPreference(t.Context(), registered.RefreshToken, input)
	if err != nil || state.Preference != "denied" || state.MetricsToken != nil {
		t.Fatalf("old grant replay did not use current denial: %+v %v", state, err)
	}
	repository.managed.Preference, repository.managed.Suppressed = "allowed", true
	state, err = broker.GetPreference(t.Context(), registered.RefreshToken)
	if err != nil || state.MetricsToken != nil {
		t.Fatal("higher suppression minted token")
	}
	if _, err := broker.Refresh(t.Context(), registered.RefreshToken); !errors.Is(err, domain.ErrForbidden) {
		t.Fatal("refresh bypassed suppression")
	}
	input.ExpectedVersion = nil
	if _, err := broker.SetPreference(t.Context(), "invalid-credential", input); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal("partial versioned body reached crypto")
	}
	input.ExpectedVersion, input.PolicyVersion = &version, "unapproved"
	if _, err := broker.SetPreference(t.Context(), "invalid-credential", input); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal("invalid policy reached crypto")
	}
	legacy, err := json.Marshal(PreferenceResponse{Preference: "denied", RecordedAt: now})
	if err != nil || bytes.Contains(legacy, []byte("consent_epoch")) || bytes.Contains(legacy, []byte("metrics_token")) {
		t.Fatal("legacy response gained managed fields")
	}
}
