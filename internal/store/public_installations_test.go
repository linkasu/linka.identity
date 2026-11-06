package store

import (
	"context"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
)

func TestPublicInstallationConsentScope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	root := "11111111-1111-4111-8111-111111111111"
	known := PublicInstallationRegistration{
		Installation: Installation{ID: root, ProductID: "linka-plays", Platform: "android"},
		Preference:   "allowed", PreferenceAt: now,
		Consent: Consent{ID: "22222222-2222-4222-8222-222222222222", Subject: Subject{Kind: "installation", ID: root},
			ProductID: "linka-plays", ConsentType: "telemetry", PolicyVersion: "v1", Status: "granted", RecordedAt: now},
	}
	unknown := known
	unknown.Preference, unknown.Consent = "unknown", Consent{}
	denied := known
	denied.Preference, denied.Consent.Status, denied.SuppressionID = "denied", "withdrawn", "33333333-3333-4333-8333-333333333333"
	for _, input := range []PublicInstallationRegistration{known, unknown, denied} {
		if !validPublicInstallationConsent(input) {
			t.Fatalf("valid %s scope rejected", input.Preference)
		}
	}
	tests := []struct {
		name   string
		base   PublicInstallationRegistration
		change func(*PublicInstallationRegistration)
	}{
		{"unknown grant", unknown, func(i *PublicInstallationRegistration) { i.Consent = known.Consent }},
		{"unknown consent id", unknown, func(i *PublicInstallationRegistration) { i.Consent.ID = known.Consent.ID }},
		{"unknown withdrawal", unknown, func(i *PublicInstallationRegistration) { i.Consent.Status = "withdrawn" }},
		{"unknown suppression", unknown, func(i *PublicInstallationRegistration) { i.SuppressionID = denied.SuppressionID }},
		{"unknown timestamp", unknown, func(i *PublicInstallationRegistration) { i.PreferenceAt = time.Time{} }},
		{"unknown root", unknown, func(i *PublicInstallationRegistration) { i.Installation.ID = "" }},
		{"unknown product", unknown, func(i *PublicInstallationRegistration) { i.Installation.ProductID = "../invalid" }},
		{"invalid preference", known, func(i *PublicInstallationRegistration) { i.Preference = "unset" }},
		{"missing consent", known, func(i *PublicInstallationRegistration) { i.Consent = Consent{} }},
		{"consent id", known, func(i *PublicInstallationRegistration) { i.Consent.ID = "" }},
		{"cross product", known, func(i *PublicInstallationRegistration) { i.Consent.ProductID = "another-product" }},
		{"cross root", known, func(i *PublicInstallationRegistration) { i.Consent.Subject.ID = denied.SuppressionID }},
		{"subject kind", known, func(i *PublicInstallationRegistration) { i.Consent.Subject.Kind = "account" }},
		{"consent type", known, func(i *PublicInstallationRegistration) { i.Consent.ConsentType = "marketing" }},
		{"granted status", known, func(i *PublicInstallationRegistration) { i.Consent.Status = "withdrawn" }},
		{"withdrawn status", denied, func(i *PublicInstallationRegistration) { i.Consent.Status = "granted" }},
		{"policy", known, func(i *PublicInstallationRegistration) { i.Consent.PolicyVersion = "" }},
		{"recorded at", known, func(i *PublicInstallationRegistration) { i.Consent.RecordedAt = now.Add(time.Second) }},
		{"suppression", denied, func(i *PublicInstallationRegistration) { i.SuppressionID = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.base
			tt.change(&input)
			if validPublicInstallationConsent(input) {
				t.Fatal("invalid consent scope accepted")
			}
			// Validation must reject before touching a database, including on replay.
			if _, err := (&Store{}).RegisterPublicInstallation(context.Background(), input); err != domain.ErrInvalid {
				t.Fatalf("invalid registration: %v", err)
			}
		})
	}
}
