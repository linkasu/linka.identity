package store

import (
	"testing"
	"time"
)

func TestConsentEpochTransitions(t *testing.T) {
	for _, test := range []struct {
		previous, next string
		epoch, want    uint64
	}{
		{"unknown", "allowed", 0, 1}, {"unknown", "denied", 0, 1},
		{"allowed", "denied", 1, 1}, {"denied", "allowed", 1, 2},
		{"allowed", "allowed", 2, 2}, {"denied", "denied", 2, 2},
	} {
		got, err := nextConsentEpoch(InstallationConsent{Version: 1, Preference: test.previous, ConsentEpoch: test.epoch}, test.next)
		if err != nil || got != test.want {
			t.Fatalf("%+v: epoch=%d err=%v", test, got, err)
		}
	}
	if _, err := nextConsentEpoch(InstallationConsent{Version: ^uint64(0)}, "allowed"); err == nil {
		t.Fatal("version overflow accepted")
	}
	if _, err := nextConsentEpoch(InstallationConsent{Preference: "denied", ConsentEpoch: ^uint64(0)}, "allowed"); err == nil {
		t.Fatal("epoch overflow accepted")
	}
}

func TestConsentSemanticFingerprintAndValidation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	input := InstallationConsentDecision{Subject: Subject{Kind: "installation", ID: "11111111-1111-4111-8111-111111111111"},
		ProductID: "linka-pokazhi", RequestID: "22222222-2222-4222-8222-222222222222", ExpectedVersion: 1,
		Preference: "denied", PolicyVersion: "base2026-07-19-v3", RecordedAt: now.Add(-48 * time.Hour)}
	if !validConsentDecision(input, now) {
		t.Fatal("durable offline denial rejected")
	}
	equivalent := input
	equivalent.RecordedAt = equivalent.RecordedAt.In(time.FixedZone("offset", 3*60*60))
	if consentFingerprint(input) != consentFingerprint(equivalent) {
		t.Fatal("time zone changed canonical semantics")
	}
	for _, change := range []func(*InstallationConsentDecision){
		func(v *InstallationConsentDecision) { v.ExpectedVersion++ },
		func(v *InstallationConsentDecision) { v.Preference = "allowed" },
		func(v *InstallationConsentDecision) { v.PolicyVersion += "-new" },
		func(v *InstallationConsentDecision) { v.RecordedAt = v.RecordedAt.Add(time.Millisecond) },
	} {
		changed := input
		change(&changed)
		if consentFingerprint(input) == consentFingerprint(changed) {
			t.Fatal("changed body retained fingerprint")
		}
	}
	for _, change := range []func(*InstallationConsentDecision){
		func(v *InstallationConsentDecision) { v.ExpectedVersion = 0 },
		func(v *InstallationConsentDecision) { v.RequestID = "not-uuid" },
		func(v *InstallationConsentDecision) { v.Preference = "unknown" },
		func(v *InstallationConsentDecision) { v.PolicyVersion = "" },
		func(v *InstallationConsentDecision) { v.RecordedAt = time.Date(2019, 12, 31, 23, 59, 59, 0, time.UTC) },
		func(v *InstallationConsentDecision) { v.RecordedAt = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC) },
		func(v *InstallationConsentDecision) { v.RecordedAt = now.Add(5*time.Minute + time.Millisecond) },
		func(v *InstallationConsentDecision) { v.RecordedAt = now.Add(time.Microsecond) },
	} {
		changed := input
		change(&changed)
		if validConsentDecision(changed, now) {
			t.Fatal("invalid decision accepted")
		}
	}
}
